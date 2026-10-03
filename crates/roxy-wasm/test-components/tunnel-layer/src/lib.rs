//! A test layer that exports `tunnel`: it relays both directions of an
//! upgraded connection, tagging the flow `tunnel` (and `tunnel:<name>` with
//! config `{"name": ...}`), and (with config `{"upper": true}`)
//! upper-casing client → upstream bytes.

use std::sync::atomic::{AtomicBool, Ordering};

static UPPER: AtomicBool = AtomicBool::new(false);

wit_bindgen::generate!({
    path: "../../../../wit",
    world: "roxy:addon/tunnel-layer",
    generate_all,
});

use exports::roxy::addon::tunnel::Guest as Tunnel;
use exports::wasi::http::incoming_handler::Guest as Handler;
use wasi::http::types::{
    Fields, IncomingRequest, OutgoingBody, OutgoingRequest, OutgoingResponse, ResponseOutparam,
};
use wasi::io::streams::{InputStream, OutputStream, StreamError};

struct Layer;

/// The `name` from this layer's config, if any (`{"name": "a"}`).
fn name() -> Option<String> {
    let config = roxy::addon::flow::config();
    let start = config.find("\"name\":\"")? + "\"name\":\"".len();
    let len = config[start..].find('"')?;
    Some(config[start..start + len].to_owned())
}

fn write_all(out: &OutputStream, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        let n = bytes.len().min(4096);
        out.blocking_write_and_flush(&bytes[..n]).expect("write");
        bytes = &bytes[n..];
    }
}

impl Handler for Layer {
    /// Passes the exchange through unchanged (so an upgrade request reaches
    /// the upstream and the `101` comes back).
    fn handle(req: IncomingRequest, out: ResponseOutparam) {
        let headers = Fields::from_list(&req.headers().entries()).expect("headers");
        let next_req = OutgoingRequest::new(headers);
        next_req.set_method(&req.method()).expect("method");
        next_req.set_scheme(req.scheme().as_ref()).expect("scheme");
        next_req
            .set_authority(req.authority().as_deref())
            .expect("authority");
        next_req
            .set_path_with_query(req.path_with_query().as_deref())
            .expect("path");
        let next_body = next_req.body().expect("body");
        let fut = roxy::addon::chain::next(next_req).expect("next");
        {
            let in_body = req.consume().expect("consume");
            {
                let input = in_body.stream().expect("stream");
                let output = next_body.write().expect("write");
                copy(&input, &output);
            }
            drop(in_body);
        }
        OutgoingBody::finish(next_body, None).expect("finish");
        drop(req);

        fut.subscribe().block();
        let resp = fut.get().expect("ready").expect("once").expect("response");
        let mine =
            OutgoingResponse::new(Fields::from_list(&resp.headers().entries()).expect("headers"));
        mine.set_status_code(resp.status()).expect("status");
        let mine_body = mine.body().expect("body");
        ResponseOutparam::set(out, Ok(mine));
        {
            let body = resp.consume().expect("consume");
            {
                let input = body.stream().expect("stream");
                let output = mine_body.write().expect("write");
                copy(&input, &output);
            }
            drop(body);
        }
        drop(resp);
        OutgoingBody::finish(mine_body, None).expect("finish");
    }
}

fn copy(input: &InputStream, output: &OutputStream) {
    loop {
        match input.blocking_read(64 * 1024) {
            Ok(chunk) => write_all(output, &chunk),
            Err(StreamError::Closed) => break,
            Err(e) => panic!("read failed: {e:?}"),
        }
    }
}

impl Tunnel for Layer {
    fn on_tunnel(
        from_client: InputStream,
        to_upstream: OutputStream,
        from_upstream: InputStream,
        to_client: OutputStream,
    ) {
        roxy::addon::flow::add_tag("tunnel");
        if let Some(name) = name() {
            roxy::addon::flow::add_tag(&format!("tunnel:{name}"));
        }
        let upper = UPPER.load(Ordering::Relaxed);
        // Relay both directions as bytes arrive. Each side is dropped when
        // its input closes, which closes the matching output.
        let mut up = Some((from_client, to_upstream));
        let mut down = Some((from_upstream, to_client));
        while up.is_some() || down.is_some() {
            let mut pollables = Vec::new();
            if let Some((i, _)) = &up {
                pollables.push(i.subscribe());
            }
            if let Some((i, _)) = &down {
                pollables.push(i.subscribe());
            }
            let refs: Vec<_> = pollables.iter().collect();
            wasi::io::poll::poll(&refs);
            drop(refs);
            drop(pollables);

            if let Some((i, o)) = &up {
                match i.read(64 * 1024) {
                    Ok(mut c) => {
                        if upper {
                            c.make_ascii_uppercase();
                        }
                        write_all(o, &c);
                    }
                    Err(StreamError::Closed) => up = None,
                    Err(e) => panic!("read failed: {e:?}"),
                }
            }
            if let Some((i, o)) = &down {
                match i.read(64 * 1024) {
                    Ok(c) => write_all(o, &c),
                    Err(StreamError::Closed) => down = None,
                    Err(e) => panic!("read failed: {e:?}"),
                }
            }
        }
    }
}

impl exports::roxy::addon::init::Guest for Layer {
    fn init() -> Result<(), String> {
        UPPER.store(
            roxy::addon::flow::config().contains("\"upper\": true")
                || roxy::addon::flow::config().contains("\"upper\":true"),
            Ordering::Relaxed,
        );
        Ok(())
    }
}

export!(Layer);
