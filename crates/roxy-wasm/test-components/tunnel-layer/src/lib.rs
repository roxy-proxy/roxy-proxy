//! A test layer that exports `tunnel`: it relays both directions of an
//! upgraded connection, upper-casing client → upstream bytes.

wit_bindgen::generate!({
    path: "../../../../wit",
    world: "roxy:addon/tunnel-layer",
    generate_all,
});

use exports::roxy::addon::tunnel::Guest as Tunnel;
use exports::wasi::http::incoming_handler::Guest as Handler;
use wasi::http::types::{
    Fields, IncomingRequest, OutgoingBody, OutgoingResponse, ResponseOutparam,
};
use wasi::io::streams::{InputStream, OutputStream, StreamError};

struct Layer;

fn write_all(out: &OutputStream, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        let n = bytes.len().min(4096);
        out.blocking_write_and_flush(&bytes[..n]).expect("write");
        bytes = &bytes[n..];
    }
}

impl Handler for Layer {
    fn handle(_req: IncomingRequest, out: ResponseOutparam) {
        let resp = OutgoingResponse::new(Fields::new());
        let body = resp.body().expect("body");
        ResponseOutparam::set(out, Ok(resp));
        {
            let s = body.write().expect("write");
            write_all(&s, b"tunnel layer");
        }
        OutgoingBody::finish(body, None).expect("finish");
    }
}

impl Tunnel for Layer {
    fn on_tunnel(
        from_client: InputStream,
        to_upstream: OutputStream,
        from_upstream: InputStream,
        to_client: OutputStream,
    ) {
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
                        c.make_ascii_uppercase();
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
        Ok(())
    }
}

export!(Layer);
