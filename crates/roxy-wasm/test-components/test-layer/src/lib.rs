//! A test layer for roxy-wasm. Its behaviour for an exchange is chosen by
//! the request's `x-test` header (default `pass`); see `handle`.
//!
//! A layer configured with a name (`{"name": "a"}`) reads `x-test-a` in
//! preference to `x-test`, so each layer of a stack can be told what to do,
//! and when it passes an exchange on it tags the flow `via:a` (unless
//! configured `"tag": false`, as an observer is) and appends `a` to the
//! forwarded request's `x-via` header.

use std::sync::atomic::{AtomicU64, Ordering};

wit_bindgen::generate!({
    path: "../../../../wit",
    world: "roxy:addon/layer",
    generate_all,
});

use exports::wasi::http::incoming_handler::Guest as Handler;
use roxy::addon::{chain, endpoints, flow};
use wasi::http::types::{
    Fields, IncomingBody, IncomingRequest, IncomingResponse, OutgoingBody, OutgoingRequest,
    OutgoingResponse, ResponseOutparam,
};
use wasi::io::streams::{InputStream, OutputStream, StreamError};

struct Layer;

/// Exchanges this instance has handled (to observe pooling and recycling).
static EXCHANGES: AtomicU64 = AtomicU64::new(0);
/// Memory deliberately kept alive across exchanges (`x-test: grow`).
static mut HELD: Vec<Vec<u8>> = Vec::new();

fn header(req: &IncomingRequest, name: &str) -> Option<String> {
    req.headers()
        .get(name)
        .first()
        .map(|v| String::from_utf8_lossy(v).into_owned())
}

/// The `name` from this layer's config, if any (`{"name": "a"}`).
fn name() -> Option<String> {
    let config = flow::config();
    let start = config.find("\"name\":\"")? + "\"name\":\"".len();
    let len = config[start..].find('"')?;
    Some(config[start..start + len].to_owned())
}

/// Whether a named layer tags the flows it passes on. Off for an observer,
/// whose tags the host refuses.
fn tags() -> bool {
    !flow::config().contains("\"tag\":false")
}

/// The behaviour for this exchange: `x-test-<name>`, else `x-test`.
fn test_for(req: &IncomingRequest) -> String {
    name()
        .and_then(|n| header(req, &format!("x-test-{n}")))
        .or_else(|| header(req, "x-test"))
        .unwrap_or_else(|| "pass".to_owned())
}

/// `x-read-bytes` (default 1): how much body to read before answering.
fn read_bytes(req: &IncomingRequest) -> u64 {
    header(req, "x-read-bytes")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1)
}

/// Reads at least `n` bytes of `input` (or to its end).
fn read_at_least(input: &InputStream, n: u64) -> Vec<u8> {
    let mut got = Vec::new();
    while (got.len() as u64) < n {
        match input.blocking_read(64 * 1024) {
            Ok(chunk) => got.extend_from_slice(&chunk),
            Err(StreamError::Closed) => break,
            Err(e) => panic!("read failed: {e:?}"),
        }
    }
    got
}

fn write_all(out: &OutputStream, bytes: &[u8]) {
    assert!(try_write_all(out, bytes), "write: the reader is gone");
}

/// Writes `bytes`, or returns `false` once the reader has closed the
/// stream. The host drops a request body it has refused, and that is the
/// layer's only signal to stop sending.
fn try_write_all(out: &OutputStream, mut bytes: &[u8]) -> bool {
    while !bytes.is_empty() {
        let n = bytes.len().min(4096);
        match out.blocking_write_and_flush(&bytes[..n]) {
            Ok(()) => bytes = &bytes[n..],
            Err(StreamError::Closed) => return false,
            Err(e) => panic!("write failed: {e:?}"),
        }
    }
    true
}

/// Copies `input` to `out`, chunk by chunk, transforming each chunk.
fn pump(input: &InputStream, out: &OutputStream, upper: bool) {
    loop {
        match input.blocking_read(64 * 1024) {
            Ok(mut chunk) => {
                if upper {
                    chunk.make_ascii_uppercase();
                }
                write_all(out, &chunk);
            }
            Err(StreamError::Closed) => break,
            Err(e) => panic!("read failed: {e:?}"),
        }
    }
}

fn read_all(body: IncomingBody) -> Vec<u8> {
    let mut all = Vec::new();
    {
        let input = body.stream().expect("stream");
        loop {
            match input.blocking_read(64 * 1024) {
                Ok(chunk) => all.extend_from_slice(&chunk),
                Err(StreamError::Closed) => break,
                Err(e) => panic!("read failed: {e:?}"),
            }
        }
    }
    drop(body);
    all
}

fn respond(out: ResponseOutparam, status: u16, body: &[u8]) {
    let resp = OutgoingResponse::new(Fields::new());
    resp.set_status_code(status).expect("status");
    let resp_body = resp.body().expect("body");
    ResponseOutparam::set(out, Ok(resp));
    {
        let stream = resp_body.write().expect("write");
        write_all(&stream, body);
    }
    OutgoingBody::finish(resp_body, None).expect("finish");
}

/// A copy of the incoming request, ready for `next`. A named layer appends
/// its name to `x-via` and tags the flow `via:<name>`.
fn forward_head(req: &IncomingRequest) -> OutgoingRequest {
    let mut entries = req.headers().entries();
    if let Some(n) = name() {
        if tags() {
            flow::add_tag(&format!("via:{n}"));
        }
        let via = match entries.iter().position(|(k, _)| k == "x-via") {
            Some(i) => {
                let (_, v) = entries.remove(i);
                format!("{},{n}", String::from_utf8_lossy(&v))
            }
            None => n,
        };
        entries.push(("x-via".to_owned(), via.into_bytes()));
    }
    let headers = Fields::from_list(&entries).expect("headers");
    let out = OutgoingRequest::new(headers);
    out.set_method(&req.method()).expect("method");
    out.set_scheme(req.scheme().as_ref()).expect("scheme");
    out.set_authority(req.authority().as_deref())
        .expect("authority");
    out.set_path_with_query(req.path_with_query().as_deref())
        .expect("path");
    out
}

fn await_response(fut: wasi::http::types::FutureIncomingResponse) -> IncomingResponse {
    fut.subscribe().block();
    fut.get().expect("ready").expect("once").expect("response")
}

/// Streams `resp` back to the client through `out`.
fn answer_with(resp: IncomingResponse, out: ResponseOutparam, upper: bool) {
    let headers = Fields::from_list(&resp.headers().entries()).expect("headers");
    let mine = OutgoingResponse::new(headers);
    mine.set_status_code(resp.status()).expect("status");
    let mine_body = mine.body().expect("body");
    ResponseOutparam::set(out, Ok(mine));
    {
        let body = resp.consume().expect("consume");
        {
            let input = body.stream().expect("stream");
            let output = mine_body.write().expect("write");
            pump(&input, &output, upper);
        }
        drop(body);
    }
    drop(resp);
    OutgoingBody::finish(mine_body, None).expect("finish");
}

/// The default: pass the exchange through, streaming both bodies, chunk by
/// chunk (upper-cased when `x-upper` is set). With `x-hold`, neither body
/// it passes on is ever ended. Unbuffered, the response from below goes
/// out with `x-status` as its status, if set.
fn pass(req: IncomingRequest, out: ResponseOutparam, buffer_first: bool) {
    let upper = header(&req, "x-upper").is_some();
    let tweaks = Tweaks {
        upper,
        hold: header(&req, "x-hold").is_some(),
        status: header(&req, "x-status").map(|v| v.parse().expect("x-status")),
    };
    let next_req = forward_head(&req);
    let next_body = next_req.body().expect("body");
    let in_body = req.consume().expect("consume");

    let buffered = buffer_first.then(|| {
        let stream = in_body.stream().expect("stream");
        let mut all = Vec::new();
        loop {
            match stream.blocking_read(64 * 1024) {
                Ok(c) => all.extend_from_slice(&c),
                Err(StreamError::Closed) => break,
                Err(e) => panic!("read failed: {e:?}"),
            }
        }
        all
    });

    let fut = chain::next(next_req).expect("next");
    let Some(all) = buffered else {
        duplex(req, in_body, next_body, fut, out, tweaks);
        return;
    };
    {
        let output = next_body.write().expect("write");
        write_all(&output, &all);
    }
    OutgoingBody::finish(next_body, None).expect("finish");
    drop(in_body);
    drop(req);

    answer_with(await_response(fut), out, upper);
}

/// What `pass` does to the exchange besides passing it on, from the
/// request's `x-*` headers.
struct Tweaks {
    upper: bool,
    hold: bool,
    status: Option<u16>,
}

/// Streams both bodies at once: the request body into `next` and the
/// response from below back out, each chunk as it comes, neither waiting
/// for the other to end. A WebSocket's request body only ends when the
/// client closes, while its response streams all along.
fn duplex(
    req: IncomingRequest,
    in_body: IncomingBody,
    next_body: OutgoingBody,
    fut: wasi::http::types::FutureIncomingResponse,
    out: ResponseOutparam,
    Tweaks {
        upper,
        hold,
        status,
    }: Tweaks,
) {
    let up = |mut c: Vec<u8>| {
        if upper {
            c.make_ascii_uppercase();
        }
        c
    };
    let req_in = in_body.stream().expect("stream");
    let mut req_out = Some(next_body.write().expect("write"));
    let mut next_body = Some(next_body);
    let mut req_open = true;
    let mut out = Some(out);
    // The response from below, once it has arrived, and our own.
    let mut resp: Option<(IncomingResponse, IncomingBody, OutgoingBody)> = None;
    let mut resp_streams: Option<(InputStream, OutputStream)> = None;
    loop {
        if req_open {
            match req_in.read(64 * 1024) {
                Ok(c) if !c.is_empty() => {
                    if !try_write_all(req_out.as_ref().expect("open"), &up(c)) {
                        // The layer below is done with the request body
                        // (a refused request); stop relaying it.
                        req_open = false;
                        drop(req_out.take());
                        drop(next_body.take());
                    }
                }
                Ok(_) => {}
                // A broken body is never passed on as if it had ended:
                // trapping fails the exchange closed.
                Err(StreamError::LastOperationFailed(e)) => {
                    panic!("request body failed: {}", e.to_debug_string())
                }
                Err(StreamError::Closed) => {
                    // The client's body ended: end the one below, so a
                    // peer waiting for it (an echo) can end its response.
                    req_open = false;
                    drop(req_out.take());
                    if let Some(b) = next_body.take() {
                        let _ = OutgoingBody::finish(b, None);
                    }
                }
            }
        }
        if resp.is_none()
            && let Some(r) = fut.get()
        {
            let below = r.expect("once").expect("response");
            let headers = Fields::from_list(&below.headers().entries()).expect("headers");
            let mine = OutgoingResponse::new(headers);
            mine.set_status_code(status.unwrap_or(below.status()))
                .expect("status");
            let mine_body = mine.body().expect("body");
            ResponseOutparam::set(out.take().expect("one answer"), Ok(mine));
            let body = below.consume().expect("consume");
            let input = body.stream().expect("stream");
            let output = mine_body.write().expect("write");
            resp_streams = Some((input, output));
            resp = Some((below, body, mine_body));
        }
        let mut resp_open = resp.is_none();
        if let Some((input, output)) = &resp_streams {
            match input.read(64 * 1024) {
                Ok(c) => {
                    resp_open = true;
                    if !c.is_empty() {
                        write_all(output, &up(c));
                    }
                }
                Err(StreamError::LastOperationFailed(e)) => {
                    panic!("response body failed: {}", e.to_debug_string())
                }
                Err(StreamError::Closed) => {}
            }
        }
        if !resp_open && resp_streams.is_some() {
            // The response from below ended: end ours.
            drop(resp_streams.take());
            let (below, body, mine_body) = resp.take().expect("response");
            drop(body);
            drop(below);
            if hold {
                // Keep both bodies open until the client's request body
                // goes away.
                while req_open && req_in.blocking_read(64 * 1024).is_ok() {}
                drop(req_out);
                drop(req_in);
                drop(next_body);
                drop(in_body);
                drop(req);
                drop(mine_body);
                return;
            }
            OutgoingBody::finish(mine_body, None).expect("finish");
            break;
        }
        let mut wait = Vec::new();
        if req_open {
            wait.push(req_in.subscribe());
        }
        match &resp_streams {
            Some((input, _)) => wait.push(input.subscribe()),
            None => wait.push(fut.subscribe()),
        }
        let refs: Vec<&wasi::io::poll::Pollable> = wait.iter().collect();
        wasi::io::poll::poll(&refs);
    }
    // Close the request direction too, however far it got.
    drop(req_out);
    drop(req_in);
    if let Some(b) = next_body {
        let _ = OutgoingBody::finish(b, None);
    }
    drop(in_body);
    drop(req);
}

/// Like `pass`, but full duplex: it streams the request body into `next`
/// while watching for the response, so a response from below (an inner
/// layer or the upstream answering early) is relayed at once, abandoning
/// the rest of the request body.
fn relay(req: IncomingRequest, out: ResponseOutparam) {
    let next_req = forward_head(&req);
    let next_body = next_req.body().expect("body");
    let in_body = req.consume().expect("consume");
    let fut = chain::next(next_req).expect("next");
    let mut early = None;
    {
        let input = in_body.stream().expect("stream");
        let output = next_body.write().expect("write");
        let mut pending: Vec<u8> = Vec::new();
        let mut input_open = true;
        loop {
            if let Some(r) = fut.get() {
                early = Some(r);
                break;
            }
            if pending.is_empty() && !input_open {
                break;
            }
            let mut pollables = vec![fut.subscribe()];
            if pending.is_empty() {
                pollables.push(input.subscribe());
            } else {
                pollables.push(output.subscribe());
            }
            let refs: Vec<_> = pollables.iter().collect();
            wasi::io::poll::poll(&refs);
            drop(refs);
            drop(pollables);
            if pending.is_empty() {
                match input.read(64 * 1024) {
                    Ok(chunk) => pending = chunk,
                    Err(StreamError::Closed) => input_open = false,
                    // The request body broke (the client or an outer layer
                    // gave up): abandon the exchange.
                    Err(_) => return,
                }
            } else {
                let n = output.check_write().expect("check_write") as usize;
                if n > 0 {
                    let k = n.min(pending.len());
                    output.write(&pending[..k]).expect("write");
                    pending.drain(..k);
                }
            }
        }
    }
    let resp = if let Some(r) = early {
        // Answered before the body was all sent: abandon the rest.
        drop(next_body);
        drop(in_body);
        drop(req);
        r.expect("once").expect("response")
    } else {
        OutgoingBody::finish(next_body, None).expect("finish");
        drop(in_body);
        drop(req);
        await_response(fut)
    };
    answer_with(resp, out, false);
}

fn call_capability(req: &IncomingRequest) -> String {
    match header(req, "x-cap").as_deref().unwrap_or("") {
        "current" => {
            let info = flow::current();
            format!(
                "{} {} {}",
                info.flow_id, info.principal.client_ip, info.principal.listener
            )
        }
        "add-tag" => {
            flow::add_tag("tagged");
            "ok".to_owned()
        }
        "config" => flow::config(),
        "log" => {
            flow::log(flow::LogLevel::Info, "hello from the layer");
            "ok".to_owned()
        }
        "record" => {
            flow::record("verdict", "{\"score\":0.9}", true);
            "ok".to_owned()
        }
        "state" => {
            let put = flow::state_put("k", "{\"n\":1}", None);
            let got = flow::state_get("k");
            format!("{put:?} {got:?}")
        }
        "metric" => format!(
            "{:?}",
            flow::metric_get("requests", &["10.0.0.1".to_owned()])
        ),
        "endpoint" => {
            let path = header(req, "x-cap-path").unwrap_or_else(|| "/score?q=1".to_owned());
            let r = OutgoingRequest::new(Fields::new());
            r.set_path_with_query(Some(&path)).expect("path");
            match endpoints::call("monitor", r) {
                Ok(fut) => {
                    let resp = await_response(fut);
                    let status = resp.status();
                    let body = read_all(resp.consume().expect("consume"));
                    drop(resp);
                    format!("{status} {}", String::from_utf8_lossy(&body))
                }
                Err(e) => format!("error {e:?}"),
            }
        }
        "unknown-endpoint" => {
            let r = OutgoingRequest::new(Fields::new());
            match endpoints::call("nope", r) {
                Ok(fut) => {
                    fut.subscribe().block();
                    match fut.get().expect("ready").expect("once") {
                        Ok(_) => "ok".to_owned(),
                        Err(e) => format!("error {e:?}"),
                    }
                }
                Err(e) => format!("error {e:?}"),
            }
        }
        other => format!("unknown capability test {other:?}"),
    }
}

impl Handler for Layer {
    fn handle(req: IncomingRequest, out: ResponseOutparam) {
        let n = EXCHANGES.fetch_add(1, Ordering::Relaxed) + 1;
        let test = test_for(&req);
        if let Some(n) = test.strip_prefix("fields:") {
            // Build a `fields` holding one value of `n` bytes, then answer.
            // Past the host's cap on a `fields` this traps instead.
            let n: usize = n.parse().expect("size");
            let f = Fields::new();
            f.append("x-big", &vec![b'a'; n]).expect("append");
            respond(out, 200, b"fields ok");
            drop(f);
            return;
        }
        if let Some(n) = test.strip_prefix("log:") {
            // Log one message of `n` bytes, then answer.
            let n: usize = n.parse().expect("size");
            flow::log(flow::LogLevel::Info, &"m".repeat(n));
            respond(out, 200, b"logged");
            return;
        }
        if let Some(n) = test.strip_prefix("record:") {
            // Record one document of about `n` bytes, then answer.
            let n: usize = n.parse().expect("size");
            flow::record("big", &format!("{{\"s\":\"{}\"}}", "r".repeat(n)), false);
            respond(out, 200, b"recorded");
            return;
        }
        if let Some(n) = test.strip_prefix("hoard:") {
            // Hold `n` host resources at once, then answer. Past the host's
            // per-instance cap this traps instead of answering.
            let n: usize = n.parse().expect("count");
            let held: Vec<Fields> = (0..n).map(|_| Fields::new()).collect();
            respond(out, 200, b"hoarded");
            drop(held);
            return;
        }
        match test.as_str() {
            "pass" => pass(req, out, false),
            "relay" => relay(req, out),
            "buffer" => pass(req, out, true),
            "deny" => respond(out, 403, b"denied by layer"),
            "answer" => {
                let who = name().unwrap_or_default();
                respond(out, 200, format!("answered by {who}").as_bytes());
            }
            "read-then-answer" => {
                // Answer after `x-read-bytes` of the body, without `next`.
                let n = read_bytes(&req);
                let body = req.consume().expect("consume");
                let got = {
                    let input = body.stream().expect("stream");
                    read_at_least(&input, n)
                };
                let who = name().unwrap_or_default();
                respond(
                    out,
                    200,
                    format!("answered by {who} after {} bytes", got.len()).as_bytes(),
                );
                drop(body);
            }
            "next-then-answer" => {
                // Pass the request on, stream `x-read-bytes` of its body
                // into `next`, then abandon it and answer locally.
                let n = read_bytes(&req);
                let next_req = forward_head(&req);
                let next_body = next_req.body().expect("body");
                let in_body = req.consume().expect("consume");
                let fut = chain::next(next_req).expect("next");
                let sent = {
                    let input = in_body.stream().expect("stream");
                    let output = next_body.write().expect("write");
                    let got = read_at_least(&input, n);
                    write_all(&output, &got);
                    got.len()
                };
                drop(fut);
                drop(next_body);
                let who = name().unwrap_or_default();
                respond(
                    out,
                    200,
                    format!("answered by {who} after forwarding {sent} bytes").as_bytes(),
                );
                drop(in_body);
            }
            "cut-then-await" => {
                // Stream `x-read-bytes` of the body into `next`, leave it
                // unfinished while still waiting on the response, then
                // answer whatever `next` gives back.
                let n = read_bytes(&req);
                let next_req = forward_head(&req);
                let next_body = next_req.body().expect("body");
                let in_body = req.consume().expect("consume");
                let fut = chain::next(next_req).expect("next");
                {
                    let input = in_body.stream().expect("stream");
                    let output = next_body.write().expect("write");
                    write_all(&output, &read_at_least(&input, n));
                }
                drop(next_body);
                fut.subscribe().block();
                match fut.get().expect("ready").expect("once") {
                    Ok(resp) => answer_with(resp, out, false),
                    Err(_) => respond(out, 200, b"answered after next failed"),
                }
                drop(in_body);
            }
            "count" => respond(out, 200, n.to_string().as_bytes()),
            "caps" => {
                let body = call_capability(&req);
                respond(out, 200, body.as_bytes());
            }
            "loop" => {
                let mut i: u64 = 0;
                loop {
                    i = std::hint::black_box(i.wrapping_add(1));
                }
            }
            "host-loop" => loop {
                std::hint::black_box(flow::config());
            },
            "memory" => {
                let mut hog: Vec<Vec<u8>> = Vec::new();
                loop {
                    hog.push(vec![1u8; 1 << 20]);
                    std::hint::black_box(&hog);
                }
            }
            "grow" => {
                // Keep ~8 MiB alive past this exchange.
                #[allow(static_mut_refs)]
                unsafe {
                    HELD.push(vec![1u8; 8 << 20]);
                }
                respond(out, 200, b"grown");
            }
            "next-twice" => {
                let first = chain::next(forward_head(&req)).expect("next");
                let _second = chain::next(forward_head(&req));
                drop(first);
                respond(out, 200, b"unreachable");
            }
            "trap" => panic!("layer panics"),
            "no-response" => drop(out),
            "error-response" => ResponseOutparam::set(
                out,
                Err(wasi::http::types::ErrorCode::InternalError(Some(
                    "layer says no".to_owned(),
                ))),
            ),
            "leak" => {
                // Answer, write part of the body, and return without
                // finishing it.
                let resp = OutgoingResponse::new(Fields::new());
                let body = resp.body().expect("body");
                ResponseOutparam::set(out, Ok(resp));
                let stream = body.write().expect("write");
                write_all(&stream, b"partial");
                std::mem::forget(stream);
                std::mem::forget(body);
            }
            "trap-after-head" => {
                let resp = OutgoingResponse::new(Fields::new());
                let body = resp.body().expect("body");
                ResponseOutparam::set(out, Ok(resp));
                {
                    let stream = body.write().expect("write");
                    write_all(&stream, b"partial");
                }
                // `x-delay-ms` holds the cut back so the head lands first.
                if let Some(ms) = header(&req, "x-delay-ms").and_then(|v| v.parse::<u64>().ok()) {
                    wasi::clocks::monotonic_clock::subscribe_duration(ms * 1_000_000).block();
                }
                panic!("layer panics mid-body");
            }
            "tags-after-head" => {
                // Answer, then tag the flow without end, each tag unique and
                // `x-tag-len` bytes long (default 2). Only the host's cap on a
                // flow's tags stops this.
                let len: usize = header(&req, "x-tag-len")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(2);
                let resp = OutgoingResponse::new(Fields::new());
                let body = resp.body().expect("body");
                ResponseOutparam::set(out, Ok(resp));
                {
                    let stream = body.write().expect("write");
                    write_all(&stream, b"partial");
                }
                let mut i: u64 = 0;
                loop {
                    flow::add_tag(&format!("{i:0>len$}"));
                    i += 1;
                }
            }
            "trap-after-finish" => {
                respond(out, 200, b"complete");
                panic!("layer panics after its response");
            }
            "rewrite" => {
                // Pass a new request (to another path, with a new body).
                let r = forward_head(&req);
                r.set_path_with_query(Some("/rewritten")).expect("path");
                let b = r.body().expect("body");
                let fut = chain::next(r).expect("next");
                {
                    // The rules may refuse the request at its head and drop
                    // its body before it is written: not an error here.
                    let s = b.write().expect("write");
                    let _ = s.blocking_write_and_flush(b"replaced");
                }
                let _ = OutgoingBody::finish(b, None);
                drop(req);
                answer_with(await_response(fut), out, false);
            }
            "elsewhere-then-metric" => {
                // Send the request (bodiless) to `x-to`'s host, wait for the
                // response, then answer with this flow's `requests` metric
                // as `metric-get` sees it.
                let r = forward_head(&req);
                let to = header(&req, "x-to").expect("x-to");
                r.set_authority(Some(&to)).expect("authority");
                let b = r.body().expect("body");
                let fut = chain::next(r).expect("next");
                OutgoingBody::finish(b, None).expect("finish");
                drop(req);
                let resp = await_response(fut);
                drop(read_all(resp.consume().expect("consume")));
                drop(resp);
                let got = flow::metric_get("by_host", &[]);
                respond(out, 200, format!("{got:?}").as_bytes());
            }
            "invalid-next" => {
                let r = forward_head(&req);
                // wasi-http validates most of the head in its setters;
                // a scheme roxy does not speak gets through to `next`.
                r.set_scheme(Some(&wasi::http::types::Scheme::Other("ftp".to_owned())))
                    .expect("scheme");
                let _ = chain::next(r);
                respond(out, 200, b"unreachable");
            }
            other => respond(out, 400, format!("unknown test {other:?}").as_bytes()),
        }
    }
}

impl exports::roxy::addon::init::Guest for Layer {
    fn init() -> Result<(), String> {
        let config = flow::config();
        if config.contains("fail_init") {
            return Err("init asked to fail".to_owned());
        }
        if config.contains("flow_in_init") {
            let _ = flow::current();
        }
        if config.contains("log_in_init") {
            flow::log(flow::LogLevel::Info, "init");
        }
        Ok(())
    }
}

export!(Layer);
