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

use exports::roxy::addon::handler::Guest as Handler;
use roxy::addon::types::{self, Body, PendingResponse, RequestHead, ResponseHead};
use roxy::addon::{chain, endpoints, flow};
use wasi::io::poll::Pollable;
use wasi::io::streams::{InputStream, OutputStream, StreamError};

struct Layer;

/// Exchanges this instance has handled (to observe pooling and recycling).
static EXCHANGES: AtomicU64 = AtomicU64::new(0);
/// Memory deliberately kept alive across exchanges (`x-test: grow`).
static mut HELD: Vec<Vec<u8>> = Vec::new();

/// A response from below: its head and body stream.
type Answer = (ResponseHead, InputStream);

fn header(req: &RequestHead, name: &str) -> Option<String> {
    req.headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
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
fn test_for(req: &RequestHead) -> String {
    name()
        .and_then(|n| header(req, &format!("x-test-{n}")))
        .or_else(|| header(req, "x-test"))
        .unwrap_or_else(|| "pass".to_owned())
}

/// `x-read-bytes` (default 1): how much body to read before answering.
fn read_bytes(req: &RequestHead) -> u64 {
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

fn read_all(input: &InputStream) -> Vec<u8> {
    read_at_least(input, u64::MAX)
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

fn head(status: u16, headers: Vec<(String, Vec<u8>)>) -> ResponseHead {
    ResponseHead { status, headers }
}

/// Answers with `body` in one piece.
fn respond(status: u16, body: &[u8]) {
    let out = chain::respond(&head(status, Vec::new()), Body::Bytes(body.to_vec()));
    assert!(out.is_none(), "no stream for a whole body");
}

/// Answers with a streamed body, returning the stream to write it to.
fn respond_streaming(head: &ResponseHead) -> OutputStream {
    chain::respond(head, Body::Stream).expect("stream")
}

/// A copy of the incoming head, ready for `next`. A named layer appends
/// its name to `x-via` and tags the flow `via:<name>`.
fn forward_head(req: &RequestHead) -> RequestHead {
    forward_head_with(req, Vec::new())
}

/// [`forward_head`] with `extra` headers added.
fn forward_head_with(req: &RequestHead, extra: Vec<(String, Vec<u8>)>) -> RequestHead {
    let mut entries = req.headers.clone();
    entries.extend(extra);
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
    RequestHead {
        method: req.method.clone(),
        scheme: req.scheme.clone(),
        authority: req.authority.clone(),
        path_with_query: req.path_with_query.clone(),
        headers: entries,
    }
}

/// Passes `head` down with a body the layer will write, returning the
/// response to come and the stream to write to.
fn next_streaming(head: &RequestHead) -> (PendingResponse, OutputStream) {
    let (pending, out) = chain::next(head, Body::Stream).expect("next");
    (pending, out.expect("stream"))
}

fn await_response(pending: PendingResponse) -> Answer {
    PendingResponse::wait(pending).expect("response")
}

/// Streams `resp` back to the client.
fn answer_with((below, body): Answer, upper: bool) {
    let out = respond_streaming(&below);
    pump(&body, &out, upper);
    drop(body);
    types::finish(out);
}

/// The default: pass the exchange through, streaming both bodies, chunk by
/// chunk (upper-cased when `x-upper` is set). With `x-hold`, neither body
/// it passes on is ended until the client's request body goes away.
/// Unbuffered, the response from below goes out with `x-status` as its
/// status, if set.
fn pass(req: &RequestHead, body: InputStream, buffer_first: bool) {
    let upper = header(req, "x-upper").is_some();
    let tweaks = Tweaks {
        upper,
        hold: header(req, "x-hold").is_some(),
        status: header(req, "x-status").map(|v| v.parse().expect("x-status")),
    };
    let next_head = forward_head(req);
    let buffered = buffer_first.then(|| read_all(&body));
    let (pending, next_out) = next_streaming(&next_head);
    let Some(all) = buffered else {
        duplex(body, next_out, pending, tweaks);
        return;
    };
    write_all(&next_out, &all);
    types::finish(next_out);
    drop(body);
    answer_with(await_response(pending), upper);
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
    req_in: InputStream,
    req_out: OutputStream,
    pending: PendingResponse,
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
    let mut req_out = Some(req_out);
    let mut req_open = true;
    // The response from below and our own, once it has arrived.
    let mut resp: Option<(InputStream, OutputStream)> = None;
    loop {
        if req_open {
            match req_in.read(64 * 1024) {
                Ok(c) if !c.is_empty() => {
                    if !try_write_all(req_out.as_ref().expect("open"), &up(c)) {
                        // The layer below is done with the request body
                        // (a refused request); stop relaying it.
                        req_open = false;
                        types::finish(req_out.take().expect("open"));
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
                    types::finish(req_out.take().expect("open"));
                }
            }
        }
        if resp.is_none()
            && let Some(r) = pending.get()
        {
            let (mut below, body) = r.expect("response");
            if let Some(s) = status {
                below.status = s;
            }
            let out = respond_streaming(&below);
            resp = Some((body, out));
        }
        let mut resp_open = resp.is_none();
        if let Some((input, output)) = &resp {
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
        if !resp_open && resp.is_some() {
            // The response from below ended: end ours.
            let (input, output) = resp.take().expect("response");
            drop(input);
            if hold {
                // Keep both bodies open until the client's request body
                // goes away.
                while req_open && req_in.blocking_read(64 * 1024).is_ok() {}
                drop(req_in);
                if let Some(o) = req_out.take() {
                    types::finish(o);
                }
                types::finish(output);
                return;
            }
            types::finish(output);
            break;
        }
        let mut wait: Vec<Pollable> = Vec::new();
        if req_open {
            wait.push(req_in.subscribe());
        }
        match &resp {
            Some((input, _)) => wait.push(input.subscribe()),
            None => wait.push(pending.subscribe()),
        }
        let refs: Vec<&Pollable> = wait.iter().collect();
        wasi::io::poll::poll(&refs);
    }
    // Close the request direction too, however far it got.
    drop(req_in);
    if let Some(o) = req_out.take() {
        types::finish(o);
    }
    drop(pending);
}

/// Like `pass`, but it streams the request body into `next` while watching
/// for the response, so a response from below (an inner layer or the
/// upstream answering early) is relayed at once, abandoning the rest of
/// the request body.
fn relay(req: &RequestHead, body: InputStream) {
    let (pending, output) = next_streaming(&forward_head(req));
    let mut early = None;
    {
        let mut pending_bytes: Vec<u8> = Vec::new();
        let mut input_open = true;
        loop {
            if let Some(r) = pending.get() {
                early = Some(r);
                break;
            }
            if pending_bytes.is_empty() && !input_open {
                break;
            }
            let mut pollables = vec![pending.subscribe()];
            if pending_bytes.is_empty() {
                pollables.push(body.subscribe());
            } else {
                pollables.push(output.subscribe());
            }
            let refs: Vec<_> = pollables.iter().collect();
            wasi::io::poll::poll(&refs);
            drop(refs);
            drop(pollables);
            if pending_bytes.is_empty() {
                match body.read(64 * 1024) {
                    Ok(chunk) => pending_bytes = chunk,
                    Err(StreamError::Closed) => input_open = false,
                    // The request body broke (the client or an outer layer
                    // gave up): abandon the exchange.
                    Err(_) => return,
                }
            } else {
                let n = output.check_write().expect("check_write") as usize;
                if n > 0 {
                    let k = n.min(pending_bytes.len());
                    output.write(&pending_bytes[..k]).expect("write");
                    pending_bytes.drain(..k);
                }
            }
        }
    }
    let resp = if let Some(r) = early {
        // Answered before the body was all sent: abandon the rest.
        drop(output);
        drop(body);
        drop(pending);
        r.expect("response")
    } else {
        types::finish(output);
        drop(body);
        await_response(pending)
    };
    answer_with(resp, false);
}

fn call_capability(req: &RequestHead) -> String {
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
            flow::record("verdict", "{\"score\":0.9}");
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
            let r = RequestHead {
                method: "GET".to_owned(),
                scheme: None,
                authority: None,
                path_with_query: path,
                headers: Vec::new(),
            };
            match endpoints::call("monitor", &r, Body::Empty) {
                Ok((pending, _)) => {
                    let (below, body) = await_response(pending);
                    let bytes = read_all(&body);
                    format!("{} {}", below.status, String::from_utf8_lossy(&bytes))
                }
                Err(e) => format!("error {e:?}"),
            }
        }
        "unknown-endpoint" => {
            let r = RequestHead {
                method: "GET".to_owned(),
                scheme: None,
                authority: None,
                path_with_query: "/".to_owned(),
                headers: Vec::new(),
            };
            match endpoints::call("nope", &r, Body::Empty) {
                Ok((pending, _)) => {
                    pending.subscribe().block();
                    match pending.get().expect("ready") {
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
    fn handle(req: RequestHead, body: InputStream) {
        let n = EXCHANGES.fetch_add(1, Ordering::Relaxed) + 1;
        let test = test_for(&req);
        if let Some(n) = test.strip_prefix("fields:") {
            // Answer with a head holding one value of `n` bytes. Past the
            // host's cap on a head this traps instead.
            let n: usize = n.parse().expect("size");
            let big = head(200, vec![("x-big".to_owned(), vec![b'a'; n])]);
            let out = chain::respond(&big, Body::Bytes(b"fields ok".to_vec()));
            assert!(out.is_none());
            return;
        }
        if let Some(n) = test.strip_prefix("log:") {
            // Log one message of `n` bytes, then answer.
            let n: usize = n.parse().expect("size");
            flow::log(flow::LogLevel::Info, &"m".repeat(n));
            respond(200, b"logged");
            return;
        }
        if let Some(n) = test.strip_prefix("record:") {
            // Record one document of about `n` bytes, then answer.
            let n: usize = n.parse().expect("size");
            flow::record("big", &format!("{{\"s\":\"{}\"}}", "r".repeat(n)));
            respond(200, b"recorded");
            return;
        }
        if let Some(n) = test.strip_prefix("hoard:") {
            // Hold `n` host resources at once, then answer. Past the host's
            // per-instance cap this traps instead of answering.
            let n: usize = n.parse().expect("count");
            let held: Vec<Pollable> = (0..n)
                .map(|_| wasi::clocks::monotonic_clock::subscribe_duration(1_000_000_000))
                .collect();
            respond(200, b"hoarded");
            drop(held);
            return;
        }
        match test.as_str() {
            "pass" => pass(&req, body, false),
            "relay" => relay(&req, body),
            "buffer" => pass(&req, body, true),
            "deny" => respond(403, b"denied by layer"),
            "answer" => {
                let who = name().unwrap_or_default();
                respond(200, format!("answered by {who}").as_bytes());
            }
            "read-then-answer" => {
                // Answer after `x-read-bytes` of the body, without `next`.
                let n = read_bytes(&req);
                let got = read_at_least(&body, n);
                let who = name().unwrap_or_default();
                respond(
                    200,
                    format!("answered by {who} after {} bytes", got.len()).as_bytes(),
                );
            }
            "next-then-answer" => {
                // Pass the request on, stream `x-read-bytes` of its body
                // into `next`, then abandon it and answer locally.
                let n = read_bytes(&req);
                let (pending, output) = next_streaming(&forward_head(&req));
                let got = read_at_least(&body, n);
                write_all(&output, &got);
                drop(pending);
                drop(output);
                let who = name().unwrap_or_default();
                respond(
                    200,
                    format!("answered by {who} after forwarding {} bytes", got.len()).as_bytes(),
                );
            }
            "cut-then-await" => {
                // Stream `x-read-bytes` of the body into `next`, leave it
                // unfinished while still waiting on the response, then
                // answer whatever `next` gives back.
                let n = read_bytes(&req);
                let (pending, output) = next_streaming(&forward_head(&req));
                write_all(&output, &read_at_least(&body, n));
                drop(output);
                match PendingResponse::wait(pending) {
                    Ok(resp) => answer_with(resp, false),
                    Err(_) => respond(200, b"answered after next failed"),
                }
            }
            "count" => respond(200, n.to_string().as_bytes()),
            "caps" => {
                let answer = call_capability(&req);
                respond(200, answer.as_bytes());
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
                respond(200, b"grown");
            }
            "next-twice" => {
                let first = chain::next(&forward_head(&req), Body::Empty).expect("next");
                let _second = chain::next(&forward_head(&req), Body::Empty);
                drop(first);
                respond(200, b"unreachable");
            }
            "trap" => panic!("layer panics"),
            "no-response" => {}
            "leak" => {
                // Answer, write part of the body, and return without
                // finishing it.
                let out = respond_streaming(&head(200, Vec::new()));
                write_all(&out, b"partial");
                std::mem::forget(out);
            }
            "trap-after-head" => {
                let out = respond_streaming(&head(200, Vec::new()));
                write_all(&out, b"partial");
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
                let out = respond_streaming(&head(200, Vec::new()));
                write_all(&out, b"partial");
                let mut i: u64 = 0;
                loop {
                    flow::add_tag(&format!("{i:0>len$}"));
                    i += 1;
                }
            }
            "trap-after-finish" => {
                respond(200, b"complete");
                panic!("layer panics after its response");
            }
            "endpoint-bad-path" => {
                // A refused path is an error the layer recovers from; the
                // body it handed the call is spent either way.
                let r = RequestHead {
                    method: "GET".to_owned(),
                    scheme: None,
                    authority: None,
                    path_with_query: "/a b".to_owned(),
                    headers: Vec::new(),
                };
                match endpoints::call("monitor", &r, Body::Passthrough(body)) {
                    Err(types::Error::RequestUriInvalid) => respond(200, b"recovered"),
                    Err(e) => respond(500, format!("{e:?}").as_bytes()),
                    Ok(_) => respond(500, b"accepted a bad path"),
                }
            }
            "big-bytes" => {
                // A whole body past what the host holds for a guest.
                let n: usize = header(&req, "x-bytes")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(2 << 20);
                drop(body);
                respond(200, &vec![b'b'; n]);
            }
            "rewrite" => {
                // Pass a new request (to another path, with a new body).
                let mut r = forward_head(&req);
                r.path_with_query = "/rewritten".to_owned();
                let (pending, out) = next_streaming(&r);
                // The rules may refuse the request at its head and drop
                // its body before it is written: not an error here.
                let _ = out.blocking_write_and_flush(b"replaced");
                types::finish(out);
                drop(body);
                answer_with(await_response(pending), false);
            }
            "elsewhere-then-metric" => {
                // Send the request (bodiless) to `x-to`'s host, wait for the
                // response, then answer with this flow's `requests` metric
                // as `metric-get` sees it.
                let mut r = forward_head(&req);
                r.authority = Some(header(&req, "x-to").expect("x-to"));
                let (pending, out) = chain::next(&r, Body::Empty).expect("next");
                assert!(out.is_none());
                drop(body);
                let (_, below) = await_response(pending);
                drop(read_all(&below));
                drop(below);
                let got = flow::metric_get("by_host", &[]);
                respond(200, format!("{got:?}").as_bytes());
            }
            "probe" => {
                // Report how much of each body reached this layer:
                // `x-saw-request` on the forwarded request, `x-saw-response`
                // on the response, and (with `x-probe-record`) a `probe`
                // record with both.
                let record = header(&req, "x-probe-record").is_some();
                let request = read_all(&body);
                drop(body);
                let saw_request = request.len();
                let r = forward_head_with(
                    &req,
                    vec![(
                        "x-saw-request".to_owned(),
                        saw_request.to_string().into_bytes(),
                    )],
                );
                let (pending, out) = chain::next(&r, Body::Bytes(request)).expect("next");
                assert!(out.is_none());
                let (mut below, below_body) = await_response(pending);
                let bytes = read_all(&below_body);
                drop(below_body);
                below.headers.push((
                    "x-saw-response".to_owned(),
                    bytes.len().to_string().into_bytes(),
                ));
                if record {
                    flow::record(
                        "probe",
                        &format!("{{\"request\":{saw_request},\"response\":{}}}", bytes.len()),
                    );
                }
                let out = chain::respond(&below, Body::Bytes(bytes));
                assert!(out.is_none());
            }
            "inject-request" => {
                // Pass the head on with a body of this layer's own.
                let (pending, out) = next_streaming(&forward_head(&req));
                let _ = out.blocking_write_and_flush(b"injected");
                types::finish(out);
                drop(body);
                answer_with(await_response(pending), false);
            }
            "inject-response" => {
                // Pass the request on, then answer with the response's head
                // over a body of this layer's own.
                let (pending, out) = next_streaming(&forward_head(&req));
                pump(&body, &out, false);
                types::finish(out);
                drop(body);
                let (below, below_body) = await_response(pending);
                drop(read_all(&below_body));
                drop(below_body);
                let out = respond_streaming(&below);
                write_all(&out, b"injected");
                types::finish(out);
            }
            "invalid-next" => {
                // A scheme roxy does not speak: the host refuses the head.
                let mut r = forward_head(&req);
                r.scheme = Some("ftp".to_owned());
                let _ = chain::next(&r, Body::Empty);
                respond(200, b"unreachable");
            }
            other => respond(400, format!("unknown test {other:?}").as_bytes()),
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
