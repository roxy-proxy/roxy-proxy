//! Unit tests of the mux: streams on a link with nothing behind it.

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use roxy_http::{Body, BodyError};
use tokio::sync::{Notify, mpsc};
use tokio_util::sync::CancellationToken;

use super::link::{Link, LinkShared, LinkState, Queued, binary, binary_frame};
use super::lock;
use super::pool::{Pool, Reservation};
use super::stream::{Lanes, MAX_BODY_FRAME, MAX_HOST_CALLS_WAITING, Stream, StreamState, open};
use crate::addons::attribution::Fault;
use crate::addons::chain::{Head, Headless, LaneRx};
use crate::addons::service::testing;
use crate::addons::service::{Call, In, ServiceError};
use crate::addons::{AddonImpl, AddonMode, AddonSpec, Ends, StackError};
use crate::in_flight::Dir;
use crate::testkit::ALLOW_UP;

/// A link whose connection has failed, with nothing behind it.
fn failed_link() -> Arc<Link> {
    let (ctl, _) = mpsc::unbounded_channel();
    let (data, _) = mpsc::channel(1);
    Arc::new(Link {
        shared: Arc::new(LinkShared {
            streams: Mutex::new(LinkState {
                open: HashMap::new(),
                next_id: 1,
                failed: true,
            }),
            ctl,
            refusals: mpsc::channel(1).0,
        }),
        data,
    })
}

/// The lanes around a lone stream's layer: where its forward arrives
/// (the core stage's end) and where its answer arrives (the client edge's
/// end).
struct Around {
    forward: LaneRx,
    answer: LaneRx,
    _ends: Ends,
}

/// An enforce stream on a link with nothing behind it, on the lanes of a
/// one-layer flow. What the stream sends goes nowhere.
async fn lone_stream() -> (Arc<Stream>, Around, crate::testkit::Kit) {
    lone_stream_of(
        testing::addon("s", "pass", AddonMode::Enforce, |_| {}),
        None,
    )
    .await
}

/// [`lone_stream`] for the layer `addon`, in its mode (an observe stream
/// has no lanes), holding `slot` in a pool if given.
async fn lone_stream_of(
    addon: Arc<AddonSpec>,
    slot: Option<Reservation>,
) -> (Arc<Stream>, Around, crate::testkit::Kit) {
    lone_stream_on(addon, slot, failed_link()).await
}

async fn lone_stream_on(
    addon: Arc<AddonSpec>,
    slot: Option<Reservation>,
    link: Arc<Link>,
) -> (Arc<Stream>, Around, crate::testkit::Kit) {
    let mode = addon.mode;
    let kit = testing::kit(ALLOW_UP, vec![addon]).await;
    let (st, _cx, mut ends) = crate::addons::test_flow(&kit);
    let layer = ends.layers.pop().unwrap();
    if mode == AddonMode::Enforce {
        layer.stage.enforcing();
    }
    let lanes = (mode == AddonMode::Enforce).then(|| Lanes {
        req: layer.req_out,
        res: layer.res_out,
        bypassed: Arc::default(),
    });
    let stream = Arc::new(Stream {
        id: 1,
        link: link.clone(),
        st,
        index: 0,
        mode,
        state: Mutex::new(StreamState::new(lanes, slot)),
        more_credit: Notify::new(),
        ended: CancellationToken::new(),
        answered: CancellationToken::new(),
        stop_in: [CancellationToken::new(), CancellationToken::new()],
        bypassed: Arc::default(),
        wire: Arc::default(),
        calls: Mutex::new(None),
        draining: Mutex::new(None),
    });
    lock(&link.shared.streams).open.insert(1, stream.clone());
    let forward = std::mem::replace(&mut ends.core.req_in, layer.req_in);
    let answer = std::mem::replace(&mut ends.edge.res_in, layer.res_in);
    let around = Around {
        forward,
        answer,
        _ends: ends,
    };
    (stream, around, kit)
}

/// The service's fault its stream's failure put on the flow.
fn service_fault(stream: &Stream) -> ServiceError {
    match stream.st.attribution.fault() {
        Some(Fault::Layer {
            err: StackError::Service(e),
            ..
        }) => e,
        other => panic!("a service fault, not {other:?}"),
    }
}

fn request_head() -> In {
    In::Request {
        method: "POST".to_owned(),
        url: "http://up.test/x".to_owned(),
        headers: Vec::new(),
    }
}

/// A head-only lane is the service's head over the bypassed body: the
/// bypassed bytes, trailers and end are the lane's, with no end owed by
/// the service.
#[tokio::test]
async fn a_head_only_lane_is_the_head_over_the_bypassed_body() {
    use crate::addons::Part;
    use http_body_util::BodyExt as _;

    for dir in [Dir::Request, Dir::Response] {
        for with_trailers in [false, true] {
            let addon = testing::subscribed(
                testing::addon("s", "pass", AddonMode::Enforce, |_| {}),
                Part::Head,
                Part::Head,
            );
            let (stream, mut around, _kit) = lone_stream_of(addon, None).await;
            let (mut bypass, body) = Body::channel(u64::MAX, None);
            match dir {
                Dir::Request => {
                    stream.bypassed.hold_request(&mut http::Request::new(body));
                    stream.control(request_head());
                }
                Dir::Response => {
                    stream
                        .bypassed
                        .hold_response(&mut http::Response::new(body));
                    stream.control(In::Response {
                        status: 200,
                        headers: Vec::new(),
                    });
                }
            }
            let (_, mut body) = match dir {
                Dir::Request => around.forward.head().await.unwrap(),
                Dir::Response => around.answer.head().await.unwrap(),
            };
            bypass
                .send_data(bytes::Bytes::from_static(b"through"))
                .await
                .unwrap();
            assert_eq!(
                body.frame().await.unwrap().unwrap().into_data().unwrap(),
                "through"
            );
            if with_trailers {
                let mut trailers = http::HeaderMap::new();
                trailers.insert("x-finished", http::HeaderValue::from_static("yes"));
                bypass.send_trailers(trailers).await.unwrap();
            }
            bypass.finish().await.unwrap();
            if with_trailers {
                let trailers = body
                    .frame()
                    .await
                    .unwrap()
                    .unwrap()
                    .into_trailers()
                    .unwrap();
                assert_eq!(trailers["x-finished"], "yes");
            }
            assert!(body.frame().await.is_none());
            assert!(stream.st.attribution.fault().is_none());
        }
    }
}

/// An end after the head of a head-only lane is the service sending what
/// it is not subscribed to, with or without an error on it.
#[tokio::test]
async fn an_end_after_a_head_only_head_fails_the_service() {
    use crate::addons::Part;

    for error in [None, Some("cut".to_owned())] {
        let addon = testing::subscribed(
            testing::addon("s", "pass", AddonMode::Enforce, |_| {}),
            Part::Head,
            Part::Head,
        );
        let (stream, mut around, _kit) = lone_stream_of(addon, None).await;
        stream.control(In::Response {
            status: 200,
            headers: Vec::new(),
        });
        let _answer = around.answer.head().await.unwrap();
        stream.control(In::ResponseEnd { error });
        assert!(matches!(
            service_fault(&stream),
            ServiceError::Unsubscribed("response")
        ));
    }
}

/// A transport whose queue is drained explicitly by the test.
fn pressure_link(
    depth: usize,
) -> (
    Arc<Link>,
    mpsc::Receiver<Queued>,
    mpsc::UnboundedReceiver<super::link::Message>,
) {
    let (ctl, controls) = mpsc::unbounded_channel();
    let (data, queued) = mpsc::channel(depth);
    (
        Arc::new(Link {
            shared: Arc::new(LinkShared {
                streams: Mutex::new(LinkState {
                    open: HashMap::new(),
                    next_id: 2,
                    failed: false,
                }),
                ctl,
                refusals: mpsc::channel(1).0,
            }),
            data,
        }),
        queued,
        controls,
    )
}

#[tokio::test]
async fn backpressure_request_stop_releases_a_full_transport_queue() {
    let (link, mut queued, _controls) = pressure_link(1);
    let addon = testing::addon("s", "pass", AddonMode::Enforce, |_| {});
    let (stream, _around, _kit) = lone_stream_on(addon, None, link).await;
    // The service has already received this stream's open.
    assert!(stream.wire.write(true));
    let (mut upload, body) = Body::channel(u64::MAX, None);
    upload
        .send_data(bytes::Bytes::from_static(b"body"))
        .await
        .unwrap();
    let mut pump = Box::pin(stream.pump(
        Dir::Request,
        super::super::Out::Request {
            method: "POST".into(),
            url: "http://up.test/x".into(),
            headers: vec![],
        },
        body,
    ));
    // The head fills the socket queue; the body write must wait behind it.
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut pump)
            .await
            .is_err()
    );
    assert_eq!(stream.link.data.capacity(), 0);
    assert!(!upload.is_closed());
    stream.control(In::Stop { dir: Dir::Request });
    let stopped = tokio::time::timeout(Duration::from_millis(100), &mut pump)
        .await
        .is_ok();
    drop(pump);
    assert!(
        stopped,
        "a request stop did not interrupt the full transport queue"
    );
    assert!(
        upload.is_closed(),
        "the stopped upload still owns its source"
    );
    stream.input_done(Dir::Request);
    assert!(!stream.ended.is_cancelled());
    // Once socket progress resumes, the other input can still send bytes.
    queued.recv().await.unwrap();
    assert!(
        stream
            .pump_body(Dir::Response, Body::from_bytes("response"))
            .await
            .is_ok()
    );
    let response = queued.recv().await.unwrap().msg.into_data();
    assert_eq!(response[4], 1);
    assert_eq!(&response[5..], b"response");
}

#[tokio::test]
async fn backpressure_service_credit_stalls_and_resumes_after_bounded_prefetch() {
    use http_body_util::BodyExt as _;
    let (link, _queued, mut controls) = pressure_link(1);
    let addon = testing::addon("s", "pass", AddonMode::Enforce, |_| {});
    let (stream, mut around, _kit) = lone_stream_on(addon, None, link).await;
    stream.control(In::Response {
        status: 200,
        headers: vec![],
    });
    let (_, mut body) = around.answer.head().await.unwrap();
    let window = vec![1u8; usize::try_from(super::window::WINDOW).unwrap()];
    // Two windows can be credited before the consumer reads anything:
    // the lane has two frame slots and the feeder coalesces a full window.
    for _ in 0..2 {
        stream.bytes(Dir::Response, &window);
        let m = tokio::time::timeout(Duration::from_secs(1), controls.recv())
            .await
            .unwrap()
            .unwrap();
        let m: serde_json::Value = serde_json::from_str(m.to_text().unwrap()).unwrap();
        assert_eq!(m["type"], "credit");
        assert_eq!(m["bytes"], super::window::WINDOW);
    }
    stream.bytes(Dir::Response, &window);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), controls.recv())
            .await
            .is_err(),
        "the full lane must withhold further credit"
    );
    assert_eq!(
        body.frame()
            .await
            .unwrap()
            .unwrap()
            .data_ref()
            .unwrap()
            .len(),
        window.len()
    );
    let m = tokio::time::timeout(Duration::from_secs(1), controls.recv())
        .await
        .unwrap()
        .unwrap();
    let m: serde_json::Value = serde_json::from_str(m.to_text().unwrap()).unwrap();
    assert_eq!(m["type"], "credit");
    assert_eq!(m["bytes"], super::window::WINDOW);
    drop(body);
}

#[tokio::test]
async fn backpressure_spent_request_credit_preserves_response_and_stop() {
    use super::stream::Lost;
    let (link, mut queued, _controls) = pressure_link(super::link::WRITE_QUEUE);
    let addon = testing::addon("s", "pass", AddonMode::Enforce, |_| {});
    let (stream, _around, _kit) = lone_stream_on(addon, None, link).await;
    assert!(stream.wire.write(true));
    let request_stream = stream.clone();
    let request = tokio::spawn(async move {
        request_stream
            .pump_body(
                Dir::Request,
                Body::from_bytes(vec![1; 2 * usize::try_from(super::window::WINDOW).unwrap()]),
            )
            .await
    });
    let mut bytes = 0;
    while bytes < usize::try_from(super::window::WINDOW).unwrap() {
        let message = tokio::time::timeout(Duration::from_secs(1), queued.recv())
            .await
            .unwrap()
            .unwrap();
        bytes += message.msg.into_data().len() - 5;
    }
    assert_eq!(bytes, usize::try_from(super::window::WINDOW).unwrap());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), queued.recv())
            .await
            .is_err()
    );
    // Spending request credit must leave the response lane free to run.
    assert!(
        tokio::time::timeout(
            Duration::from_secs(1),
            stream.pump_body(Dir::Response, Body::from_bytes("response"))
        )
        .await
        .unwrap()
        .is_ok()
    );
    let response = queued.recv().await.unwrap().msg.into_data();
    assert_eq!(response[4], 1);
    assert_eq!(&response[5..], b"response");
    stream.control(In::Credit {
        dir: Dir::Request,
        bytes: MAX_BODY_FRAME as u64,
    });
    let resumed = tokio::time::timeout(Duration::from_secs(1), queued.recv())
        .await
        .unwrap()
        .unwrap()
        .msg
        .into_data();
    assert_eq!(resumed.len() - 5, MAX_BODY_FRAME);
    stream.control(In::Stop { dir: Dir::Request });
    let result = tokio::time::timeout(Duration::from_secs(1), request)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(result, Err(Lost::Stream)),
        "a stop wakes a pump waiting for credit"
    );
}

#[tokio::test]
async fn a_stopped_forward_upload_keeps_the_upstream_response_input() {
    let (stream, mut around, _kit) = lone_stream().await;
    stream.input_done(Dir::Request);
    stream.control(In::Response {
        status: 200,
        headers: Vec::new(),
    });
    stream.control(In::ResponseEnd { error: None });
    let (_, body) = around.answer.head().await.unwrap();
    body.collect_up_to(u64::MAX).await.unwrap();
    stream.stop(Dir::Request);
    assert!(!lock(&stream.state).ended());
    assert!(!stream.st.layer_torn(0));
    stream.input_done(Dir::Response);
    tokio::time::timeout(Duration::from_secs(1), stream.until_ended())
        .await
        .unwrap();
}

#[tokio::test]
async fn a_headless_forward_end_releases_the_held_upload_before_the_answer_ends() {
    let (stream, _around, _kit) = lone_stream().await;
    let (upload, body) = Body::channel(u64::MAX, None);
    stream.bypassed.hold_request(&mut http::Request::new(body));
    stream.control(In::Response {
        status: 200,
        headers: Vec::new(),
    });
    stream.control(In::RequestEnd { error: None });
    tokio::time::timeout(Duration::from_secs(1), upload.closed())
        .await
        .unwrap();
    assert!(!lock(&stream.state).ended(), "the answer remains open");
}

#[tokio::test]
async fn accepted_calls_receive_results_after_the_observers_close() {
    let (ctl, _ctl_rx) = mpsc::unbounded_channel();
    let (refusals, mut refused) = mpsc::channel(4);
    let (data, mut sent) = mpsc::channel(4);
    let link = Arc::new(Link {
        shared: Arc::new(LinkShared {
            streams: Mutex::new(LinkState {
                open: HashMap::new(),
                next_id: 2,
                failed: false,
            }),
            ctl,
            refusals,
        }),
        data,
    });
    let addon = testing::granted(
        testing::addon("s", "pass", AddonMode::Observe, |_| {}),
        &[roxy_wasm::Capability::Record],
    );
    let (stream, _around, kit) = lone_stream_on(addon, None, link).await;
    stream.control(In::Call(Call::Record {
        id: 9,
        kind: "final".into(),
        data: serde_json::json!({}),
    }));
    stream.input_done(Dir::Request);
    stream.input_done(Dir::Response);
    stream.control(In::Close);
    assert!(
        !lock(&stream.state).ended(),
        "the accepted call retains the stream"
    );
    let queued = tokio::time::timeout(Duration::from_secs(1), sent.recv())
        .await
        .unwrap()
        .unwrap();
    let value: serde_json::Value = serde_json::from_str(queued.msg.to_text().unwrap()).unwrap();
    assert_eq!(value["type"], "result");
    assert_eq!(value["id"], 9);
    stream.until_ended().await;
    assert_eq!(kit.events("layer_record", 1).await[0]["kind"], "final");

    // A new call can cross the final input end on the wire. It receives
    // a refusal, including if the reader routed it just before retirement.
    for routed in [false, true] {
        if routed {
            lock(&stream.link.shared.streams)
                .open
                .insert(stream.id, stream.clone());
        }
        let serde_json::Value::Object(call) = serde_json::json!({
            "type": "record", "id": 10, "kind": "too late", "data": {}
        }) else {
            unreachable!();
        };
        super::link::control_frame(&stream.link.shared, stream.id, call).unwrap();
        let reply = refused.try_recv().expect("the late call is refused");
        let value: serde_json::Value = serde_json::from_str(reply.to_text().unwrap()).unwrap();
        assert_eq!(value["type"], "result");
        assert_eq!(value["stream"], stream.id);
        assert_eq!(value["id"], 10);
        assert_eq!(value["error"], "the stream has ended");
        assert!(sent.try_recv().is_err(), "no accepted call's result");
        lock(&stream.link.shared.streams).open.remove(&stream.id);
    }
}

#[tokio::test]
async fn short_body_after_both_ends_is_a_protocol_fault() {
    let (stream, mut around, _kit) = lone_stream().await;
    stream.control(In::Response {
        status: 200,
        headers: vec![("content-length".into(), "10".into())],
    });
    let (_, body) = around.answer.head().await.unwrap();
    stream.bytes(Dir::Response, b"short");
    stream.control(In::RequestEnd { error: None });
    stream.control(In::ResponseEnd { error: None });
    assert!(body.collect_up_to(u64::MAX).await.is_err());
    tokio::task::yield_now().await;
    assert_eq!(service_fault(&stream).kind(), "service:protocol");
    assert!(!stream.st.cause().aborted);
}

#[tokio::test]
async fn headless_response_cut_generates_no_response_fault() {
    let (stream, _around, _kit) = lone_stream().await;
    stream.control(In::ResponseEnd {
        error: Some("no answer".into()),
    });
    assert!(
        matches!(stream.st.attribution.fault(), Some(Fault::Layer { .. })),
        "an enforcing layer with no answer must record no_response at its stage"
    );
}

#[tokio::test]
async fn data_after_trailers_is_rejected() {
    for dir in [Dir::Request, Dir::Response] {
        for feed_first in [false, true] {
            let (stream, _around, _kit) = lone_stream().await;
            stream.control(match dir {
                Dir::Request => request_head(),
                Dir::Response => In::Response {
                    status: 200,
                    headers: Vec::new(),
                },
            });
            stream.control(In::Trailers {
                dir,
                headers: vec![("x-check".to_owned(), "done".to_owned())],
            });
            if feed_first {
                tokio::task::yield_now().await;
            }
            stream.bytes(dir, b"after trailers");
            assert!(
                lock(&stream.state).ended(),
                "DATA after trailers was accepted"
            );
            assert_eq!(service_fault(&stream).kind(), "service:protocol");
        }
    }
}

/// The service's response head is taken while the request body it is
/// forwarding is still streaming; each body's bytes reach their own
/// consumer, and the stream ends once both outputs finish, with its
/// input pumps already complete.
#[tokio::test]
async fn a_response_head_arrives_while_the_request_body_streams() {
    let (stream, mut around, _kit) = lone_stream().await;
    stream.input_done(Dir::Request);
    stream.input_done(Dir::Response);
    stream.control(request_head());
    let (_, req) = around
        .forward
        .head()
        .await
        .expect("the request is forwarded");
    stream.bytes(Dir::Request, b"up");
    stream.control(In::Response {
        status: 200,
        headers: Vec::new(),
    });
    let (head, res) = tokio::time::timeout(Duration::from_millis(100), around.answer.head())
        .await
        .expect("the response head is not held behind the request body")
        .unwrap();
    assert!(matches!(head, Head::Response(p) if p.status == 200));
    stream.bytes(Dir::Response, b"down");
    stream.control(In::ResponseEnd { error: None });
    assert_eq!(
        res.collect_up_to(u64::MAX).await.unwrap().data,
        &b"down"[..]
    );
    assert!(
        !lock(&stream.state).ended(),
        "the request lane is still owed"
    );
    stream.bytes(Dir::Request, b"load");
    stream.control(In::RequestEnd { error: None });
    assert_eq!(
        req.collect_up_to(u64::MAX).await.unwrap().data,
        &b"upload"[..]
    );
    assert!(lock(&stream.state).ended());
}

/// A lane the service ends before its head carries nothing: a headless
/// `request_end` is no forward, and the stream still owes the answer.
#[tokio::test]
async fn a_headless_request_end_is_no_forward() {
    let (stream, mut around, _kit) = lone_stream().await;
    stream.control(In::RequestEnd { error: None });
    assert_eq!(around.forward.head().await.unwrap_err(), Headless::Ended);
    assert!(!lock(&stream.state).ended(), "the answer is owed");
    stream.control(In::Response {
        status: 204,
        headers: Vec::new(),
    });
    stream.control(In::ResponseEnd { error: None });
    let (_, body) = around.answer.head().await.unwrap();
    body.collect_up_to(u64::MAX).await.unwrap();
    assert!(
        !lock(&stream.state).ended(),
        "input pumps still own their lanes"
    );
    stream.input_done(Dir::Request);
    stream.input_done(Dir::Response);
    stream.until_ended().await;
}

/// An end the service sends with an error cuts the lane where it is: an
/// abort of its own, not its fault, and the stream goes on to its end.
#[tokio::test]
async fn a_lane_the_service_cuts_is_its_abort_not_its_fault() {
    let (stream, mut around, _kit) = lone_stream().await;
    stream.control(request_head());
    let (_, req) = around
        .forward
        .head()
        .await
        .expect("the request is forwarded");
    stream.bytes(Dir::Request, b"part");
    stream.control(In::RequestEnd {
        error: Some("changed my mind".to_owned()),
    });
    assert!(req.collect_up_to(u64::MAX).await.is_err());
    assert!(!lock(&stream.state).ended(), "the answer is still owed");
    assert!(stream.st.attribution.fault().is_none(), "no fault");
    assert!(stream.st.cause().aborted);
}

/// Trailers come once, after the body's bytes and before its end, and
/// reach the lane as the body's last frame; before a head they are a
/// protocol error.
#[tokio::test]
async fn trailers_follow_the_bytes_and_precede_the_end() {
    use http_body_util::BodyExt as _;
    let (stream, mut around, _kit) = lone_stream().await;
    stream.control(request_head());
    let (_, req) = around
        .forward
        .head()
        .await
        .expect("the request is forwarded");
    stream.bytes(Dir::Request, b"body");
    stream.control(In::Trailers {
        dir: Dir::Request,
        headers: vec![("x-sum".to_owned(), "1".to_owned())],
    });
    stream.control(In::RequestEnd { error: None });
    let collected = req.collect().await.unwrap();
    assert_eq!(collected.trailers().unwrap()["x-sum"], "1");
    assert_eq!(collected.to_bytes(), &b"body"[..]);
    assert!(!lock(&stream.state).ended());
    stream.control(In::Trailers {
        dir: Dir::Response,
        headers: Vec::new(),
    });
    assert!(lock(&stream.state).ended(), "trailers before a head");
    assert_eq!(service_fault(&stream).kind(), "service:protocol");
}

/// The service's `stop` ends roxy's pump of that body where it is.
#[tokio::test]
async fn a_stop_from_the_service_ends_the_pump() {
    let (stream, _around, _kit) = lone_stream().await;
    let (_tx, body) = Body::channel(u64::MAX, None);
    stream.control(In::Stop { dir: Dir::Request });
    let pumped = tokio::time::timeout(
        Duration::from_millis(100),
        stream.pump_body(Dir::Request, body),
    )
    .await
    .expect("the pump ends on the stop");
    assert!(matches!(pumped, Err(super::stream::Lost::Stream)));
}

/// A request head that does not parse is the service's protocol error:
/// the stream ends, the layer is torn down with it, and nothing was
/// forwarded.
#[tokio::test]
async fn an_invalid_request_head_fails_the_stream() {
    let (stream, mut around, _kit) = lone_stream().await;
    stream.control(In::Request {
        method: "GET".to_owned(),
        url: "http://up.test/".to_owned(),
        headers: vec![("bad header".to_owned(), "x".to_owned())],
    });
    assert!(lock(&stream.state).ended());
    assert!(
        matches!(around.forward.head().await, Err(Headless::Cut(_))),
        "nothing is forwarded"
    );
    assert_eq!(service_fault(&stream).kind(), "service:protocol");
}

fn fields(n: usize) -> Vec<(String, String)> {
    (0..n).map(|i| (format!("x-{i}"), "v".to_owned())).collect()
}

/// A service head is held to `limits.max_headers` like any head roxy
/// parses: one field over is the service's protocol error, on either
/// head, and the stream ends rather than the connection's reader.
#[tokio::test]
async fn a_head_with_more_than_max_headers_fields_fails_the_stream() {
    let (stream, _around, _kit) = lone_stream().await;
    stream.control(In::Request {
        method: "GET".to_owned(),
        url: "http://up.test/".to_owned(),
        headers: fields(101),
    });
    assert!(lock(&stream.state).ended());
    let e = service_fault(&stream);
    assert_eq!(e.kind(), "service:protocol", "{e}");
    assert_eq!(
        e.to_string(),
        "service protocol violation: 101 header fields, more than max_headers (100)"
    );

    let (stream, mut around, _kit) = lone_stream().await;
    stream.control(request_head());
    around
        .forward
        .head()
        .await
        .expect("the request is forwarded");
    stream.control(In::Response {
        status: 200,
        headers: fields(101),
    });
    assert!(lock(&stream.state).ended());
    let e = service_fault(&stream);
    assert!(e.to_string().contains("max_headers (100)"), "{e}");
}

/// Bytes are owed to a head in their own direction: response bytes
/// while only the request body is being fed fail the stream.
#[tokio::test]
async fn bytes_of_a_body_without_a_head_fail_the_stream() {
    let (stream, mut around, _kit) = lone_stream().await;
    stream.control(request_head());
    let (_, req) = around
        .forward
        .head()
        .await
        .expect("the request is forwarded");
    stream.bytes(Dir::Response, b"early");
    assert!(lock(&stream.state).ended());
    assert!(req.collect_up_to(u64::MAX).await.is_err());
    let e = service_fault(&stream);
    assert!(
        e.to_string()
            .contains("bytes of a response body that is not open"),
        "{e}"
    );
}

/// A body that fails on its way to the service ends its lane with the
/// failure and nothing else: the stream goes on, the service's answer is
/// still owed, and the fault is whoever handed the body to the stack,
/// recorded as the pump read the failure.
#[tokio::test]
async fn a_body_failing_on_its_way_to_the_service_ends_its_lane_only() {
    use crate::addons::attribution::{Side, attributed};
    let (stream, _around, _kit) = lone_stream().await;
    let (tx, body) = Body::channel(u64::MAX, None);
    tx.abort(BodyError::Incomplete);
    let body = attributed(&stream.st, Side::Client, body);
    assert!(matches!(
        stream.pump_body(Dir::Request, body).await,
        Err(super::stream::Lost::Body(BodyError::Incomplete))
    ));
    assert!(
        matches!(stream.st.attribution.fault(), Some(Fault::Client(_))),
        "the client is at fault, not the service"
    );
    assert!(!lock(&stream.state).ended(), "the stream goes on");
}

/// A call the service sent before the stream ended still runs once it
/// has: the record reaches the flow log, named by the call, though its
/// `result` has nowhere to go. The worker has not run when the stream is
/// reset, so the call is still queued at the end.
#[tokio::test]
async fn a_call_queued_before_the_end_still_runs() {
    let addon = testing::granted(
        testing::addon("s", "pass", AddonMode::Enforce, |_| {}),
        &[roxy_wasm::Capability::Record],
    );
    let (stream, _around, kit) = lone_stream_of(addon, None).await;
    stream.control(In::Call(Call::Record {
        id: 7,
        kind: "late".to_owned(),
        data: serde_json::json!({"n": 1}),
    }));
    stream.reset("the exchange ended");
    assert!(lock(&stream.state).ended());
    let r = kit.events("layer_record", 1).await;
    assert_eq!(r[0]["kind"], "late", "{r:#?}");
    assert_eq!(r[0]["call"], 7, "{r:#?}");
}

/// An ended stream keeps its place on the connection while the calls
/// queued before its end still run, so what a service leaves behind on
/// ended streams is bounded like its open ones; the place goes once they
/// have run. The worker has not run when the stream is reset, so the call
/// is still queued then.
#[tokio::test]
async fn an_ended_stream_keeps_its_place_until_its_calls_have_run() {
    let pool = Arc::new(Pool {
        entries: Mutex::new(Vec::new()),
        freed: Notify::new(),
        max_connections: 1,
        max_streams: 1,
        retired: AtomicBool::new(false),
    });
    let slot = pool.reserve().await;
    let addon = testing::granted(
        testing::addon("s", "pass", AddonMode::Observe, |_| {}),
        &[roxy_wasm::Capability::Record],
    );
    let (stream, _around, kit) = lone_stream_of(addon, Some(slot)).await;
    stream.control(In::Call(Call::Record {
        id: 1,
        kind: "late".to_owned(),
        data: serde_json::json!({}),
    }));
    stream.reset("the exchange ended");
    assert_eq!(
        lock(&pool.entries)[0].reserved,
        1,
        "the place is held while the call waits to run"
    );
    kit.events("layer_record", 1).await;
    let place = tokio::time::timeout(Duration::from_millis(500), pool.reserve()).await;
    assert!(place.is_ok(), "the place is free once the call has run");
}

/// A call handed to a stream that has already ended is refused, with no
/// worker started for it. The reader may still hold the stream after
/// another task ended it, and must learn that it owes a refusal.
#[tokio::test]
async fn a_call_after_the_end_is_not_accepted() {
    let addon = testing::granted(
        testing::addon("s", "pass", AddonMode::Observe, |_| {}),
        &[roxy_wasm::Capability::Record],
    );
    let (stream, _around, kit) = lone_stream_of(addon, None).await;
    stream.reset("the exchange ended");
    assert!(!stream.queue_host_call(Call::Record {
        id: 1,
        kind: "late".to_owned(),
        data: serde_json::json!({}),
    }));
    assert!(
        lock(&stream.calls).is_none(),
        "no worker for a dropped call"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        kit.sink
            .events()
            .iter()
            .all(|e| e["event"] != "layer_record"),
        "the call did not run"
    );
}

/// A call that fails after the stream has ended is still the layer's
/// failure, logged once with its call id and the failure's kind: `settle`
/// has nothing left to tell, so the worker logs it itself, and the calls
/// queued behind it still run. An observe stream, whose failures are
/// logged as they come.
#[tokio::test]
async fn a_call_failing_after_the_end_is_logged() {
    let addon = testing::granted(
        testing::addon("s", "pass", AddonMode::Observe, |_| {}),
        &[roxy_wasm::Capability::Record],
    );
    let (stream, _around, kit) = lone_stream_of(addon, None).await;
    stream.control(In::Call(Call::StateGet {
        id: 9,
        key: "k".to_owned(),
    }));
    stream.control(In::Call(Call::Record {
        id: 10,
        kind: "after".to_owned(),
        data: serde_json::json!({}),
    }));
    stream.reset("the exchange ended");
    assert!(lock(&stream.state).ended());
    let errs = kit.events("layer_error", 1).await;
    assert_eq!(errs[0]["layer"], "s", "{errs:#?}");
    assert_eq!(errs[0]["mode"], "observe", "{errs:#?}");
    assert_eq!(errs[0]["kind"], "capability:state", "{errs:#?}");
    assert_eq!(errs[0]["call"], 9, "{errs:#?}");
    let r = kit.events("layer_record", 1).await;
    assert_eq!(r[0]["call"], 10, "the call behind the failure ran: {r:#?}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let errs: Vec<_> = kit
        .sink
        .events()
        .into_iter()
        .filter(|e| e["event"] == "layer_error")
        .collect();
    assert_eq!(errs.len(), 1, "{errs:#?}");
}

/// `MAX_HOST_CALLS_WAITING` calls may wait for the stream's worker; one
/// more is the service's protocol error, and fails the stream.
#[tokio::test]
async fn more_calls_waiting_than_the_cap_fail_the_stream() {
    let (stream, _around, _kit) = lone_stream().await;
    let get = |id| {
        In::Call(Call::StateGet {
            id,
            key: "k".to_owned(),
        })
    };
    let cap = u64::try_from(MAX_HOST_CALLS_WAITING).unwrap();
    for id in 1..=cap {
        stream.control(get(id));
    }
    assert!(!lock(&stream.state).ended(), "{cap} calls may wait");
    stream.control(get(cap + 1));
    assert!(lock(&stream.state).ended());
    let e = service_fault(&stream);
    assert_eq!(e.kind(), "service:protocol", "{e}");
    assert_eq!(
        e.to_string(),
        format!("service protocol violation: more than {cap} host calls waiting")
    );
}

/// A connection that failed keeps its place in the pool while streams
/// still hold it; the pool opens another only once they are gone.
#[tokio::test]
async fn a_failed_connection_counts_until_its_streams_end() {
    let pool = Arc::new(Pool {
        entries: Mutex::new(Vec::new()),
        freed: Notify::new(),
        max_connections: 1,
        max_streams: 2,
        retired: AtomicBool::new(false),
    });
    let first = pool.reserve().await;
    let second = pool.reserve().await;
    assert!(Arc::ptr_eq(&first.link, &second.link));
    first.link.set(failed_link()).ok().unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), pool.reserve())
            .await
            .is_err(),
        "the pool is full: one connection, held by two streams"
    );
    drop(first);
    drop(second);
    assert!(lock(&pool.entries).is_empty());
    let fresh = tokio::time::timeout(Duration::from_millis(100), pool.reserve())
        .await
        .expect("room again");
    assert!(fresh.link.get().is_none(), "a new connection");
}

/// Concurrent streams spread across the pool's connections: a stream
/// opens a new one while the pool has room and none is idle, then the one
/// with the fewest streams takes the next, and a full connection is passed
/// over for one with room.
#[tokio::test]
async fn streams_spread_across_connections() {
    let pool = Arc::new(Pool {
        entries: Mutex::new(Vec::new()),
        freed: Notify::new(),
        max_connections: 2,
        max_streams: 2,
        retired: AtomicBool::new(false),
    });
    let first = pool.reserve().await;
    let second = pool.reserve().await;
    assert!(
        !Arc::ptr_eq(&first.link, &second.link),
        "a second connection opens"
    );
    let third = pool.reserve().await;
    let fourth = pool.reserve().await;
    assert!(
        !Arc::ptr_eq(&third.link, &fourth.link),
        "the connection with fewer streams takes the next"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), pool.reserve())
            .await
            .is_err(),
        "every connection is full"
    );
    let freed = first.link.clone();
    drop(first);
    let fifth = pool.reserve().await;
    assert!(Arc::ptr_eq(&fifth.link, &freed), "the place a stream freed");
    assert!(lock(&pool.entries).iter().all(|e| e.reserved == 2));
}

/// Fills the data queue of `stream`'s connection with body frames of
/// its own, until the writer is stalled on a socket nobody reads and
/// the queue stays full.
async fn fill(stream: &Stream) {
    let frame = binary(stream.id, Dir::Request, &vec![0u8; MAX_BODY_FRAME]);
    let queued = || Queued {
        msg: frame.clone(),
        wire: stream.wire.clone(),
        open: false,
    };
    loop {
        while stream.link.data.try_send(queued()).is_ok() {}
        tokio::time::sleep(Duration::from_millis(50)).await;
        if stream.link.data.try_send(queued()).is_err() {
            break;
        }
    }
}

/// A stream reset while its `open` is still queued, behind a full
/// data queue: the service sees its `open` before its `reset`, or
/// neither.
#[tokio::test]
async fn a_reset_never_overtakes_its_open() {
    let kit = testing::kit(
        ALLOW_UP,
        vec![testing::addon("s", "pause", AddonMode::Enforce, |s| {
            s.max_connections = 1;
        })],
    )
    .await;
    let (st, _cx, _ends) = crate::addons::test_flow(&kit);
    let snap = st.snap.clone();
    let AddonImpl::Service(svc) = &snap.addons[0].kind else {
        panic!("a service layer");
    };

    let first = open(&st, 0, svc, AddonMode::Observe, &mut None)
        .await
        .unwrap();
    // The service reads nothing until its pause is over.
    fill(&first).await;
    // Queued at the back once the writer moves again.
    let second = open(&st, 0, svc, AddonMode::Observe, &mut None)
        .await
        .unwrap();
    second.reset("the exchange ended");
    // Everything before this is on the wire once its `open` is.
    let third = open(&st, 0, svc, AddonMode::Observe, &mut None)
        .await
        .unwrap();

    let log = kit.upstream.service();
    let opened = |id: u32| log.opens().iter().any(|o| o["stream"] == id);
    tokio::time::timeout(Duration::from_secs(10), async {
        while !opened(third.id) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the third stream opens");
    assert_eq!(
        log.unknown_resets(),
        Vec::<u32>::new(),
        "a reset before its open"
    );
    let reset = log.resets().iter().any(|(id, _)| *id == second.id);
    assert_eq!(opened(second.id), reset, "open and reset, or neither");
}

/// An `open` given up while its message waits for the socket (a
/// missed `first_byte_timeout`) leaves no stream behind: the next
/// exchange gets its place.
#[tokio::test]
async fn an_open_given_up_mid_send_releases_its_place() {
    let kit = testing::kit(
        ALLOW_UP,
        vec![testing::addon("s", "stall", AddonMode::Enforce, |s| {
            s.max_connections = 1;
            s.max_streams = 2;
        })],
    )
    .await;
    let (st, _cx, _ends) = crate::addons::test_flow(&kit);
    let snap = st.snap.clone();
    let AddonImpl::Service(svc) = &snap.addons[0].kind else {
        panic!("a service layer");
    };

    let first = open(&st, 0, svc, AddonMode::Observe, &mut None)
        .await
        .unwrap();
    // The service never reads.
    fill(&first).await;
    let given_up = tokio::time::timeout(
        Duration::from_millis(100),
        open(&st, 0, svc, AddonMode::Observe, &mut None),
    )
    .await;
    assert!(given_up.is_err(), "the open message cannot go");

    assert_eq!(lock(&first.link.shared.streams).open.len(), 1);
    let pool = lock(&snap.services.by_key).values().next().unwrap().clone();
    assert_eq!(lock(&pool.entries)[0].reserved, 1);
    let place = tokio::time::timeout(Duration::from_millis(100), pool.reserve()).await;
    assert!(place.is_ok(), "the given-up stream's place is free");
}

/// Body frames for a stream that has ended queue nothing on the
/// connection, however many arrive, and do not fail it.
#[tokio::test]
async fn frames_on_an_ended_stream_queue_nothing() {
    let (ctl, mut ctl_rx) = mpsc::unbounded_channel();
    let shared = LinkShared {
        streams: Mutex::new(LinkState {
            open: HashMap::new(),
            next_id: 2,
            failed: false,
        }),
        ctl,
        refusals: mpsc::channel(1).0,
    };
    let frame = binary(1, Dir::Request, b"x");
    for _ in 0..10_000 {
        binary_frame(&shared, &frame.clone().into_data()).unwrap();
    }
    assert!(
        matches!(ctl_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "nothing queued for an ended stream"
    );
    assert!(!lock(&shared.streams).failed);
}

/// Late-call replies cannot grow the unbounded credit/reset queue. A
/// service flooding them fails the connection when their queue fills.
#[test]
fn replies_to_calls_on_ended_streams_are_bounded() {
    let (ctl, mut ctl_rx) = mpsc::unbounded_channel();
    let (refusals, mut replies) = mpsc::channel(2);
    let shared = LinkShared {
        streams: Mutex::new(LinkState {
            open: HashMap::new(),
            next_id: 2,
            failed: false,
        }),
        ctl,
        refusals,
    };
    let call = || {
        let serde_json::Value::Object(v) = serde_json::json!({
            "type": "quarantine", "id": 3
        }) else {
            unreachable!();
        };
        v
    };
    for _ in 0..2 {
        super::link::control_frame(&shared, 1, call()).unwrap();
    }
    assert!(matches!(
        super::link::control_frame(&shared, 1, call()),
        Err(ServiceError::Protocol(_))
    ));
    assert!(ctl_rx.try_recv().is_err());
    for _ in 0..2 {
        assert!(replies.try_recv().is_ok());
    }
    assert!(replies.try_recv().is_err());
    assert!(
        matches!(
            super::link::control_frame(&shared, 2, call()),
            Err(ServiceError::Protocol(_))
        ),
        "a never-opened stream still fails framing"
    );
    assert!(replies.try_recv().is_err());
}
