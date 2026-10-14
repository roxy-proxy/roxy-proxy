//! Unit tests of the mux: streams on a link with nothing behind it.

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use roxy_http::{Body, BodyError};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use super::link::{Link, LinkShared, LinkState, Queued, binary, binary_frame};
use super::lock;
use super::pool::{Pool, Reservation};
use super::stream::{
    Answers, MAX_BODY_FRAME, MAX_HOST_CALLS_WAITING, Phase, Stream, StreamState, open,
};
use crate::addons::service::testing;
use crate::addons::service::{Call, First, In, Unanswered};
use crate::addons::{AddonImpl, AddonMode, AddonSpec};
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
        }),
        data,
    })
}

/// An enforce stream on a link with nothing behind it, with the
/// answers an exchange would wait on. What the stream sends goes
/// nowhere.
async fn lone_stream() -> (Arc<Stream>, Answers, crate::testkit::Kit) {
    lone_stream_of(
        testing::addon("s", "pass", AddonMode::Enforce, |_| {}),
        None,
    )
    .await
}

/// [`lone_stream`] for the layer `addon`, in its mode (an observe
/// stream's answers go unused), holding `slot` in a pool if given.
async fn lone_stream_of(
    addon: Arc<AddonSpec>,
    slot: Option<Reservation>,
) -> (Arc<Stream>, Answers, crate::testkit::Kit) {
    let mode = addon.mode;
    let kit = testing::kit(ALLOW_UP, vec![addon]).await;
    let (st, _cx) = crate::addons::test_flow(&kit);
    let (first_tx, first) = oneshot::channel();
    let (second_tx, second) = oneshot::channel();
    let phase = match mode {
        AddonMode::Enforce => Phase::AwaitingFirst {
            first: first_tx,
            second: second_tx,
        },
        AddonMode::Observe => Phase::Observing {
            forwarding: false,
            responded: false,
        },
    };
    let link = failed_link();
    let stream = Arc::new(Stream {
        id: 1,
        link: link.clone(),
        st,
        index: 0,
        mode,
        state: Mutex::new(StreamState::new(phase, slot)),
        more_credit: Notify::new(),
        ended: CancellationToken::new(),
        wire: Arc::default(),
        calls: Mutex::new(None),
        draining: Mutex::new(None),
    });
    lock(&link.shared.streams).open.insert(1, stream.clone());
    (stream, Answers { first, second }, kit)
}

fn request_head() -> In {
    In::Request {
        method: "POST".to_owned(),
        url: "http://up.test/x".to_owned(),
        headers: Vec::new(),
    }
}

/// The service's response head is taken while the request body it is
/// forwarding is still streaming; each body's bytes reach their own
/// consumer, and the stream ends once both have.
#[tokio::test]
async fn a_response_head_arrives_while_the_request_body_streams() {
    let (stream, answers, _kit) = lone_stream().await;
    stream.control(request_head());
    let First::Forward(req) = answers.first.await.unwrap().unwrap() else {
        panic!("the request is forwarded");
    };
    stream.bytes(Dir::Request, b"up");
    stream.control(In::Response {
        status: 200,
        headers: Vec::new(),
    });
    let res = tokio::time::timeout(Duration::from_millis(100), answers.second)
        .await
        .expect("the response head is not held behind the request body")
        .unwrap()
        .unwrap();
    assert_eq!(res.status(), 200);
    stream.bytes(Dir::Response, b"down");
    stream.control(In::ResponseEnd);
    assert_eq!(
        res.into_body().collect_up_to(u64::MAX).await.unwrap().data,
        &b"down"[..]
    );
    assert!(
        !lock(&stream.state).ended(),
        "the request body is still owed"
    );
    stream.bytes(Dir::Request, b"load");
    stream.control(In::RequestEnd);
    assert_eq!(
        req.into_body().collect_up_to(u64::MAX).await.unwrap().data,
        &b"upload"[..]
    );
    assert!(lock(&stream.state).ended());
}

/// A `101` from the service answers an upgrade only: on an ordinary
/// exchange it is a protocol violation, like any status below 200.
#[tokio::test]
async fn a_101_on_an_exchange_that_is_not_an_upgrade_fails_the_stream() {
    let (stream, answers, _kit) = lone_stream().await;
    stream.control(request_head());
    let First::Forward(_req) = answers.first.await.unwrap().unwrap() else {
        panic!("the request is forwarded");
    };
    stream.control(In::Response {
        status: 101,
        headers: Vec::new(),
    });
    assert!(lock(&stream.state).ended());
    let e = answers.second.await.unwrap().unwrap_err();
    assert!(e.to_string().contains("status 101"), "{e}");
}

/// A request head that does not parse is the service's protocol error,
/// and the first answer is where the exchange learns it: nothing was
/// forwarded, so that answer is still owed.
#[tokio::test]
async fn an_invalid_request_head_fails_the_first_answer() {
    let (stream, answers, _kit) = lone_stream().await;
    stream.control(In::Request {
        method: "GET".to_owned(),
        url: "http://up.test/".to_owned(),
        headers: vec![("bad header".to_owned(), "x".to_owned())],
    });
    assert!(lock(&stream.state).ended());
    let Err(Unanswered::Service(e)) = answers.first.await.expect("the first answer is told") else {
        panic!("the request is not forwarded");
    };
    assert_eq!(e.kind(), "service:protocol", "{e}");
}

fn fields(n: usize) -> Vec<(String, String)> {
    (0..n).map(|i| (format!("x-{i}"), "v".to_owned())).collect()
}

/// A service head is held to `limits.max_headers` like any head roxy
/// parses: one field over is the service's protocol error, on either
/// head, and the stream ends rather than the connection's reader.
#[tokio::test]
async fn a_head_with_more_than_max_headers_fields_fails_the_stream() {
    let (stream, answers, _kit) = lone_stream().await;
    stream.control(In::Request {
        method: "GET".to_owned(),
        url: "http://up.test/".to_owned(),
        headers: fields(101),
    });
    assert!(lock(&stream.state).ended());
    let Err(Unanswered::Service(e)) = answers.first.await.expect("the first answer is told") else {
        panic!("the request is not forwarded");
    };
    assert_eq!(e.kind(), "service:protocol", "{e}");
    assert_eq!(
        e.to_string(),
        "service protocol violation: 101 header fields, more than max_headers (100)"
    );

    let (stream, answers, _kit) = lone_stream().await;
    stream.control(request_head());
    let First::Forward(_req) = answers.first.await.unwrap().unwrap() else {
        panic!("the request is forwarded");
    };
    stream.control(In::Response {
        status: 200,
        headers: fields(101),
    });
    assert!(lock(&stream.state).ended());
    let e = answers.second.await.unwrap().unwrap_err();
    assert!(e.to_string().contains("max_headers (100)"), "{e}");
}

/// Bytes are owed to a head in their own direction: response bytes
/// while only the request body is being fed fail the stream.
#[tokio::test]
async fn bytes_of_a_body_without_a_head_fail_the_stream() {
    let (stream, answers, _kit) = lone_stream().await;
    stream.control(request_head());
    let First::Forward(req) = answers.first.await.unwrap().unwrap() else {
        panic!("the request is forwarded");
    };
    stream.bytes(Dir::Response, b"early");
    assert!(lock(&stream.state).ended());
    assert!(req.into_body().collect_up_to(u64::MAX).await.is_err());
    let e = answers.second.await.unwrap().unwrap_err();
    assert!(
        e.to_string()
            .contains("bytes of a response body that is not open"),
        "{e}"
    );
}

/// A body that fails on its way to the service ends the stream without
/// blaming the service: the pending answer says which body failed, and
/// the fault is whoever handed the body to the stack, recorded as the
/// pump read the failure.
#[tokio::test]
async fn a_body_failing_on_its_way_to_the_service_is_not_its_failure() {
    use crate::addons::attribution::{Fault, Side, attributed};
    let (stream, answers, _kit) = lone_stream().await;
    let (tx, body) = Body::channel(u64::MAX, None);
    tx.abort(BodyError::Incomplete);
    let body = attributed(&stream.st, Side::Client, body);
    assert!(!stream.pump_body(Dir::Request, body).await);
    assert!(
        matches!(stream.st.attribution.fault(), Some(Fault::Client(_))),
        "the client is at fault, not the service"
    );
    let lost = answers.first.await.unwrap().err().expect("no answer");
    assert!(
        matches!(lost, Unanswered::Body(Dir::Request, BodyError::Incomplete)),
        "{lost:?}"
    );
    assert!(matches!(
        super::super::unanswered(lost),
        super::super::Fail::Below(_)
    ));
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
    let (stream, _answers, kit) = lone_stream_of(addon, None).await;
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
    let (stream, _answers, kit) = lone_stream_of(addon, Some(slot)).await;
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

/// A call handed to a stream that has already ended is dropped, with no
/// worker started for it: the reader may still hold the stream after
/// another task ended it, and the call crossed the end.
#[tokio::test]
async fn a_call_after_the_end_is_dropped() {
    let addon = testing::granted(
        testing::addon("s", "pass", AddonMode::Observe, |_| {}),
        &[roxy_wasm::Capability::Record],
    );
    let (stream, _answers, kit) = lone_stream_of(addon, None).await;
    stream.reset("the exchange ended");
    stream.control(In::Call(Call::Record {
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
    let (stream, _answers, kit) = lone_stream_of(addon, None).await;
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
    let (stream, answers, _kit) = lone_stream().await;
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
    let Err(Unanswered::Service(e)) = answers.first.await.expect("the first answer is told") else {
        panic!("the request is not forwarded");
    };
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
    let (st, _cx) = crate::addons::test_flow(&kit);
    let snap = st.snap.clone();
    let AddonImpl::Service(svc) = &snap.addons[0].kind else {
        panic!("a service layer");
    };

    let (first, _) = open(&st, 0, svc, AddonMode::Enforce).await.unwrap();
    // The service reads nothing until its pause is over.
    fill(&first).await;
    // Queued at the back once the writer moves again.
    let (second, _) = open(&st, 0, svc, AddonMode::Enforce).await.unwrap();
    second.reset("the exchange ended");
    // Everything before this is on the wire once its `open` is.
    let (third, _) = open(&st, 0, svc, AddonMode::Enforce).await.unwrap();

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
    let (st, _cx) = crate::addons::test_flow(&kit);
    let snap = st.snap.clone();
    let AddonImpl::Service(svc) = &snap.addons[0].kind else {
        panic!("a service layer");
    };

    let (first, _) = open(&st, 0, svc, AddonMode::Enforce).await.unwrap();
    // The service never reads.
    fill(&first).await;
    let given_up = tokio::time::timeout(
        Duration::from_millis(100),
        open(&st, 0, svc, AddonMode::Enforce),
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
