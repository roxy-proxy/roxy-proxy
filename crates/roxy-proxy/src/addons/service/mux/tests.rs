//! Unit tests of the mux: streams on a link with nothing behind it.

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use roxy_http::{Body, BodyError};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use super::link::{Link, LinkShared, LinkState, Queued, binary};
use super::lock;
use super::pool::Pool;
use super::stream::{Answers, MAX_BODY_FRAME, Phase, Stream, StreamState, open};
use crate::addons::service::testing;
use crate::addons::service::{First, In, Unanswered};
use crate::addons::{AddonImpl, AddonMode};
use crate::testkit::ALLOW_UP;
use crate::watch::Dir;

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
    let kit = testing::kit(
        ALLOW_UP,
        vec![testing::addon("s", "pass", AddonMode::Enforce, |_| {})],
    )
    .await;
    let (st, _cx) = crate::addons::test_flow(&kit);
    let (first_tx, first) = oneshot::channel();
    let (second_tx, second) = oneshot::channel();
    let link = failed_link();
    let stream = Arc::new(Stream {
        id: 1,
        link: link.clone(),
        st,
        index: 0,
        mode: AddonMode::Enforce,
        state: Mutex::new(StreamState::new(
            Phase::AwaitingFirst {
                first: first_tx,
                second: second_tx,
            },
            None,
        )),
        more_credit: Notify::new(),
        ended: CancellationToken::new(),
        wire: Arc::default(),
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
        res.into_body().collect_up_to(u64::MAX).await.unwrap(),
        &b"down"[..]
    );
    assert!(
        !lock(&stream.state).ended(),
        "the request body is still owed"
    );
    stream.bytes(Dir::Request, b"load");
    stream.control(In::RequestEnd);
    assert_eq!(
        req.into_body().collect_up_to(u64::MAX).await.unwrap(),
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
/// the exchange takes a request body's failure as the client's.
#[tokio::test]
async fn a_body_failing_on_its_way_to_the_service_is_not_its_failure() {
    let (stream, answers, _kit) = lone_stream().await;
    let (tx, body) = Body::channel(u64::MAX, None);
    tx.abort(BodyError::Incomplete);
    assert!(!stream.pump_body(Dir::Request, body).await);
    let lost = answers.first.await.unwrap().err().expect("no answer");
    assert!(
        matches!(lost, Unanswered::Body(Dir::Request, BodyError::Incomplete)),
        "{lost:?}"
    );
    assert!(matches!(
        super::super::unanswered(&stream.st, 0, lost),
        super::super::Fail::Below(_)
    ));
    assert!(
        matches!(stream.st.take_fault(), crate::addons::Fault::Client(_)),
        "the client is at fault, not the service"
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
