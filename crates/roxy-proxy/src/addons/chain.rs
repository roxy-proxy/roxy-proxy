//! The exchange as a chain of lanes.
//!
//! ```text
//!   S0 (client edge) ──req[0]──▶ L1 ──req[1]──▶ … ──req[n]──▶ Sn+1 (core)
//!                    ◀──res[0]──    ◀──res[1]──   …  ◀──res[n]──
//! ```
//!
//! Hop `k` joins stages `Sk` and `Sk+1` with two lanes: `req[k]`, produced
//! by `Sk` and consumed by `Sk+1`, and `res[k]`, produced by `Sk+1` and
//! consumed by `Sk`. A lane is shaped like an HTTP/2 stream: its producer
//! puts at most one head on it, then data, then ends or cuts it; its
//! consumer stops it by letting go of it before the end. A lane ended or cut
//! without a head carries nothing: a headless request lane is no forward, a
//! headless response lane is no answer.
//!
//! A lane is terminal once ended, cut or stopped, and never moves again.
//! The rules the chain keeps:
//!
//! - A stage is torn down when it faults or when the consumer of its
//!   response lane stops that lane: its driver is cancelled, every lane it
//!   produces that is not terminal is cut, and every lane it holds is
//!   released. All stages upstream of it are cancelled as well, even if
//!   an intermediate response lane has already ended.
//! - A stopped request lane tells its producer and nothing else.
//! - A layer that lets go of its response lane without a head has not
//!   answered: that is its `no_response` fault.
//! - A faulting layer's fault is recorded first; then it is torn down; and
//!   an HTTP error response is put on its response lane if that lane
//!   has no head yet, so the layer downstream sees a response it may
//!   reshape.
//! - A layer answered if it put its head on the lane it produces before it
//!   had taken the head of the response lane it consumes, decided then.
//! - A layer cutting a lane it produces is an abort, except a headless
//!   response cut, which is the same `no_response` fault as a headless end.
//! - A producer ending a lane does not acknowledge consumption of queued
//!   frames. Every body is read or dropped before its lane is complete.
//! - The exchange is over once all lanes are complete and all registered
//!   drivers have returned. Cancellation reaches stages independently of
//!   lane state, so a completed answer cannot keep upstream work alive.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};

use bytes::Bytes;
use http::HeaderMap;
use http_body::{Body as HttpBody, Frame, SizeHint};
use roxy_http::{Body, BodyError, BodySender};
use roxy_wasm::LayerError;
use tokio::sync::oneshot;
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};
use tokio_util::task::TaskTracker;

use super::{BoxFuture, ENDED, StackError, lock};

/// A teardown's reason when the consumer of a response lane let go of it.
pub(crate) const GAVE_UP: &str = "the layer downstream gave up";
/// A teardown's reason when a layer faulted.
pub(crate) const FAILED: &str = "a layer failed";

/// Bound queued frames so a slow consumer applies backpressure promptly.
const LANE_DEPTH: usize = 2;

/// The head of a lane: a request on a request lane, a response on a
/// response lane.
#[derive(Debug)]
pub(crate) enum Head {
    Request(http::request::Parts),
    Response(http::response::Parts),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Publication {
    Forwarded,
    Failure,
}

/// Where a lane is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LaneState {
    /// No head yet.
    Idle,
    /// A fault reserved this lane for the generated refusal.
    PendingFailure,
    /// The head is on it; the body may still be running.
    Open,
    /// Complete: ended by its producer, with or without a head.
    Ended,
    /// Incomplete: cut by its producer, or by a teardown.
    Cut(String),
    /// Its consumer let go of it before the end.
    Stopped,
}

impl LaneState {
    fn is_terminal(&self) -> bool {
        !matches!(
            self,
            LaneState::Idle | LaneState::PendingFailure | LaneState::Open
        )
    }
}

/// Why a lane's head never came.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Headless {
    /// Ended without one: nothing was forwarded, or nothing answered.
    Ended,
    /// Cut without one.
    Cut(String),
}

impl std::fmt::Display for Headless {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Headless::Ended => f.write_str("no response"),
            Headless::Cut(why) => f.write_str(why),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dir {
    Req,
    Res,
}

/// One lane of one hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LaneId {
    pub(crate) hop: usize,
    pub(crate) dir: Dir,
}

impl LaneId {
    /// The stage that puts frames on the lane.
    fn producer(self) -> usize {
        match self.dir {
            Dir::Req => self.hop,
            Dir::Res => self.hop + 1,
        }
    }

    /// The stage that reads them.
    fn consumer(self) -> usize {
        match self.dir {
            Dir::Req => self.hop + 1,
            Dir::Res => self.hop,
        }
    }
}

/// What the chain tells the flow's record.
pub(crate) trait Recorder: Send + Sync + 'static {
    /// Layer `layer` (its index in `addons:`) failed with `err`.
    fn fault(&self, layer: usize, err: StackError);
    /// Build the HTTP response for the first recorded failure. `None`
    /// means the exchange must close without a response.
    fn failure_response(&self, layer: usize) -> BoxFuture<Option<(http::response::Parts, Body)>>;
    /// An enforcing layer cut a lane it produces.
    fn aborted(&self);
    /// The client went: noted before anything is cut for it.
    fn client_gone(&self);
}

struct LaneSlot {
    state: LaneState,
    /// The consumer has read or dropped the body. A producer's end can
    /// arrive while data is still queued for that consumer.
    consumed: bool,
    /// A head is on the lane.
    head: bool,
}

struct Lane {
    slot: Mutex<LaneSlot>,
    /// Cancelled when the lane becomes terminal.
    terminal: CancellationToken,
    /// Hands the head to the consumer. The chain holds it rather than the
    /// producer, so a failed producer's refusal goes through it too.
    head_tx: Mutex<Option<oneshot::Sender<(Head, Body)>>>,
}

struct Hop {
    req: Lane,
    res: Lane,
}

struct StageState {
    /// Cancelled when the stage is torn down; its driver stops on it.
    torn: CancellationToken,
    torn_why: OnceLock<&'static str>,
    /// The layer runs on this exchange in enforce mode: what it puts on
    /// its lanes is its own, so a headless answer is its `no_response`
    /// fault and a cut its abort. A skipped layer or an observer passes
    /// the lanes through as it found them.
    enforcing: AtomicBool,
    failed: AtomicBool,
    /// For a layer: it has taken the head of the response lane it
    /// consumes, the upstream's answer to its forward.
    took_answer: AtomicBool,
    /// For a layer: whether its answer was its own (it had not taken the
    /// upstream's when it answered). Set when it answers.
    answered: OnceLock<bool>,
}

/// The lanes of one exchange and the rules that move them.
pub(crate) struct Chain {
    hops: Box<[Hop]>,
    stages: Box<[StageState]>,
    recorder: Box<dyn Recorder>,
    over: CancellationToken,
    pub(super) tasks: TaskTracker,
    /// The client edge gave the exchange up: everything upstream of it is
    /// torn down, for `why`.
    torn: CancellationToken,
    torn_why: OnceLock<&'static str>,
}

/// The client edge's ends: it produces `req[0]` and consumes `res[0]`.
pub(crate) struct EdgeIo {
    pub(crate) req_out: LaneTx,
    pub(crate) res_in: LaneRx,
}

/// A layer's ends.
pub(crate) struct LayerIo {
    pub(crate) req_in: LaneRx,
    pub(crate) res_in: LaneRx,
    pub(crate) req_out: LaneTx,
    pub(crate) res_out: LaneTx,
    pub(crate) stage: StageHandle,
}

/// The core's ends: it consumes `req[n]` and produces `res[n]`.
pub(crate) struct CoreIo {
    pub(crate) req_in: LaneRx,
    pub(crate) res_out: LaneTx,
    pub(crate) stage: StageHandle,
}

impl Chain {
    /// A chain for `layers` layers, with every end handed out once.
    pub(crate) fn new(
        layers: usize,
        recorder: impl Recorder,
    ) -> (Arc<Self>, EdgeIo, Vec<LayerIo>, CoreIo) {
        let lane = || Lane {
            slot: Mutex::new(LaneSlot {
                state: LaneState::Idle,
                consumed: true,
                head: false,
            }),
            terminal: CancellationToken::new(),
            head_tx: Mutex::new(None),
        };
        let hops = (0..=layers)
            .map(|_| Hop {
                req: lane(),
                res: lane(),
            })
            .collect();
        let stages = (0..layers + 2)
            .map(|_| StageState {
                torn: CancellationToken::new(),
                torn_why: OnceLock::new(),
                enforcing: AtomicBool::new(false),
                failed: AtomicBool::new(false),
                took_answer: AtomicBool::new(false),
                answered: OnceLock::new(),
            })
            .collect();
        let tasks = TaskTracker::new();
        tasks.close();
        let chain = Arc::new(Self {
            hops,
            stages,
            recorder: Box::new(recorder),
            over: CancellationToken::new(),
            tasks,
            torn: CancellationToken::new(),
            torn_why: OnceLock::new(),
        });
        let ends = |dir| -> (Vec<Option<LaneTx>>, Vec<Option<LaneRx>>) {
            (0..=layers)
                .map(|hop| {
                    let lane = LaneId { hop, dir };
                    let (tx, rx) = oneshot::channel();
                    *lock(&chain.lane(lane).head_tx) = Some(tx);
                    let tx = LaneTx {
                        chain: chain.clone(),
                        lane,
                        used: false,
                    };
                    let rx = LaneRx {
                        chain: chain.clone(),
                        lane,
                        rx,
                        spent: false,
                    };
                    (Some(tx), Some(rx))
                })
                .unzip()
        };
        let (mut req_tx, mut req_rx) = ends(Dir::Req);
        let (mut res_tx, mut res_rx) = ends(Dir::Res);
        let handle = |stage| StageHandle {
            chain: chain.clone(),
            stage,
        };
        let edge = EdgeIo {
            req_out: req_tx[0].take().expect("handed out once"),
            res_in: res_rx[0].take().expect("handed out once"),
        };
        let layer_ios = (0..layers)
            .map(|i| LayerIo {
                req_in: req_rx[i].take().expect("handed out once"),
                res_in: res_rx[i + 1].take().expect("handed out once"),
                req_out: req_tx[i + 1].take().expect("handed out once"),
                res_out: res_tx[i].take().expect("handed out once"),
                stage: handle(i + 1),
            })
            .collect();
        let core = CoreIo {
            req_in: req_rx[layers].take().expect("handed out once"),
            res_out: res_tx[layers].take().expect("handed out once"),
            stage: handle(layers + 1),
        };
        (chain, edge, layer_ios, core)
    }

    fn lane(&self, id: LaneId) -> &Lane {
        let hop = &self.hops[id.hop];
        match id.dir {
            Dir::Req => &hop.req,
            Dir::Res => &hop.res,
        }
    }

    fn is_layer(&self, stage: usize) -> bool {
        stage >= 1 && stage + 1 < self.stages.len()
    }

    /// Whether `stage`'s lane events are a layer's own.
    fn enforcing(&self, stage: usize) -> bool {
        self.is_layer(stage) && self.stages[stage].enforcing.load(Ordering::Acquire)
    }

    pub(crate) fn state(&self, id: LaneId) -> LaneState {
        lock(&self.lane(id).slot).state.clone()
    }

    /// A head is on `id`.
    pub(crate) fn has_head(&self, id: LaneId) -> bool {
        lock(&self.lane(id).slot).head
    }

    /// Cancelled when the client edge tears the exchange down.
    #[cfg(test)]
    pub(crate) fn torn_down(&self) -> CancellationToken {
        self.torn.clone()
    }

    /// Layer `layer` is torn down, or being torn down.
    pub(crate) fn layer_torn(&self, layer: usize) -> bool {
        self.stages[layer + 1].torn_why.get().is_some()
    }

    /// Cancelled when layer `layer` is torn down.
    pub(crate) fn layer_torn_down(&self, layer: usize) -> CancellationToken {
        self.stages[layer + 1].torn.clone()
    }

    /// Why layer `layer` was torn down, once it has been.
    pub(crate) fn layer_torn_down_why(&self, layer: usize) -> &'static str {
        self.stages[layer + 1]
            .torn_why
            .get()
            .copied()
            .unwrap_or(ENDED)
    }

    /// Layer `layer` faults with `err`.
    pub(crate) fn fail_layer(self: &Arc<Self>, layer: usize, err: StackError) {
        self.fail(layer + 1, err);
    }

    /// Every lane has been consumed or abandoned, and all drivers have exited.
    #[cfg(test)]
    pub(crate) fn is_over(&self) -> bool {
        self.over.is_cancelled() && self.tasks.is_empty()
    }

    pub(crate) async fn until_over(&self) {
        self.over.cancelled().await;
        self.tasks.wait().await;
    }

    /// Track work that can still change the exchange or its record. The
    /// initial drivers are registered before publishing the first head;
    /// any child work is registered before its parent finishes.
    pub(crate) fn spawn<F>(&self, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.tasks.spawn(future)
    }

    /// The consumer of `id` has its head. For a layer's response lane, an
    /// answer it gives from now on is the upstream's, passed on.
    fn took_head(&self, id: LaneId) {
        let consumer = id.consumer();
        if id.dir == Dir::Res && self.is_layer(consumer) {
            self.stages[consumer]
                .took_answer
                .store(true, Ordering::Release);
        }
    }

    /// The layer whose own answer reached the client, if a layer's did.
    pub(crate) fn answered_by(&self) -> Option<usize> {
        (1..self.stages.len() - 1)
            .find(|&s| self.stages[s].answered.get() == Some(&true))
            .map(|s| s - 1)
    }

    /// Moves `id` to the terminal state `to` unless it is terminal already.
    fn settle(&self, id: LaneId, to: LaneState) -> bool {
        self.settle_recorded(id, to, false)
    }

    /// As [`Chain::settle`]; `abort` notes the producer's abort if the
    /// lane moves.
    fn settle_recorded(&self, id: LaneId, to: LaneState, abort: bool) -> bool {
        let lane = self.lane(id);
        {
            let mut slot = lock(&lane.slot);
            if slot.state.is_terminal() {
                return false;
            }
            if abort {
                self.recorder.aborted();
            }
            slot.state = to;
        }
        lane.terminal.cancel();
        self.check_over();
        true
    }

    fn check_over(&self) {
        let finished = |lane: &Lane| {
            let slot = lock(&lane.slot);
            slot.state.is_terminal() && slot.consumed
        };
        if self
            .hops
            .iter()
            .all(|h| finished(&h.req) && finished(&h.res))
        {
            self.over.cancel();
        }
    }

    fn consumed(&self, id: LaneId) {
        lock(&self.lane(id).slot).consumed = true;
        self.check_over();
    }

    /// A head is on `id`; `body` is what follows it, handed to the
    /// consumer. Discarded on a terminal lane.
    fn head(self: &Arc<Self>, id: LaneId, head: Head, mut body: Body, publication: Publication) {
        let producer = id.producer();
        let complete = body.is_end_stream();
        if complete {
            drop(std::mem::take(&mut body));
        }
        let tx = {
            let mut slot = lock(&self.lane(id).slot);
            if slot.state.is_terminal()
                || (publication != Publication::Failure
                    && ((slot.state == LaneState::PendingFailure)
                        || self.stages[producer].failed.load(Ordering::Acquire)
                        || self.stages[producer].torn_why.get().is_some()))
            {
                return;
            }
            slot.state = LaneState::Open;
            slot.head = true;
            slot.consumed = complete;
            if id.dir == Dir::Res && self.is_layer(producer) {
                let st = &self.stages[producer];
                let _ = st.answered.set(!st.took_answer.load(Ordering::Acquire));
            }
            lock(&self.lane(id).head_tx)
                .take()
                .expect("a lane takes one head")
        };
        let body = if complete {
            body
        } else {
            // Even the last declared byte can precede a cut. Only a clean
            // lane end commits this body on the wire.
            Body::wrap_native(Reading::new(self, id, body), u64::MAX, None)
        };
        // The consumer may have let go already: the body then drops here,
        // which is a stop on a lane that is stopped.
        let _ = tx.send((head, body));
        if complete {
            self.end(id);
        }
    }

    fn end(&self, id: LaneId) {
        self.settle(id, LaneState::Ended);
    }

    /// `id`'s producer lets go of it without a head.
    fn end_headless(self: &Arc<Self>, id: LaneId) {
        let producer = id.producer();
        {
            let slot = lock(&self.lane(id).slot);
            if slot.state != LaneState::Idle {
                return;
            }
        }
        if id.dir == Dir::Res && self.enforcing(producer) {
            self.fail(producer, LayerError::NoResponse.into());
        } else {
            self.end(id);
        }
    }

    /// `id` is cut: by its producer (`abort`), or by a teardown.
    fn cut(&self, id: LaneId, why: String, abort: bool) {
        if abort && self.producer_closed(id) {
            return;
        }
        let abort = abort && self.enforcing(id.producer());
        self.settle_recorded(id, LaneState::Cut(why), abort);
    }

    /// `id`'s consumer read an error from its body: the lane is cut
    /// whoever the producer is, and it is the producer's abort only while
    /// the producer still holds the lane (`abort`: the error is not the
    /// fail-closed cut of a producer that failed).
    fn read_cut(&self, id: LaneId, why: String, abort: bool) {
        let abort = abort && !self.producer_closed(id) && self.enforcing(id.producer());
        self.settle_recorded(id, LaneState::Cut(why), abort);
    }

    /// `id`'s consumer lets go of it before the end.
    fn stop(&self, id: LaneId, why: &'static str) {
        if !self.settle(id, LaneState::Stopped) {
            return;
        }
        if id.dir == Dir::Res {
            self.tear_down_stage(id.producer(), why);
        }
    }

    /// Layer stage `stage` faults with `err`.
    fn fail(self: &Arc<Self>, stage: usize, err: StackError) {
        debug_assert!(self.is_layer(stage));
        let res_out = LaneId {
            hop: stage - 1,
            dir: Dir::Res,
        };
        let reserved = {
            let mut slot = lock(&self.lane(res_out).slot);
            if self.stages[stage].failed.swap(true, Ordering::AcqRel) {
                return;
            }
            let idle = slot.state == LaneState::Idle;
            if idle {
                slot.state = LaneState::PendingFailure;
            }
            idle
        };
        // The refusal is built from the recorded fault, so it starts after.
        self.recorder.fault(stage - 1, err);
        if reserved {
            self.refuse(res_out);
        }
        self.tear_down_stage(stage, FAILED);
    }

    /// Builds the refusal for the failed layer that left `id` without a
    /// head, and puts it on `id`. Building it waits for the stages upstream
    /// to return, so it runs as its own task; a consumer that lets go of
    /// the lane first abandons it.
    fn refuse(self: &Arc<Self>, id: LaneId) {
        let chain = self.clone();
        let generated = self.recorder.failure_response(id.hop);
        self.spawn(async move {
            let terminal = chain.lane(id).terminal.clone();
            let generated = tokio::select! {
                biased;
                () = terminal.cancelled() => return,
                generated = generated => generated,
            };
            match generated {
                Some((parts, body)) => {
                    chain.head(id, Head::Response(parts), body, Publication::Failure);
                }
                None => chain.cut(id, FAILED.to_owned(), false),
            }
        });
    }

    fn producer_closed(&self, id: LaneId) -> bool {
        let slot = lock(&self.lane(id).slot);
        slot.state.is_terminal()
            || (slot.state == LaneState::PendingFailure)
            || self.stages[id.producer()].failed.load(Ordering::Acquire)
            || self.stages[id.producer()].torn_why.get().is_some()
    }

    fn tear_down_stage(&self, stage: usize, why: &'static str) {
        // Cancellation belongs to stages, independently of whether their
        // response lanes have already ended. Ordinary consumer release
        // still only cancels a producer whose response was unfinished.
        for stage in stage..self.stages.len() {
            self.cancel_stage(stage, why);
        }
    }

    fn cancel_stage(&self, stage: usize, why: &'static str) {
        let st = &self.stages[stage];
        if st.torn_why.set(why).is_err() {
            return;
        }
        let last = self.stages.len() - 1;
        if stage < last {
            self.cut_unless_pending_failure(
                LaneId {
                    hop: stage,
                    dir: Dir::Req,
                },
                why,
            );
        }
        if stage > 0 {
            self.cut_unless_pending_failure(
                LaneId {
                    hop: stage - 1,
                    dir: Dir::Res,
                },
                why,
            );
            self.stop(
                LaneId {
                    hop: stage - 1,
                    dir: Dir::Req,
                },
                why,
            );
        }
        if stage < last {
            self.settle(
                LaneId {
                    hop: stage,
                    dir: Dir::Res,
                },
                LaneState::Stopped,
            );
        }
        st.torn.cancel();
    }

    fn cut_unless_pending_failure(&self, id: LaneId, why: &'static str) {
        let lane = self.lane(id);
        {
            let mut slot = lock(&lane.slot);
            if slot.state.is_terminal() || slot.state == LaneState::PendingFailure {
                return;
            }
            slot.state = LaneState::Cut(why.to_owned());
        }
        lane.terminal.cancel();
        self.check_over();
    }

    /// Cancel every stage when the client disappears or its response is
    /// refused. Completed lanes retain their outcomes; unfinished lanes
    /// are cut or stopped. Driver cancellation does not depend on either.
    pub(crate) fn tear_down(&self, why: &'static str) {
        if why == super::CLIENT_GONE {
            self.recorder.client_gone();
        }
        let _ = self.torn_why.set(why);
        self.torn.cancel();
        self.settle(
            LaneId {
                hop: 0,
                dir: Dir::Res,
            },
            LaneState::Stopped,
        );
        self.cut(
            LaneId {
                hop: 0,
                dir: Dir::Req,
            },
            why.to_owned(),
            false,
        );
        self.tear_down_stage(1, why);
    }

    /// The default reason when `stage` lets go of a lane it holds.
    fn gave_up(&self, stage: usize) -> &'static str {
        if self.is_layer(stage) { GAVE_UP } else { ENDED }
    }

    /// What a consumer waiting for a head on `id` gets once the lane is
    /// terminal without one.
    fn headless(&self, id: LaneId) -> Headless {
        match self.state(id) {
            LaneState::Ended => Headless::Ended,
            LaneState::Cut(why) => Headless::Cut(why),
            // Released from under its consumer by a teardown.
            LaneState::Stopped => Headless::Cut(
                self.stages[id.consumer()]
                    .torn_why
                    .get()
                    .copied()
                    .unwrap_or(ENDED)
                    .to_owned(),
            ),
            LaneState::Idle | LaneState::PendingFailure | LaneState::Open => {
                unreachable!("terminal")
            }
        }
    }
}

/// A stage's handle on its own place in the chain.
pub(crate) struct StageHandle {
    chain: Arc<Chain>,
    stage: usize,
}

impl StageHandle {
    /// Cancel this stage and all stages upstream of it.
    pub(crate) fn cancel(&self, why: &'static str) {
        self.chain.tear_down_stage(self.stage, why);
    }

    /// The layer faults: recorded, torn down, its answer generated if none
    /// is on its lane. A layer's only: the edges cut their own lanes.
    pub(crate) fn fail(&self, err: impl Into<StackError>) {
        self.chain.fail(self.stage, err.into());
    }

    /// The layer runs in enforce mode: its lane events are its own.
    pub(crate) fn enforcing(&self) {
        self.chain.stages[self.stage]
            .enforcing
            .store(true, Ordering::Release);
    }

    /// Cancelled when the stage is torn down.
    pub(crate) fn torn_down(&self) -> CancellationToken {
        self.chain.stages[self.stage].torn.clone()
    }

    #[cfg(test)]
    pub(crate) fn torn_down_why(&self) -> Option<&'static str> {
        self.chain.stages[self.stage].torn_why.get().copied()
    }

    /// Whether the layer's answer was its own; `None` until it answers.
    #[cfg(test)]
    pub(crate) fn answered(&self) -> Option<bool> {
        self.chain.stages[self.stage].answered.get().copied()
    }
}

/// A lane's producing end. Used once: a head with its body, or a headless
/// end or cut. Let go of unused, it ends the lane headless.
pub(crate) struct LaneTx {
    chain: Arc<Chain>,
    lane: LaneId,
    used: bool,
}

impl LaneTx {
    /// Puts `head` on the lane; the body follows through the writer
    /// returned, `known_length` bytes of it when declared and at most
    /// `cap`.
    pub(crate) fn head(mut self, head: Head, known_length: Option<u64>, cap: u64) -> LaneBody {
        self.used = true;
        let (sender, body) = Body::channel_with_depth(LANE_DEPTH, cap, known_length);
        self.chain
            .head(self.lane, head, body, Publication::Forwarded);
        LaneBody {
            chain: self.chain.clone(),
            lane: self.lane,
            sender: Some(sender),
        }
    }

    /// Puts `head` on the lane with a body made elsewhere (an upstream's,
    /// a refusal's, a guest's stream): the lane ends or cuts as its
    /// consumer reads the body to its end. An error read from it is this
    /// producer's abort unless an earlier fault or client loss explains it;
    /// [`BodyError::Stopped`] is how a failed producer's body is cut for
    /// it, never an abort.
    pub(crate) fn whole(mut self, head: Head, body: Body) {
        self.used = true;
        self.chain
            .head(self.lane, head, body, Publication::Forwarded);
    }

    /// Nothing goes on the lane.
    pub(crate) fn end_headless(mut self) {
        self.used = true;
        self.chain.end_headless(self.lane);
    }

    /// Nothing goes on the lane, and that is not the lane's complete
    /// story.
    pub(crate) fn cut_headless(mut self, why: impl Into<String>) {
        self.used = true;
        if self.lane.dir == Dir::Res && self.chain.enforcing(self.lane.producer()) {
            self.chain.end_headless(self.lane);
        } else {
            self.chain.cut(self.lane, why.into(), true);
        }
    }
}

impl Drop for LaneTx {
    fn drop(&mut self) {
        if !self.used {
            self.chain.end_headless(self.lane);
        }
    }
}

/// The body of a lane, written by its producer. Dropped unfinished, it
/// cuts the lane.
pub(crate) struct LaneBody {
    chain: Arc<Chain>,
    lane: LaneId,
    sender: Option<BodySender>,
}

impl LaneBody {
    fn sender(&mut self) -> Result<&mut BodySender, BodyError> {
        if self.chain.producer_closed(self.lane) {
            return Err(BodyError::Closed);
        }
        self.sender.as_mut().ok_or(BodyError::Closed)
    }

    /// Resolves when the consumer has stopped or the lane is terminal.
    pub(crate) async fn closed(&self) {
        let terminal = self.chain.lane(self.lane).terminal.clone();
        if let Some(sender) = &self.sender {
            tokio::select! {
                () = sender.closed() => {}
                () = terminal.cancelled() => {}
            }
        }
    }

    /// Waits until a frame can be pushed. Cancel-safe.
    pub(crate) async fn ready(&mut self) -> Result<(), BodyError> {
        let terminal = self.chain.lane(self.lane).terminal.clone();
        let sender = self.sender()?;
        tokio::select! {
            r = sender.ready() => r,
            () = terminal.cancelled() => Err(BodyError::Closed),
        }
    }

    /// Pushes a data frame without waiting; call [`LaneBody::ready`] first.
    pub(crate) fn try_push(&mut self, data: Bytes) -> Result<(), BodyError> {
        self.sender()?.try_push(data)
    }

    pub(crate) async fn send_data(&mut self, data: Bytes) -> Result<(), BodyError> {
        self.ready().await?;
        self.try_push(data)
    }

    pub(crate) async fn send_trailers(&mut self, trailers: HeaderMap) -> Result<(), BodyError> {
        self.ready().await?;
        self.sender()?.try_push_trailers(trailers)
    }

    /// Ends the lane. A body short of its declared length cuts it instead.
    pub(crate) async fn finish(mut self) -> Result<(), BodyError> {
        self.sender()?;
        let sender = self.sender.take().ok_or(BodyError::Closed)?;
        let terminal = self.chain.lane(self.lane).terminal.clone();
        let result = tokio::select! {
            biased;
            () = terminal.cancelled() => Err(BodyError::Closed),
            result = sender.finish() => result,
        };
        match result {
            Ok(()) => {
                self.chain.end(self.lane);
                Ok(())
            }
            Err(BodyError::Closed) => Err(BodyError::Closed),
            Err(e) => {
                self.chain.cut(self.lane, e.to_string(), false);
                Err(e)
            }
        }
    }

    /// Cuts the lane: what the consumer has is not the whole body.
    pub(crate) fn abort(mut self, why: impl Into<String>) {
        if let Some(sender) = self.sender.take() {
            sender.abort(BodyError::Incomplete);
        }
        self.chain.cut(self.lane, why.into(), true);
    }
}

impl Drop for LaneBody {
    fn drop(&mut self) {
        if self.sender.take().is_some() {
            self.chain
                .cut(self.lane, "body dropped unfinished".to_owned(), true);
        }
    }
}

/// A lane's consuming end. Let go of before the head, it stops the lane;
/// after it, the body carries the lane.
pub(crate) struct LaneRx {
    chain: Arc<Chain>,
    lane: LaneId,
    rx: oneshot::Receiver<(Head, Body)>,
    /// The head was taken (or the lane released): nothing is held here.
    spent: bool,
}

impl LaneRx {
    pub(crate) fn id(&self) -> LaneId {
        self.lane
    }

    /// Waits for the head. Cancel-safe.
    pub(crate) async fn head(&mut self) -> Result<(Head, Body), Headless> {
        let terminal = self.chain.lane(self.lane).terminal.clone();
        let arrived = tokio::select! {
            biased;
            r = &mut self.rx => r.ok(),
            () = terminal.cancelled() => self.rx.try_recv().ok(),
        };
        if let Some(arrived) = arrived {
            self.spent = true;
            self.chain.took_head(self.lane);
            return Ok(arrived);
        }
        terminal.cancelled().await;
        self.spent = true;
        Err(self.chain.headless(self.lane))
    }

    /// The head, if it is on the lane now. A headless end is seen too; a
    /// refusal roxy has yet to put on the lane is not.
    #[cfg(test)]
    pub(crate) fn try_head(&mut self) -> Option<Result<(Head, Body), Headless>> {
        if let Ok(arrived) = self.rx.try_recv() {
            self.spent = true;
            self.chain.took_head(self.lane);
            return Some(Ok(arrived));
        }
        if !self.chain.lane(self.lane).terminal.is_cancelled() {
            return None;
        }
        self.spent = true;
        Some(Err(self.chain.headless(self.lane)))
    }

    /// Stops the lane, giving `why` to whatever is torn down for it.
    #[cfg(test)]
    pub(crate) fn release(mut self, why: &'static str) {
        if !self.spent {
            self.spent = true;
            self.chain.stop(self.lane, why);
        }
    }
}

impl Drop for LaneRx {
    fn drop(&mut self) {
        if !self.spent {
            let why = self.chain.gave_up(self.lane.consumer());
            self.chain.stop(self.lane, why);
        }
    }
}

/// A lane's body as its consumer reads it: the end it reads ends the lane,
/// an error cuts it, letting go of it early stops it, and a lane cut or
/// released from outside while the producer is quiet ends the read.
struct Reading {
    inner: Body,
    chain: Arc<Chain>,
    lane: LaneId,
    done: AtomicBool,
    /// HTTP trailers commit successful completion. Keep them private
    /// until the producer's clean end and length checks have arrived.
    trailers: Option<HeaderMap>,
    /// One future for the lane's end, so its waker stays registered across
    /// polls that found the inner body pending.
    terminal: Pin<Box<WaitForCancellationFutureOwned>>,
}

impl Reading {
    fn new(chain: &Arc<Chain>, lane: LaneId, inner: Body) -> Self {
        Self {
            inner,
            chain: chain.clone(),
            lane,
            done: AtomicBool::new(false),
            trailers: None,
            terminal: Box::pin(chain.lane(lane).terminal.clone().cancelled_owned()),
        }
    }

    fn ended(&self) {
        if !self.done.swap(true, Ordering::AcqRel) {
            self.chain.end(self.lane);
        }
    }

    fn consumed(&mut self) {
        // Body adapters can publish accounting on drop. Dispose of them
        // before allowing the exchange's final record to be collected.
        drop(std::mem::take(&mut self.inner));
        self.chain.consumed(self.lane);
    }

    /// The body's error reached the reader: the lane is cut, by its
    /// producer unless this is the fail-closed cut of a producer that
    /// failed.
    fn cut(&mut self, e: &BodyError) {
        if !self.done.swap(true, Ordering::AcqRel) {
            let abort = *e != BodyError::Stopped;
            self.chain.read_cut(self.lane, e.to_string(), abort);
            self.consumed();
        }
    }
}

impl HttpBody for Reading {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = &mut *self;
        if this.done.load(Ordering::Acquire) {
            this.consumed();
            return Poll::Ready(None);
        }
        loop {
            match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    if this.trailers.is_some() {
                        this.cut(&BodyError::Incomplete);
                        return Poll::Ready(Some(Err(BodyError::Incomplete)));
                    }
                    match frame.into_trailers() {
                        Ok(trailers) => this.trailers = Some(trailers),
                        Err(frame) => return Poll::Ready(Some(Ok(frame))),
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    this.cut(&e);
                    return Poll::Ready(Some(Err(e)));
                }
                Poll::Ready(None) => {
                    this.ended();
                    this.consumed();
                    if !matches!(this.chain.state(this.lane), LaneState::Ended) {
                        return Poll::Ready(Some(Err(BodyError::Incomplete)));
                    }
                    return Poll::Ready(this.trailers.take().map(|t| Ok(Frame::trailers(t))));
                }
                Poll::Pending => {
                    if this.terminal.as_mut().poll(cx).is_ready()
                        && matches!(
                            this.chain.state(this.lane),
                            LaneState::Cut(_) | LaneState::Stopped
                        )
                    {
                        this.done.store(true, Ordering::Release);
                        this.consumed();
                        return Poll::Ready(Some(Err(BodyError::Incomplete)));
                    }
                    return Poll::Pending;
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        // The producer ending does not mean its buffered frames were checked.
        // Poll through EOF before allowing a codec to skip this reader.
        self.done.load(Ordering::Acquire) && self.trailers.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for Reading {
    fn drop(&mut self) {
        if !self.done.swap(true, Ordering::AcqRel) {
            let why = self
                .chain
                .torn_why
                .get()
                .copied()
                .unwrap_or_else(|| self.chain.gave_up(self.lane.consumer()));
            self.chain.stop(self.lane, why);
        }
        self.consumed();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    use http_body_util::BodyExt;

    use super::super::CLIENT_GONE;
    use super::*;

    #[derive(Default)]
    struct Record {
        faults: Mutex<Vec<(usize, String)>>,
        /// Aborts reported.
        aborts: Mutex<usize>,
        /// The generated failure response, if one can be sent.
        response: Option<(u16, &'static str)>,
        /// Its body fails as it is read.
        broken: bool,
        release: Option<CancellationToken>,
    }

    impl Recorder for Arc<Record> {
        fn fault(&self, layer: usize, err: StackError) {
            lock(&self.faults).push((layer, err.to_string()));
        }

        fn failure_response(
            &self,
            _layer: usize,
        ) -> BoxFuture<Option<(http::response::Parts, Body)>> {
            let configured = self.response;
            let broken = self.broken;
            let release = self.release.clone();
            Box::pin(async move {
                if let Some(release) = release {
                    release.cancelled().await;
                }
                let (status, body) = configured?;
                if broken {
                    let (sender, body) = Body::channel(u64::MAX, None);
                    sender.abort(BodyError::Incomplete);
                    return Some((response(status), body));
                }
                Some((response(status), Body::from_bytes(body)))
            })
        }

        fn aborted(&self) {
            *lock(&self.aborts) += 1;
        }

        fn client_gone(&self) {}
    }

    fn chain(layers: usize) -> (Arc<Chain>, EdgeIo, Vec<LayerIo>, CoreIo, Arc<Record>) {
        let record = Arc::new(Record {
            response: Some((503, "failure")),
            ..Record::default()
        });
        let (c, e, l, k) = Chain::new(layers, record.clone());
        for io in &l {
            io.stage.enforcing();
        }
        (c, e, l, k, record)
    }

    fn request() -> Head {
        Head::Request(
            http::Request::get("http://up.test/")
                .body(())
                .unwrap()
                .into_parts()
                .0,
        )
    }

    fn response(status: u16) -> http::response::Parts {
        http::Response::builder()
            .status(status)
            .body(())
            .unwrap()
            .into_parts()
            .0
    }

    fn req(hop: usize) -> LaneId {
        LaneId { hop, dir: Dir::Req }
    }

    fn res(hop: usize) -> LaneId {
        LaneId { hop, dir: Dir::Res }
    }

    async fn settles<T>(f: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(5), f)
            .await
            .expect("settles")
    }

    #[tokio::test]
    async fn a_terminal_lane_never_moves() {
        let (c, mut edge, _layers, core, _) = chain(0);
        // Stopped before the head: the head is discarded, the end after it
        // changes nothing.
        drop(core.req_in);
        assert_eq!(c.state(req(0)), LaneState::Stopped);
        let body = edge.req_out.head(request(), None, u64::MAX);
        assert_eq!(c.state(req(0)), LaneState::Stopped);
        assert_eq!(body.finish().await, Err(BodyError::Closed));
        assert_eq!(c.state(req(0)), LaneState::Stopped);
        // Disposal stops the lane, just as it does for every consumer.
        core.res_out
            .whole(Head::Response(response(200)), Body::from_bytes("x"));
        let (_, b) = edge.res_in.head().await.unwrap();
        drop(b);
        assert_eq!(c.state(res(0)), LaneState::Stopped);
    }

    #[tokio::test]
    async fn teardown_after_completed_response_cancels_all_stages() {
        let (c, _edge, mut layers, core, _) = chain(1);
        let layer = layers.pop().unwrap();
        layer
            .res_out
            .whole(Head::Response(response(204)), Body::empty());
        assert_eq!(c.state(res(0)), LaneState::Ended);
        c.tear_down(CLIENT_GONE);
        assert!(
            layer.stage.torn_down().is_cancelled(),
            "the layer survives client teardown"
        );
        assert!(
            core.stage.torn_down().is_cancelled(),
            "the connector survives client teardown"
        );
        assert!(c.is_over(), "reclamation remains blocked");
    }

    #[tokio::test]
    async fn teardown_crosses_completed_intermediate_response() {
        let (c, _edge, mut layers, core, _) = chain(2);
        let upstream = layers.pop().unwrap();
        let downstream = layers.pop().unwrap();
        upstream
            .res_out
            .whole(Head::Response(response(204)), Body::empty());
        c.tear_down(CLIENT_GONE);
        assert!(downstream.stage.torn_down().is_cancelled());
        assert!(
            upstream.stage.torn_down().is_cancelled(),
            "a completed intermediate lane blocks teardown"
        );
        assert!(core.stage.torn_down().is_cancelled());
    }

    #[tokio::test]
    async fn finishing_full_lane_wakes_on_teardown() {
        let (c, edge, _layers, mut core, _) = chain(0);
        let mut writer = edge.req_out.head(request(), None, u64::MAX);
        let (_, _reader) = core.req_in.head().await.unwrap();
        writer.send_data(Bytes::from_static(b"a")).await.unwrap();
        writer.send_data(Bytes::from_static(b"b")).await.unwrap();
        let finish = writer.finish();
        tokio::pin!(finish);
        assert!(futures_util::poll!(finish.as_mut()).is_pending());
        c.tear_down(CLIENT_GONE);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), finish)
                .await
                .is_ok(),
            "finish still waits for buffer space on a terminal lane"
        );
    }

    #[tokio::test]
    async fn an_ended_lane_let_go_of_unread_is_not_stopped() {
        let (c, mut edge, _layers, core, _) = chain(0);
        let mut body = core
            .res_out
            .head(Head::Response(response(200)), None, u64::MAX);
        body.send_data(Bytes::from_static(b"x")).await.unwrap();
        body.finish().await.unwrap();
        assert_eq!(c.state(res(0)), LaneState::Ended);
        let (_, b) = edge.res_in.head().await.unwrap();
        drop(b);
        assert_eq!(c.state(res(0)), LaneState::Ended);
        assert!(!c.is_over());
        edge.req_out.end_headless();
        assert!(c.is_over());
    }

    #[tokio::test]
    async fn the_producer_learns_of_a_stop_at_its_next_frame() {
        let (c, edge, _layers, mut core, _) = chain(0);
        let mut body = edge.req_out.head(request(), None, u64::MAX);
        let (_, reader) = core.req_in.head().await.unwrap();
        body.send_data(Bytes::from_static(b"a")).await.unwrap();
        drop(reader);
        assert_eq!(c.state(req(0)), LaneState::Stopped);
        settles(body.closed()).await;
        assert_eq!(
            body.send_data(Bytes::from_static(b"b")).await,
            Err(BodyError::Closed)
        );
        // A stopped request lane tells its producer and nothing else.
        assert!(!core.stage.torn_down().is_cancelled());
        assert_eq!(c.state(res(0)), LaneState::Idle);
    }

    #[tokio::test]
    async fn a_stopped_response_lane_tears_its_producer_down_hop_by_hop() {
        let (c, edge, mut layers, mut core, record) = chain(2);
        let mut l2 = layers.pop().unwrap();
        let mut l1 = layers.pop().unwrap();
        let upload = edge.req_out.head(request(), None, u64::MAX);
        let (_, b0) = l1.req_in.head().await.unwrap();
        l1.req_out.whole(request(), b0);
        let (_, b1) = l2.req_in.head().await.unwrap();
        l2.req_out.whole(request(), b1);
        let (_, b2) = core.req_in.head().await.unwrap();
        let mut answer = core
            .res_out
            .head(Head::Response(response(200)), None, u64::MAX);
        answer.send_data(Bytes::from_static(b"a")).await.unwrap();

        edge.res_in.release(CLIENT_GONE);

        for (io, name) in [(&l1.stage, "L1"), (&l2.stage, "L2"), (&core.stage, "core")] {
            assert!(io.torn_down().is_cancelled(), "{name} torn down");
            assert_eq!(io.torn_down_why(), Some(CLIENT_GONE), "{name}");
        }
        assert_eq!(c.state(res(0)), LaneState::Stopped);
        assert_eq!(c.state(req(1)), LaneState::Cut(CLIENT_GONE.to_owned()));
        assert_eq!(c.state(res(1)), LaneState::Stopped);
        assert_eq!(c.state(req(2)), LaneState::Cut(CLIENT_GONE.to_owned()));
        assert_eq!(c.state(res(2)), LaneState::Stopped);
        // The core's producer end learns its answer is not wanted.
        settles(answer.closed()).await;
        // A teardown's cuts are nobody's abort, and nobody's fault.
        assert_eq!(*lock(&record.aborts), 0);
        assert!(lock(&record.faults).is_empty());
        // L1 let go of the upload as it went: the edge's writer learns, and
        // nothing is left to move.
        assert_eq!(c.state(req(0)), LaneState::Stopped);
        settles(upload.closed()).await;
        assert!(!c.is_over(), "the consumer still holds the buffered upload");
        drop(b2);
        drop(l2.res_in);
        assert!(c.is_over());
    }

    #[tokio::test]
    async fn over_waits_for_the_last_lane() {
        let (c, mut edge, mut layers, mut core, _) = chain(1);
        let mut l1 = layers.pop().unwrap();
        let over = tokio::spawn({
            let c = c.clone();
            async move { c.until_over().await }
        });
        let f0 = edge.req_out.head(request(), None, u64::MAX);
        let (_, b0) = l1.req_in.head().await.unwrap();
        l1.req_out.whole(request(), b0);
        let (_, b1) = core.req_in.head().await.unwrap();
        f0.finish().await.unwrap();
        assert_eq!(b1.collect().await.unwrap().to_bytes(), "");
        assert_eq!(c.state(req(0)), LaneState::Ended);
        assert_eq!(c.state(req(1)), LaneState::Ended);
        core.res_out
            .whole(Head::Response(response(200)), Body::from_bytes("hi"));
        let (_, r1) = l1.res_in.head().await.unwrap();
        l1.res_out.whole(Head::Response(response(200)), r1);
        let (_, r0) = edge.res_in.head().await.unwrap();
        assert!(!c.is_over());
        assert!(!over.is_finished());
        assert_eq!(r0.collect().await.unwrap().to_bytes(), "hi");
        assert_eq!(c.state(res(1)), LaneState::Ended);
        assert_eq!(c.state(res(0)), LaneState::Ended);
        assert!(c.is_over());
        settles(over).await.unwrap();
    }

    #[tokio::test]
    async fn over_waits_for_drivers_after_both_lanes_end() {
        let (c, edge, _layers, core, _) = chain(0);
        let (release, released) = oneshot::channel();
        let recorded = Arc::new(AtomicBool::new(false));
        let output = recorded.clone();
        c.spawn(async move {
            released.await.unwrap();
            output.store(true, Ordering::Release);
        });
        edge.req_out.end_headless();
        core.res_out.end_headless();
        assert!(!c.is_over());
        let over = c.until_over();
        tokio::pin!(over);
        assert!(futures_util::poll!(over.as_mut()).is_pending());
        release.send(()).unwrap();
        settles(over).await;
        assert!(recorded.load(Ordering::Acquire));
        assert!(c.is_over());
    }

    #[tokio::test]
    async fn body_accounting_finishes_before_the_exchange_is_over() {
        struct Accounted {
            chain: Arc<Chain>,
            recorded: Arc<AtomicBool>,
            fail: bool,
        }

        impl HttpBody for Accounted {
            type Data = Bytes;
            type Error = BodyError;

            fn poll_frame(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
                Poll::Ready(self.fail.then_some(Err(BodyError::Incomplete)))
            }
        }

        impl Drop for Accounted {
            fn drop(&mut self) {
                assert!(!self.chain.is_over(), "accounting must precede reclamation");
                self.recorded.store(true, Ordering::Release);
            }
        }

        for (fail, abandon) in [(false, false), (true, false), (false, true)] {
            let (c, mut edge, _layers, core, _) = chain(0);
            edge.req_out.end_headless();
            let recorded = Arc::new(AtomicBool::new(false));
            let body = Body::wrap_native(
                Accounted {
                    chain: c.clone(),
                    recorded: recorded.clone(),
                    fail,
                },
                u64::MAX,
                None,
            );
            core.res_out.whole(Head::Response(response(200)), body);
            let (_, mut body) = edge.res_in.head().await.unwrap();
            if abandon {
                c.tear_down(CLIENT_GONE);
                drop(body);
            } else {
                let result = body.frame().await;
                assert_eq!(result.is_some(), fail);
            }
            assert!(c.is_over());
            assert!(recorded.load(Ordering::Acquire));
        }
    }

    #[tokio::test]
    async fn teardown_cuts_a_ready_body_before_it_can_commit_trailers() {
        let (c, mut edge, _layers, core, _) = chain(0);
        let (mut sender, body) = Body::channel(100, None);
        let mut trailers = HeaderMap::new();
        trailers.insert("x-check", http::HeaderValue::from_static("ok"));
        sender.send_trailers(trailers).await.unwrap();
        sender.finish().await.unwrap();
        core.res_out.whole(Head::Response(response(200)), body);
        let (_, body) = edge.res_in.head().await.unwrap();
        c.tear_down(CLIENT_GONE);
        assert!(body.collect().await.is_err());
        assert!(c.is_over());
    }

    #[tokio::test]
    async fn trailers_wait_for_a_clean_end_and_matching_length() {
        for declared in [None, Some(5), Some(6)] {
            let (_c, mut edge, _layers, core, _) = chain(0);
            let mut writer = core
                .res_out
                .head(Head::Response(response(200)), declared, u64::MAX);
            let (_, mut reader) = edge.res_in.head().await.unwrap();
            writer
                .send_data(Bytes::from_static(b"hello"))
                .await
                .unwrap();
            assert_eq!(
                reader.frame().await.unwrap().unwrap().into_data().unwrap(),
                "hello"
            );
            let mut trailers = HeaderMap::new();
            trailers.insert("x-check", http::HeaderValue::from_static("ok"));
            writer.send_trailers(trailers).await.unwrap();
            assert!(
                futures_util::poll!(reader.frame()).is_pending(),
                "trailers must not commit before the end"
            );
            assert!(
                !reader.is_end_stream(),
                "held trailers still require terminal validation"
            );
            let finished = writer.finish().await;
            let terminal = reader.frame().await.unwrap();
            if declared == Some(6) {
                assert!(finished.is_err());
                assert!(terminal.is_err());
            } else {
                finished.unwrap();
                assert_eq!(terminal.unwrap().into_trailers().unwrap()["x-check"], "ok");
                assert!(reader.frame().await.is_none());
            }
        }
    }

    #[tokio::test]
    async fn unpolled_lane_bodies_preserve_request_framing() {
        for (whole, declared, expected) in [
            (true, None, Some(0)),
            (false, None, None),
            (false, Some(0), None),
        ] {
            let (_chain, edge, _layers, mut core, _) = chain(0);
            if whole {
                edge.req_out.whole(request(), Body::empty());
            } else {
                edge.req_out
                    .head(request(), declared, u64::MAX)
                    .finish()
                    .await
                    .unwrap();
            }
            let (Head::Request(mut parts), body) = core.req_in.head().await.unwrap() else {
                panic!("request head");
            };
            parts.method = http::Method::POST;
            if declared == Some(0) {
                parts.headers.insert(
                    http::header::CONTENT_LENGTH,
                    http::HeaderValue::from_static("0"),
                );
            }
            let req = roxy_http::layer::from_layer_request(
                http::Request::from_parts(parts, body),
                roxy_http::RequestMeta::new(
                    roxy_http::Version::H1_1,
                    roxy_http::TargetForm::Absolute,
                ),
                &roxy_http::Limits::default(),
                &roxy_http::HttpFlags::default(),
            )
            .unwrap();
            assert_eq!(req.body.known_length(), expected);
            assert!(req.body.collect_up_to(1).await.unwrap().data.is_empty());
        }
    }

    #[tokio::test]
    async fn an_empty_whole_body_ends_its_lane_unread() {
        let (c, edge, _layers, core, _) = chain(0);
        edge.req_out.end_headless();
        core.res_out
            .whole(Head::Response(response(204)), Body::empty());
        assert_eq!(c.state(res(0)), LaneState::Ended);
        assert!(c.is_over());
    }

    #[tokio::test]
    async fn a_fault_is_recorded_torn_down_and_answered_in_that_order() {
        let (c, mut edge, mut layers, mut core, record) = chain(1);
        let mut l1 = layers.pop().unwrap();
        let _f0 = edge.req_out.head(request(), None, u64::MAX);
        let (_, b0) = l1.req_in.head().await.unwrap();
        l1.req_out.whole(request(), b0);
        let (_, _b1) = core.req_in.head().await.unwrap();

        l1.stage.fail(LayerError::Trap("boom".into()));

        assert_eq!(lock(&record.faults).len(), 1);
        assert_eq!(lock(&record.faults)[0].0, 0);
        assert!(l1.stage.torn_down().is_cancelled());
        assert!(core.stage.torn_down().is_cancelled());
        assert_eq!(c.state(req(1)), LaneState::Cut(FAILED.to_owned()));
        // The generated lane is left for the edge to read.
        assert_eq!(c.state(res(0)), LaneState::PendingFailure);
        let (head, body) = edge.res_in.head().await.unwrap();
        let Head::Response(parts) = head else {
            panic!("a response");
        };
        assert_eq!(parts.status, 503);
        assert_eq!(body.collect().await.unwrap().to_bytes(), "failure");
        assert_eq!(c.state(res(0)), LaneState::Ended);
        // The torn-down layer letting go of its lane changes nothing.
        drop(l1.res_out);
        assert_eq!(lock(&record.faults).len(), 1);
    }

    /// Once a fault reserves the response, the guest cannot race its
    /// generated refusal with a success, even before teardown wakes it.
    #[tokio::test]
    async fn pending_failure_refuses_a_producers_head_and_body() {
        for streaming in [false, true] {
            let (c, mut edge, mut layers, _core, _) = chain(1);
            let layer = layers.pop().unwrap();
            lock(&c.lane(res(0)).slot).state = LaneState::PendingFailure;
            c.refuse(res(0));
            if streaming {
                let mut body = layer
                    .res_out
                    .head(Head::Response(response(200)), None, u64::MAX);
                assert!(body.try_push(Bytes::from_static(b"success")).is_err());
                assert!(body.finish().await.is_err());
            } else {
                layer
                    .res_out
                    .whole(Head::Response(response(200)), Body::empty());
            }
            assert_eq!(c.state(res(0)), LaneState::PendingFailure);
            let (head, body) = edge.res_in.head().await.unwrap();
            assert!(matches!(head, Head::Response(p) if p.status == 503));
            assert_eq!(body.collect().await.unwrap().to_bytes(), "failure");
        }
    }

    /// Generating the refusal may await host services. The reservation
    /// must remain exclusive for that entire wait, before stage teardown.
    #[tokio::test]
    async fn a_pending_failure_response_keeps_its_publication_reservation() {
        let release = CancellationToken::new();
        let record = Arc::new(Record {
            response: Some((503, "failure")),
            release: Some(release.clone()),
            ..Record::default()
        });
        let (c, mut edge, mut layers, _core) = Chain::new(1, record);
        let layer = layers.pop().unwrap();
        lock(&c.lane(res(0)).slot).state = LaneState::PendingFailure;
        c.refuse(res(0));
        let received = edge.res_in.head();
        tokio::pin!(received);
        assert!(futures_util::poll!(received.as_mut()).is_pending());
        layer
            .res_out
            .whole(Head::Response(response(200)), Body::empty());
        assert_eq!(c.state(res(0)), LaneState::PendingFailure);
        release.cancel();
        let (head, body) = received.await.unwrap();
        assert!(matches!(head, Head::Response(p) if p.status == 503));
        assert_eq!(body.collect().await.unwrap().to_bytes(), "failure");
    }

    /// A consumer that lets go while the refusal is being built abandons
    /// it: nothing is put on the stopped lane, and the exchange is over.
    #[tokio::test]
    async fn letting_go_abandons_a_refusal_being_built() {
        let release = CancellationToken::new();
        let record = Arc::new(Record {
            response: Some((503, "failure")),
            release: Some(release.clone()),
            ..Record::default()
        });
        let (c, edge, mut layers, core) = Chain::new(1, record.clone());
        let layer = layers.pop().unwrap();
        layer.stage.enforcing();
        layer.stage.fail(LayerError::Trap("boom".into()));
        assert_eq!(c.state(res(0)), LaneState::PendingFailure);
        drop(edge);
        assert_eq!(c.state(res(0)), LaneState::Stopped);
        drop((layer, core));
        settles(c.until_over()).await;
        assert!(c.is_over());
        assert!(!c.has_head(res(0)));
        assert_eq!(lock(&record.faults).len(), 1);
    }

    /// The transport publishes the cause before disposing of its body,
    /// so nested readers all observe the same cancellation.
    #[tokio::test]
    async fn nested_readers_keep_the_client_cancellation_reason() {
        let (c, mut edge, mut layers, core, _) = chain(2);
        let mut upstream = layers.pop().unwrap();
        let mut downstream = layers.pop().unwrap();
        let _producer = core
            .res_out
            .head(Head::Response(response(200)), None, u64::MAX);
        let (head, body) = upstream.res_in.head().await.unwrap();
        upstream.res_out.whole(head, body);
        let (head, body) = downstream.res_in.head().await.unwrap();
        downstream.res_out.whole(head, body);
        let (_, body) = edge.res_in.head().await.unwrap();
        assert!(!upstream.stage.torn_down().is_cancelled());
        assert!(!downstream.stage.torn_down().is_cancelled());
        c.tear_down(CLIENT_GONE);
        drop(body);
        settles(c.until_over()).await;
        assert_eq!(c.layer_torn_down_why(0), CLIENT_GONE);
        assert_eq!(c.layer_torn_down_why(1), CLIENT_GONE);
    }

    #[tokio::test]
    async fn a_fault_after_the_answer_cuts_it() {
        let (c, mut edge, mut layers, _core, _) = chain(1);
        let l1 = layers.pop().unwrap();
        let mut answer = l1
            .res_out
            .head(Head::Response(response(200)), None, u64::MAX);
        answer.send_data(Bytes::from_static(b"part")).await.unwrap();
        let (_, body) = edge.res_in.head().await.unwrap();
        l1.stage.fail(LayerError::Trap("boom".into()));
        assert_eq!(c.state(res(0)), LaneState::Cut(FAILED.to_owned()));
        assert!(body.collect().await.is_err(), "the reader sees the cut");
    }

    #[tokio::test]
    async fn failure_response_nothing_cuts_the_lane_headless() {
        let record = Arc::new(Record::default());
        let (c, mut edge, mut layers, _core) = Chain::new(1, record);
        let l1 = layers.pop().unwrap();
        l1.stage.enforcing();
        l1.stage.fail(LayerError::Trap("boom".into()));
        assert_eq!(
            edge.res_in.head().await.unwrap_err(),
            Headless::Cut(FAILED.to_owned())
        );
        assert_eq!(c.state(res(0)), LaneState::Cut(FAILED.to_owned()));
    }

    #[tokio::test]
    async fn a_layer_letting_go_of_its_response_lane_headless_has_not_answered() {
        let (_c, mut edge, mut layers, _core, record) = chain(1);
        let l1 = layers.pop().unwrap();
        l1.req_out.end_headless();
        drop(l1.res_out);
        assert_eq!(
            lock(&record.faults)[0].1,
            LayerError::NoResponse.to_string()
        );
        let (head, _) = edge.res_in.head().await.unwrap();
        assert!(matches!(head, Head::Response(p) if p.status == 503));
        // Not so for the core: a headless end is just no response.
        let (c, edge, _layers, core, _) = chain(0);
        core.res_out.end_headless();
        assert_eq!(c.state(res(0)), LaneState::Ended);
        drop(edge);
    }

    #[tokio::test]
    async fn a_layer_that_does_not_run_passes_headless_lanes_through() {
        let record = Arc::new(Record::default());
        let (_c, mut edge, mut layers, core) = Chain::new(1, record.clone());
        let l1 = layers.pop().unwrap();
        drop(core);
        // Not enforcing: its own ends are nobody's events.
        l1.res_out.cut_headless("passed on");
        l1.req_out.end_headless();
        assert_eq!(*lock(&record.aborts), 0);
        assert!(lock(&record.faults).is_empty());
        assert_eq!(
            edge.res_in.head().await.unwrap_err(),
            Headless::Cut("passed on".to_owned())
        );
    }

    #[tokio::test]
    async fn an_answer_is_the_layers_own_until_it_takes_the_upstreams() {
        let (c, _edge, mut layers, core, _) = chain(3);
        let mut l3 = layers.pop().unwrap();
        let l2 = layers.pop().unwrap();
        let mut l1 = layers.pop().unwrap();
        // L3 answers before anything is on res[3]: its own.
        let _a3 = l3
            .res_out
            .head(Head::Response(response(403)), None, u64::MAX);
        assert_eq!(l3.stage.answered(), Some(true));
        // L2 answers with L3's answer on res[2], untaken: its own too.
        let _a2 = l2
            .res_out
            .head(Head::Response(response(403)), None, u64::MAX);
        assert_eq!(l2.stage.answered(), Some(true));
        // L1 takes L2's answer, then passes a head on: not its own.
        let _ = l1.res_in.head().await.unwrap();
        let _a1 = l1
            .res_out
            .head(Head::Response(response(403)), None, u64::MAX);
        assert_eq!(l1.stage.answered(), Some(false));
        assert_eq!(c.answered_by(), Some(1));
        drop((core, l3.res_in.try_head()));
    }

    #[tokio::test]
    async fn answered_by_is_the_layer_nearest_the_client_that_answered() {
        let (c, _edge, mut layers, _core, _) = chain(2);
        let l2 = layers.pop().unwrap();
        let l1 = layers.pop().unwrap();
        let _a1 = l1
            .res_out
            .head(Head::Response(response(200)), None, u64::MAX);
        let _a2 = l2
            .res_out
            .head(Head::Response(response(200)), None, u64::MAX);
        assert_eq!(l1.stage.answered(), Some(true));
        assert_eq!(l2.stage.answered(), Some(true));
        assert_eq!(c.answered_by(), Some(0));
    }

    /// A refusal whose body fails as it is read still cuts its lane, so
    /// the exchange completes, and the failed layer has not aborted it.
    #[tokio::test]
    async fn a_refusal_body_that_fails_still_cuts_its_lane() {
        let record = Arc::new(Record {
            response: Some((503, "failure")),
            broken: true,
            ..Record::default()
        });
        let (c, mut edge, mut layers, core) = Chain::new(1, record.clone());
        let l1 = layers.pop().unwrap();
        l1.stage.enforcing();
        l1.stage.fail(LayerError::NoResponse);
        let (_, body) = edge.res_in.head().await.unwrap();
        assert!(body.collect().await.is_err());
        assert!(matches!(c.state(res(0)), LaneState::Cut(_)));
        assert_eq!(*lock(&record.aborts), 0);
        drop((edge, l1, core));
        settles(c.until_over()).await;
    }

    #[tokio::test]
    async fn a_layer_cutting_its_own_lane_is_an_abort_not_a_fault() {
        let (c, _edge, mut layers, mut core, record) = chain(1);
        let l1 = layers.pop().unwrap();
        let forward = l1.req_out.head(request(), None, u64::MAX);
        let (_, body) = core.req_in.head().await.unwrap();
        forward.abort("changed my mind");
        assert_eq!(
            c.state(req(1)),
            LaneState::Cut("changed my mind".to_owned())
        );
        assert!(body.collect().await.is_err());
        assert_eq!(*lock(&record.aborts), 1);
        assert!(lock(&record.faults).is_empty());
        assert!(!l1.stage.torn_down().is_cancelled());

        let (c, mut edge, mut layers, _core, record) = chain(1);
        let l1 = layers.pop().unwrap();
        l1.res_out.cut_headless("no");
        assert_eq!(*lock(&record.aborts), 0);
        assert_eq!(c.state(res(0)), LaneState::PendingFailure);
        assert_eq!(lock(&record.faults).len(), 1);
        let (head, body) = edge.res_in.head().await.unwrap();
        assert!(matches!(head, Head::Response(parts) if parts.status == 503));
        assert_eq!(body.collect().await.unwrap().to_bytes(), "failure");
    }

    #[tokio::test]
    async fn a_bound_body_moves_both_lanes_together() {
        // A head-only layer passes the body of the lane it consumes on as
        // the body of the lane it produces.
        let (c, edge, mut layers, mut core, _) = chain(1);
        let mut l1 = layers.pop().unwrap();
        let mut f0 = edge.req_out.head(request(), None, u64::MAX);
        let (_, b0) = l1.req_in.head().await.unwrap();
        l1.req_out.whole(request(), b0);
        let (_, mut b1) = core.req_in.head().await.unwrap();
        f0.send_data(Bytes::from_static(b"abc")).await.unwrap();
        let frame = b1.frame().await.unwrap().unwrap();
        assert_eq!(frame.into_data().unwrap(), "abc");
        assert_eq!(c.state(req(0)), LaneState::Open);
        assert_eq!(c.state(req(1)), LaneState::Open);
        // The core stops reading: both lanes stop, the edge's writer learns.
        drop(b1);
        assert_eq!(c.state(req(1)), LaneState::Stopped);
        assert_eq!(c.state(req(0)), LaneState::Stopped);
        settles(f0.closed()).await;

        // And an end read through the binding ends both.
        let (c, edge, mut layers, mut core, _) = chain(1);
        let mut l1 = layers.pop().unwrap();
        let f0 = edge.req_out.head(request(), None, u64::MAX);
        let (_, b0) = l1.req_in.head().await.unwrap();
        l1.req_out.whole(request(), b0);
        let (_, b1) = core.req_in.head().await.unwrap();
        f0.finish().await.unwrap();
        b1.collect().await.unwrap();
        assert_eq!(c.state(req(0)), LaneState::Ended);
        assert_eq!(c.state(req(1)), LaneState::Ended);
    }

    #[tokio::test]
    async fn a_bound_response_stopped_downstream_tears_the_core_down() {
        let (c, mut edge, mut layers, core, _) = chain(1);
        let mut l1 = layers.pop().unwrap();
        let mut upstream = core
            .res_out
            .head(Head::Response(response(200)), None, u64::MAX);
        let (_, r1) = l1.res_in.head().await.unwrap();
        l1.res_out.whole(Head::Response(response(200)), r1);
        let (_, r0) = edge.res_in.head().await.unwrap();
        upstream.send_data(Bytes::from_static(b"a")).await.unwrap();
        drop(r0);
        assert_eq!(c.state(res(0)), LaneState::Stopped);
        assert_eq!(c.state(res(1)), LaneState::Stopped);
        assert!(l1.stage.torn_down().is_cancelled());
        assert!(core.stage.torn_down().is_cancelled());
        settles(upstream.closed()).await;
    }

    #[tokio::test]
    async fn a_lane_cut_from_outside_ends_a_read_its_producer_left_hanging() {
        let (c, mut edge, mut layers, mut core, _) = chain(1);
        let l1 = layers.pop().unwrap();
        let _f0 = edge.req_out.head(request(), None, u64::MAX);
        let forward = l1.req_out.head(request(), None, u64::MAX);
        let (_, mut b1) = core.req_in.head().await.unwrap();
        // The core reads while L1's producer end stays open and quiet.
        let read = tokio::spawn(async move { b1.frame().await });
        tokio::task::yield_now().await;
        c.tear_down(ENDED);
        assert_eq!(c.state(req(1)), LaneState::Cut(ENDED.to_owned()));
        let frame = settles(read).await.unwrap();
        assert!(matches!(frame, Some(Err(BodyError::Incomplete))));
        assert!(core.stage.torn_down().is_cancelled());
        // And a wait for a head on a lane released from under its holder.
        assert_eq!(
            edge.res_in.head().await.unwrap_err(),
            Headless::Cut(ENDED.to_owned())
        );
        drop(forward);
    }

    #[tokio::test]
    async fn a_wait_for_a_head_on_a_lane_released_by_a_teardown_ends() {
        let (_c, edge, mut layers, _core, _) = chain(1);
        let mut l1 = layers.pop().unwrap();
        let waiting = tokio::spawn(async move { l1.res_in.head().await });
        tokio::task::yield_now().await;
        edge.res_in.release(ENDED);
        assert_eq!(
            settles(waiting).await.unwrap().unwrap_err(),
            Headless::Cut(ENDED.to_owned())
        );
    }

    #[tokio::test]
    async fn try_head_sees_only_what_is_on_the_lane() {
        let (_c, _edge, mut layers, core, _) = chain(1);
        let l1 = layers.pop().unwrap();
        let mut res_in = l1.res_in;
        assert!(res_in.try_head().is_none());
        core.res_out
            .whole(Head::Response(response(200)), Body::empty());
        assert!(matches!(res_in.try_head(), Some(Ok(_))));
        // A headless end is seen too; a pending failure response is not a head yet.
        let (_c, _edge, mut layers, mut core, _) = chain(2);
        let l2 = layers.pop().unwrap();
        let l1 = layers.pop().unwrap();
        l2.res_out.end_headless();
        drop(l2.req_out);
        assert!(core.req_in.try_head().unwrap().is_err());
        let mut res_in = l1.res_in;
        assert!(
            res_in.try_head().is_none(),
            "the failure response is not on the lane"
        );
        assert!(matches!(res_in.head().await, Ok((Head::Response(_), _))));
    }
}
