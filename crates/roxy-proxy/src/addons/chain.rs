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
//!   released. Releasing a response lane is a stop of that lane, so a
//!   teardown runs upstream hop by hop: nothing is carried for a response
//!   nobody waits for.
//! - A stopped request lane tells its producer and nothing else.
//! - A layer that lets go of its response lane without a head has not
//!   answered: that is its `no_response` fault.
//! - A faulting layer's fault is recorded first; then it is torn down; and
//!   the refusal the fault earns is put on its response lane if that lane
//!   has no head yet, so the layer downstream sees a response it may
//!   reshape.
//! - A layer answered if the response lane it consumes had no head when it
//!   put its own head on the lane it produces, decided then.
//! - A layer cutting a lane it produces is an abort, not a fault.
//! - The exchange is over when every lane is terminal.
#![allow(dead_code)] // The service and WASM stages drive the body writers.

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

use super::{BoxFuture, ENDED, StackError, lock};

/// A teardown's reason when the consumer of a response lane let go of it.
pub(crate) const GAVE_UP: &str = "the layer downstream gave up";
/// A teardown's reason when a layer faulted.
pub(crate) const FAILED: &str = "a layer failed";

/// Frames a lane holds before its producer waits: a lane is a wire, not a
/// buffer.
const LANE_DEPTH: usize = 2;

/// The head of a lane: a request on a request lane, a response on a
/// response lane.
#[derive(Debug)]
pub(crate) enum Head {
    Request(http::request::Parts),
    Response(http::response::Parts),
}

/// Where a lane is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LaneState {
    /// No head yet.
    Idle,
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
        !matches!(self, LaneState::Idle | LaneState::Open)
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
    /// The response the standing fault earns, put on `layer`'s response
    /// lane in its place; `None` when the exchange is closing without one.
    fn seed(&self, layer: usize) -> BoxFuture<Option<(http::response::Parts, Body)>>;
}

struct LaneSlot {
    state: LaneState,
    /// A head is on the lane.
    head: bool,
    /// The lane carries the refusal of the layer that failed to answer on
    /// it: roxy's, not the stage's, so a teardown leaves it alone and the
    /// consumer's first read produces it.
    seed: bool,
}

struct Lane {
    slot: Mutex<LaneSlot>,
    /// Cancelled when the lane becomes terminal.
    terminal: CancellationToken,
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
    /// For a layer: whether its answer was its own (the lane it consumes
    /// was headless when it answered). Set when it answers.
    answered: OnceLock<bool>,
}

/// The lanes of one exchange and the rules that move them.
pub(crate) struct Chain {
    hops: Box<[Hop]>,
    stages: Box<[StageState]>,
    recorder: Box<dyn Recorder>,
    over: CancellationToken,
    /// The client edge gave the exchange up: everything upstream of it is
    /// torn down, for `why`.
    torn: CancellationToken,
    torn_why: OnceLock<&'static str>,
    /// The first lane a layer cut of its own accord: the record's reason.
    abort: OnceLock<&'static str>,
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
                head: false,
                seed: false,
            }),
            terminal: CancellationToken::new(),
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
                answered: OnceLock::new(),
            })
            .collect();
        let chain = Arc::new(Self {
            hops,
            stages,
            recorder: Box::new(recorder),
            over: CancellationToken::new(),
            torn: CancellationToken::new(),
            torn_why: OnceLock::new(),
            abort: OnceLock::new(),
        });
        let ends = |dir| -> (Vec<Option<LaneTx>>, Vec<Option<LaneRx>>) {
            (0..=layers)
                .map(|hop| {
                    let lane = LaneId { hop, dir };
                    let (tx, rx) = oneshot::channel();
                    let tx = LaneTx {
                        chain: chain.clone(),
                        lane,
                        tx: Some(tx),
                    };
                    let rx = LaneRx {
                        chain: chain.clone(),
                        lane,
                        rx,
                        spent: false,
                        seeding: None,
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

    /// Resolves once `id` is terminal.
    pub(crate) fn settled(&self, id: LaneId) -> WaitForCancellationFutureOwned {
        self.lane(id).terminal.clone().cancelled_owned()
    }

    /// Cancelled when the client edge tears the exchange down.
    pub(crate) fn torn_down(&self) -> CancellationToken {
        self.torn.clone()
    }

    /// Why the client edge tore the exchange down, once it has.
    pub(crate) fn torn_down_why(&self) -> &'static str {
        self.torn_why.get().copied().unwrap_or(ENDED)
    }

    /// Cancelled when layer `layer` (its index in `addons:`) is torn down.
    pub(crate) fn layer_torn_down(&self, layer: usize) -> CancellationToken {
        self.stages[layer + 1].torn.clone()
    }

    /// Layer `layer` is torn down, or being torn down.
    pub(crate) fn layer_torn(&self, layer: usize) -> bool {
        self.stages[layer + 1].torn_why.get().is_some()
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
    pub(crate) fn fail_layer(&self, layer: usize, err: StackError) {
        self.fail(layer + 1, err);
    }

    /// Layer `layer` is answering: see [`StageHandle::answering`].
    pub(crate) fn layer_answering(&self, layer: usize) {
        self.answering(layer + 1);
    }

    /// Every lane is terminal: nothing in the exchange can move again.
    pub(crate) fn is_over(&self) -> bool {
        self.over.is_cancelled()
    }

    pub(crate) async fn until_over(&self) {
        self.over.cancelled().await;
    }

    /// The reason the first lane a layer cut of its own accord gives the
    /// record, if one did.
    pub(crate) fn abort_reason(&self) -> Option<&'static str> {
        self.abort.get().copied()
    }

    /// The layer whose own answer reached the client, if a layer's did.
    pub(crate) fn answered_by(&self) -> Option<usize> {
        (1..self.stages.len() - 1)
            .find(|&s| self.stages[s].answered.get() == Some(&true))
            .map(|s| s - 1)
    }

    /// Moves `id` to the terminal state `to` unless it is terminal already.
    fn settle(&self, id: LaneId, to: LaneState) -> bool {
        let lane = self.lane(id);
        {
            let mut slot = lock(&lane.slot);
            if slot.state.is_terminal() {
                return false;
            }
            slot.state = to;
        }
        lane.terminal.cancel();
        if self
            .hops
            .iter()
            .all(|h| lock(&h.req.slot).state.is_terminal() && lock(&h.res.slot).state.is_terminal())
        {
            self.over.cancel();
        }
        true
    }

    /// A head is on `id`; `body` is what follows it, handed to the
    /// consumer. Discarded on a terminal lane.
    fn head(
        self: &Arc<Self>,
        id: LaneId,
        tx: oneshot::Sender<(Head, Body)>,
        head: Head,
        body: Body,
    ) {
        let producer = id.producer();
        let complete = body.is_end_stream();
        let known = body.known_length();
        {
            let mut slot = lock(&self.lane(id).slot);
            if slot.state.is_terminal() {
                return;
            }
            slot.state = LaneState::Open;
            slot.head = true;
        }
        if id.dir == Dir::Res && self.is_layer(producer) {
            self.answering(producer);
        }
        let body = if complete {
            body
        } else {
            Body::wrap_native(Reading::new(self, id, body), u64::MAX, known)
        };
        // The consumer may have let go already: the body then drops here,
        // which is a stop on a lane that is stopped.
        let _ = tx.send((head, body));
        if complete {
            self.end(id);
        }
    }

    /// Layer stage `stage` is putting its head on its response lane: its
    /// answer is its own if the lane it consumes has none yet, decided
    /// now and never again.
    fn answering(&self, stage: usize) {
        let own = !lock(&self.hops[stage].res.slot).head;
        let _ = self.stages[stage].answered.set(own);
    }

    fn end(&self, id: LaneId) {
        self.settle(id, LaneState::Ended);
    }

    /// `id`'s producer lets go of it without a head.
    fn end_headless(&self, id: LaneId) {
        let producer = id.producer();
        {
            let slot = lock(&self.lane(id).slot);
            if slot.state != LaneState::Idle || slot.seed {
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
        if !self.settle(id, LaneState::Cut(why)) {
            return;
        }
        if abort && self.enforcing(id.producer()) {
            let _ = self.abort.set(match id.dir {
                Dir::Req => "forward_aborted",
                Dir::Res => "answer_aborted",
            });
        }
    }

    /// `id`'s consumer stops it, for `why`.
    pub(crate) fn release(&self, id: LaneId, why: &'static str) {
        self.stop(id, why);
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
    fn fail(&self, stage: usize, err: StackError) {
        debug_assert!(self.is_layer(stage));
        self.recorder.fault(stage - 1, err);
        let res_out = LaneId {
            hop: stage - 1,
            dir: Dir::Res,
        };
        {
            let mut slot = lock(&self.lane(res_out).slot);
            if slot.state == LaneState::Idle {
                slot.seed = true;
            }
        }
        self.tear_down_stage(stage, FAILED);
    }

    fn tear_down_stage(&self, stage: usize, why: &'static str) {
        let st = &self.stages[stage];
        if st.torn_why.set(why).is_err() {
            return;
        }
        let last = self.stages.len() - 1;
        if stage < last {
            self.cut_unless_seeded(
                LaneId {
                    hop: stage,
                    dir: Dir::Req,
                },
                why,
            );
        }
        if stage > 0 {
            self.cut_unless_seeded(
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
            self.stop(
                LaneId {
                    hop: stage,
                    dir: Dir::Res,
                },
                why,
            );
        }
        st.torn.cancel();
    }

    fn cut_unless_seeded(&self, id: LaneId, why: &'static str) {
        if lock(&self.lane(id).slot).seed {
            return;
        }
        self.cut(id, why.to_owned(), false);
    }

    /// Tears the whole stack down from the client edge: `res[0]` stopped
    /// and `req[0]` cut, as when the client is gone or roxy refuses what
    /// the stack produced.
    pub(crate) fn tear_down(&self, why: &'static str) {
        let _ = self.torn_why.set(why);
        self.torn.cancel();
        self.stop(
            LaneId {
                hop: 0,
                dir: Dir::Res,
            },
            why,
        );
        self.cut(
            LaneId {
                hop: 0,
                dir: Dir::Req,
            },
            why.to_owned(),
            false,
        );
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
            LaneState::Idle | LaneState::Open => unreachable!("terminal"),
        }
    }
}

/// A stage's handle on its own place in the chain.
pub(crate) struct StageHandle {
    chain: Arc<Chain>,
    stage: usize,
}

impl StageHandle {
    /// The layer faults: recorded, torn down, its answer seeded if none
    /// is on its lane. A layer's only: the edges cut their own lanes.
    pub(crate) fn fail(&self, err: impl Into<StackError>) {
        self.chain.fail(self.stage, err.into());
    }

    /// Roxy gives the stage up without a fault of its own: torn down,
    /// for `why`.
    pub(crate) fn gone(&self, why: &'static str) {
        self.chain.tear_down_stage(self.stage, why);
    }

    /// The layer runs in enforce mode: its lane events are its own.
    pub(crate) fn enforcing(&self) {
        self.chain.stages[self.stage]
            .enforcing
            .store(true, Ordering::Release);
    }

    /// The layer is answering: whether its answer is its own is read now,
    /// where the head it puts on its lane follows.
    pub(crate) fn answering(&self) {
        self.chain.answering(self.stage);
    }

    /// Cancelled when the stage is torn down.
    pub(crate) fn torn_down(&self) -> CancellationToken {
        self.chain.stages[self.stage].torn.clone()
    }

    pub(crate) fn torn_down_why(&self) -> Option<&'static str> {
        self.chain.stages[self.stage].torn_why.get().copied()
    }

    /// Whether the layer's answer was its own; `None` until it answers.
    pub(crate) fn answered(&self) -> Option<bool> {
        self.chain.stages[self.stage].answered.get().copied()
    }
}

/// A lane's producing end. Used once: a head with its body, or a headless
/// end or cut. Let go of unused, it ends the lane headless.
pub(crate) struct LaneTx {
    chain: Arc<Chain>,
    lane: LaneId,
    tx: Option<oneshot::Sender<(Head, Body)>>,
}

impl LaneTx {
    pub(crate) fn id(&self) -> LaneId {
        self.lane
    }

    /// Puts `head` on the lane; the body follows through the writer
    /// returned, `known_length` bytes of it when declared and at most
    /// `cap`.
    pub(crate) fn head(mut self, head: Head, known_length: Option<u64>, cap: u64) -> LaneBody {
        let tx = self.tx.take().expect("used once");
        let (sender, body) = Body::channel_with_depth(LANE_DEPTH, cap, known_length);
        self.chain.head(self.lane, tx, head, body);
        LaneBody {
            chain: self.chain.clone(),
            lane: self.lane,
            sender: Some(sender),
        }
    }

    /// Puts `head` on the lane with a body made elsewhere (an upstream's,
    /// a refusal's, the body of the lane this one is bound to): the lane
    /// ends or cuts as its consumer reads the body to its end.
    pub(crate) fn whole(mut self, head: Head, body: Body) {
        let tx = self.tx.take().expect("used once");
        self.chain.head(self.lane, tx, head, body);
    }

    /// Nothing goes on the lane.
    pub(crate) fn end_headless(self) {
        self.chain.end_headless(self.lane);
    }

    /// Nothing goes on the lane, and that is not the lane's complete
    /// story.
    pub(crate) fn cut_headless(mut self, why: impl Into<String>) {
        let tx = self.tx.take();
        self.chain.cut(self.lane, why.into(), true);
        drop(tx);
    }
}

impl Drop for LaneTx {
    fn drop(&mut self) {
        // The chain moves before the sender drops: a consumer woken by the
        // drop finds the lane settled, or a seed flagged on it.
        if self.tx.is_some() {
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
        if self.chain.state(self.lane).is_terminal() {
            return Err(BodyError::Closed);
        }
        self.sender.as_mut().ok_or(BodyError::Closed)
    }

    /// The body channel closed: its reader dropped it. When the reader is
    /// the client edge, wait until the lane is terminal before reporting
    /// that. The h1 and h2 handlers drop the body first and tear the chain
    /// down (with the reason) a moment later; reporting the drop early
    /// would let a producer act on it before the reason is known.
    async fn consumer_gone(&self) -> BodyError {
        if self.lane.consumer() == 0 {
            self.chain.lane(self.lane).terminal.cancelled().await;
        }
        BodyError::Closed
    }

    /// Resolves once the consumer stopped the lane, or the lane is
    /// terminal for any other reason.
    pub(crate) async fn closed(&self) {
        let terminal = self.chain.lane(self.lane).terminal.clone();
        match &self.sender {
            Some(s) if self.lane.consumer() != 0 => tokio::select! {
                () = s.closed() => {}
                () = terminal.cancelled() => {}
            },
            _ => terminal.cancelled().await,
        }
    }

    /// Waits until a frame can be pushed. Cancel-safe.
    pub(crate) async fn ready(&mut self) -> Result<(), BodyError> {
        let terminal = self.chain.lane(self.lane).terminal.clone();
        let sender = self.sender()?;
        let ready = tokio::select! {
            r = sender.ready() => r,
            () = terminal.cancelled() => Err(BodyError::Closed),
        };
        match ready {
            Err(BodyError::Closed) => Err(self.consumer_gone().await),
            other => other,
        }
    }

    /// Pushes a data frame without waiting; call [`LaneBody::ready`] first.
    pub(crate) fn try_push(&mut self, data: Bytes) -> Result<(), BodyError> {
        self.sender()?.try_push(data)
    }

    pub(crate) async fn send_data(&mut self, data: Bytes) -> Result<(), BodyError> {
        self.ready().await?;
        match self.try_push(data) {
            Err(BodyError::Closed) => Err(self.consumer_gone().await),
            other => other,
        }
    }

    pub(crate) async fn send_trailers(&mut self, trailers: HeaderMap) -> Result<(), BodyError> {
        self.ready().await?;
        match self.sender()?.try_push_trailers(trailers) {
            Err(BodyError::Closed) => Err(self.consumer_gone().await),
            other => other,
        }
    }

    /// Ends the lane. A body short of its declared length cuts it instead.
    pub(crate) async fn finish(mut self) -> Result<(), BodyError> {
        let sender = self.sender.take().ok_or(BodyError::Closed)?;
        match sender.finish().await {
            Ok(()) => {
                self.chain.end(self.lane);
                Ok(())
            }
            Err(BodyError::Closed) => Err(self.consumer_gone().await),
            Err(e) => {
                self.chain.cut(self.lane, e.to_string(), true);
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
    /// The refusal roxy is putting on this lane for the layer that failed
    /// to answer on it, kept across polls so a cancelled wait resumes it.
    seeding: Option<BoxFuture<Option<(http::response::Parts, Body)>>>,
}

impl LaneRx {
    pub(crate) fn id(&self) -> LaneId {
        self.lane
    }

    /// Waits for the head. Cancel-safe.
    pub(crate) async fn head(&mut self) -> Result<(Head, Body), Headless> {
        let lane = self.chain.lane(self.lane);
        loop {
            if std::mem::take(&mut lock(&lane.slot).seed) {
                self.seeding = Some(self.chain.recorder.seed(self.lane.hop));
            }
            if let Some(seed) = &mut self.seeding {
                let seeded = seed.await;
                self.seeding = None;
                let (tx, rx) = oneshot::channel();
                self.rx = rx;
                match seeded {
                    Some((parts, body)) => {
                        self.chain.head(self.lane, tx, Head::Response(parts), body);
                    }
                    None => self.chain.cut(self.lane, FAILED.to_owned(), false),
                }
            }
            let terminal = lane.terminal.clone();
            let arrived = tokio::select! {
                biased;
                r = &mut self.rx => r.ok(),
                () = terminal.cancelled() => self.rx.try_recv().ok(),
            };
            if let Some(arrived) = arrived {
                self.spent = true;
                return Ok(arrived);
            }
            if terminal.is_cancelled() {
                self.spent = true;
                return Err(self.chain.headless(self.lane));
            }
            // The producer let go without a head and the lane is not
            // settled: roxy is seeding it, which the next turn picks up.
            if !lock(&lane.slot).seed {
                terminal.cancelled().await;
            }
        }
    }

    /// The head, if it is on the lane now. A headless end is seen too; a
    /// refusal roxy has yet to put on the lane is not.
    pub(crate) fn try_head(&mut self) -> Option<Result<(Head, Body), Headless>> {
        if let Ok(arrived) = self.rx.try_recv() {
            self.spent = true;
            return Some(Ok(arrived));
        }
        if !self.chain.lane(self.lane).terminal.is_cancelled() {
            return None;
        }
        self.spent = true;
        Some(Err(self.chain.headless(self.lane)))
    }

    /// Stops the lane, giving `why` to whatever is torn down for it.
    pub(crate) fn release(mut self, why: &'static str) {
        if !self.spent {
            self.spent = true;
            self.chain.stop(self.lane, why);
        }
    }
}

impl Drop for LaneRx {
    fn drop(&mut self) {
        // Dropping a lane the client edge consumes does not stop it. The
        // edge stops its lane explicitly, through `Chain::tear_down` or
        // `Chain::release`, so the reason (client gone, write failed,
        // answer refused) is known when the stop happens.
        if !self.spent && self.lane.consumer() != 0 {
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
            terminal: Box::pin(chain.lane(lane).terminal.clone().cancelled_owned()),
        }
    }

    fn ended(&self) {
        if !self.done.swap(true, Ordering::AcqRel) {
            self.chain.end(self.lane);
        }
    }

    /// The body's error reached the reader: the lane is cut, by whoever
    /// cut the body (its producer's own abort is recorded where it cut).
    fn cut(&self, why: String) {
        if !self.done.swap(true, Ordering::AcqRel) {
            self.chain.cut(self.lane, why, false);
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
            return Poll::Ready(None);
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(Some(Err(e))) => {
                this.cut(e.to_string());
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                this.ended();
                Poll::Ready(None)
            }
            Poll::Pending => {
                if this.terminal.as_mut().poll(cx).is_ready()
                    && matches!(
                        this.chain.state(this.lane),
                        LaneState::Cut(_) | LaneState::Stopped
                    )
                {
                    this.done.store(true, Ordering::Release);
                    return Poll::Ready(Some(Err(BodyError::Incomplete)));
                }
                Poll::Pending
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        let end = self.inner.is_end_stream();
        if end {
            self.ended();
        }
        end
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for Reading {
    fn drop(&mut self) {
        // Same rule as `LaneRx::drop`: the client edge stops its lane
        // explicitly, not by dropping the body.
        if !self.done.swap(true, Ordering::AcqRel) && self.lane.consumer() != 0 {
            let why = self.chain.gave_up(self.lane.consumer());
            self.chain.stop(self.lane, why);
        }
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
        /// What `seed` answers with; `None` seeds nothing.
        seed: Option<(u16, &'static str)>,
    }

    impl Recorder for Arc<Record> {
        fn fault(&self, layer: usize, err: StackError) {
            lock(&self.faults).push((layer, err.to_string()));
        }

        fn seed(&self, _layer: usize) -> BoxFuture<Option<(http::response::Parts, Body)>> {
            let seed = self.seed;
            Box::pin(async move {
                let (status, body) = seed?;
                Some((response(status), Body::from_bytes(body)))
            })
        }
    }

    fn chain(layers: usize) -> (Arc<Chain>, EdgeIo, Vec<LayerIo>, CoreIo, Arc<Record>) {
        let record = Arc::new(Record {
            seed: Some((503, "seeded")),
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
        // The edge lets go of a whole body unread: its lane stays open until
        // the edge says why it stopped reading.
        core.res_out
            .whole(Head::Response(response(200)), Body::from_bytes("x"));
        let (_, b) = edge.res_in.head().await.unwrap();
        drop(b);
        assert_eq!(c.state(res(0)), LaneState::Open);
        c.release(res(0), ENDED);
        assert_eq!(c.state(res(0)), LaneState::Stopped);
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
        let (_, _b2) = core.req_in.head().await.unwrap();
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
        assert_eq!(c.abort_reason(), None);
        assert!(lock(&record.faults).is_empty());
        // L1 let go of the upload as it went: the edge's writer learns, and
        // nothing is left to move.
        assert_eq!(c.state(req(0)), LaneState::Stopped);
        settles(upload.closed()).await;
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
    async fn an_empty_whole_body_ends_its_lane_unread() {
        let (c, edge, _layers, core, _) = chain(0);
        edge.req_out.end_headless();
        core.res_out
            .whole(Head::Response(response(204)), Body::empty());
        assert_eq!(c.state(res(0)), LaneState::Ended);
        assert!(c.is_over());
    }

    #[tokio::test]
    async fn a_fault_is_recorded_torn_down_and_seeded_in_that_order() {
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
        // The seeded lane is left for the edge to read.
        assert_eq!(c.state(res(0)), LaneState::Idle);
        let (head, body) = edge.res_in.head().await.unwrap();
        let Head::Response(parts) = head else {
            panic!("a response");
        };
        assert_eq!(parts.status, 503);
        assert_eq!(body.collect().await.unwrap().to_bytes(), "seeded");
        assert_eq!(c.state(res(0)), LaneState::Ended);
        // The torn-down layer letting go of its lane changes nothing.
        drop(l1.res_out);
        assert_eq!(lock(&record.faults).len(), 1);
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
    async fn seeding_nothing_cuts_the_lane_headless() {
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
        let (c, mut edge, mut layers, core) = Chain::new(1, record.clone());
        let l1 = layers.pop().unwrap();
        drop(core);
        // Not enforcing: its own ends are nobody's events.
        l1.res_out.cut_headless("passed on");
        l1.req_out.end_headless();
        assert_eq!(c.abort_reason(), None);
        assert!(lock(&record.faults).is_empty());
        assert_eq!(
            edge.res_in.head().await.unwrap_err(),
            Headless::Cut("passed on".to_owned())
        );
    }

    #[tokio::test]
    async fn an_answer_decided_as_the_layer_answers_stands_when_its_head_lands() {
        let (c, _edge, mut layers, core, _) = chain(1);
        let l1 = layers.pop().unwrap();
        l1.stage.answering();
        core.res_out
            .whole(Head::Response(response(200)), Body::empty());
        let _a1 = l1
            .res_out
            .head(Head::Response(response(403)), None, u64::MAX);
        assert_eq!(l1.stage.answered(), Some(true));
        assert_eq!(c.answered_by(), Some(0));

        let (c, _edge, mut layers, core, _) = chain(1);
        let l1 = layers.pop().unwrap();
        core.res_out
            .whole(Head::Response(response(200)), Body::empty());
        l1.stage.answering();
        let _a1 = l1
            .res_out
            .head(Head::Response(response(200)), None, u64::MAX);
        assert_eq!(
            c.answered_by(),
            None,
            "the response from upstream, passed on"
        );
    }

    #[tokio::test]
    async fn an_answer_is_the_layers_own_only_while_its_response_lane_is_headless() {
        let (c, _edge, mut layers, core, _) = chain(2);
        let l2 = layers.pop().unwrap();
        let l1 = layers.pop().unwrap();
        // L2 answers before anything is on res[2]: its own.
        let _a2 = l2
            .res_out
            .head(Head::Response(response(403)), None, u64::MAX);
        assert_eq!(l2.stage.answered(), Some(true));
        // L1 passes a head on while L2's is on res[1]: not its own, even
        // unread.
        let _a1 = l1
            .res_out
            .head(Head::Response(response(403)), None, u64::MAX);
        assert_eq!(l1.stage.answered(), Some(false));
        assert_eq!(c.answered_by(), Some(1));
        drop(core);
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
        assert_eq!(c.abort_reason(), Some("forward_aborted"));
        assert!(lock(&record.faults).is_empty());
        assert!(!l1.stage.torn_down().is_cancelled());
        // The first abort stands.
        let answer = l1
            .res_out
            .head(Head::Response(response(200)), None, u64::MAX);
        drop(answer);
        assert_eq!(c.abort_reason(), Some("forward_aborted"));

        let (c, _edge, mut layers, _core, _) = chain(1);
        let l1 = layers.pop().unwrap();
        l1.res_out.cut_headless("no");
        assert_eq!(c.abort_reason(), Some("answer_aborted"));
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
        c.release(res(0), ENDED);
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
        // A headless end is seen too; a pending seed is not a head yet.
        let (_c, _edge, mut layers, mut core, _) = chain(2);
        let l2 = layers.pop().unwrap();
        let l1 = layers.pop().unwrap();
        l2.res_out.end_headless();
        drop(l2.req_out);
        assert!(core.req_in.try_head().unwrap().is_err());
        let mut res_in = l1.res_in;
        assert!(res_in.try_head().is_none(), "the seed is not on the lane");
        assert!(matches!(res_in.head().await, Ok((Head::Response(_), _))));
    }
}
