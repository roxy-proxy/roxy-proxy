//! The body streams a guest reads and writes, and the response it waits
//! for.
//!
//! A `wasi:io` stream in the resource table is a `Box<dyn InputStream>` (or
//! `OutputStream`), which cannot be downcast, so every stream this crate
//! hands out keeps its state behind a handle the exchange holds too, keyed
//! by the resource's index ([`Streams`]). `passthrough` and `finish` reach
//! the body through that handle, and a stream the exchange did not hand
//! out (another exchange's, stdin, a reused index) is not found there.

use std::collections::HashMap;
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

use bytes::Bytes;
use http_body::{Body as HttpBody, Frame};
use roxy_http::{Body, BodyError, BodySender};
use wasmtime::component::{Resource, ResourceTable};
use wasmtime_wasi::p2::{
    DynInputStream, DynOutputStream, InputStream, OutputStream, Pollable, StreamError, StreamResult,
};
use wasmtime_wasi::runtime::AbortOnDropJoinHandle;

use crate::bindings::roxy::addon::types;
use crate::error::LayerError;
use crate::exchange::ExchangeShared;

/// Most bytes one `write` to a guest-produced body may carry: one frame.
const WRITE_CHUNK: usize = 64 * 1024;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A proxy [`Body`] on its way into the guest (the request it handles, a
/// response from `next` or an endpoint).
struct InputState {
    /// The body, until it ends, fails or is moved out.
    body: Option<Body>,
    /// Data read from the body and not yet taken by the guest.
    buffer: Bytes,
    /// A failure to report on the next read.
    error: Option<BodyError>,
    /// Data bytes the guest has taken.
    taken: u64,
    /// The guest's handle is gone from the table: a lookup under its index
    /// is some other stream's.
    gone: bool,
}

impl InputState {
    /// Pulls from the body until there is something to report. Trailers
    /// are dropped.
    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            if !self.buffer.is_empty() || self.error.is_some() {
                return Poll::Ready(());
            }
            let Some(body) = self.body.as_mut() else {
                return Poll::Ready(());
            };
            match Pin::new(body).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(frame))) => {
                    if let Ok(data) = frame.into_data()
                        && !data.is_empty()
                    {
                        self.buffer = data;
                    }
                }
                // An observer's copy whose real body the stack dropped
                // unread ends where the reading stopped. Nobody is at fault,
                // and the guest learns what became of the request from
                // `next`.
                Poll::Ready(None | Some(Err(BodyError::Abandoned))) => self.body = None,
                Poll::Ready(Some(Err(e))) => {
                    self.error = Some(e);
                    self.body = None;
                }
            }
        }
    }
}

/// The `input-stream` the guest reads a host body through.
struct GuestInput(Arc<Mutex<InputState>>);

#[async_trait::async_trait]
impl InputStream for GuestInput {
    fn read(&mut self, size: usize) -> StreamResult<Bytes> {
        let mut s = lock(&self.0);
        let _ = s.poll_fill(&mut Context::from_waker(Waker::noop()));
        if !s.buffer.is_empty() {
            let n = size.min(s.buffer.len());
            let chunk = s.buffer.split_to(n);
            s.taken = s.taken.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
            return Ok(chunk);
        }
        if let Some(e) = s.error.take() {
            return Err(StreamError::LastOperationFailed(wasmtime::format_err!(
                "{e}"
            )));
        }
        if s.body.is_none() {
            return Err(StreamError::Closed);
        }
        Ok(Bytes::new())
    }
}

#[async_trait::async_trait]
impl Pollable for GuestInput {
    async fn ready(&mut self) {
        poll_fn(|cx| lock(&self.0).poll_fill(cx)).await;
    }
}

impl Drop for GuestInput {
    fn drop(&mut self) {
        let mut s = lock(&self.0);
        s.gone = true;
        s.body = None;
    }
}

/// Which body of the exchange a guest is producing: decides what dropping
/// it unfinished means.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Produced {
    /// The request body passed to `next`: a cut, settled by
    /// [`ExchangeShared::check_next`].
    Next,
    /// The response body: the exchange fails.
    Response,
    /// An endpoint request body: the exchange fails.
    Endpoint,
}

struct OutputState {
    /// The sender, until the body is finished or taken.
    sender: Option<BodySender>,
    produced: Produced,
    shared: Arc<ExchangeShared>,
    gone: bool,
}

impl OutputState {
    fn cut(&self, why: &str) {
        match self.produced {
            Produced::Next => self.shared.cut_next(format!("request body {why}")),
            Produced::Response => self
                .shared
                .fail(LayerError::InvalidResponse(format!("response body {why}"))),
            Produced::Endpoint => self.shared.fail(LayerError::InvalidRequest(format!(
                "endpoint request body {why}"
            ))),
        }
    }
}

/// The `output-stream` the guest writes a body through. Dropped before
/// `finish`, the body is cut: it never ends as complete.
struct GuestOutput(Arc<Mutex<OutputState>>);

#[async_trait::async_trait]
impl OutputStream for GuestOutput {
    fn write(&mut self, bytes: Bytes) -> StreamResult<()> {
        if bytes.len() > WRITE_CHUNK {
            return Err(StreamError::trap("write exceeded the permit"));
        }
        let mut s = lock(&self.0);
        let Some(tx) = s.sender.as_mut() else {
            return Err(StreamError::Closed);
        };
        match tx.try_push(bytes) {
            Ok(()) => Ok(()),
            Err(BodyError::Closed) => Err(StreamError::Closed),
            Err(e) => Err(StreamError::LastOperationFailed(wasmtime::format_err!(
                "{e}"
            ))),
        }
    }

    fn flush(&mut self) -> StreamResult<()> {
        // Written frames are already queued for the reader.
        self.check_write().map(drop)
    }

    fn check_write(&mut self) -> StreamResult<usize> {
        let s = lock(&self.0);
        match &s.sender {
            Some(tx) if !tx.is_closed() => Ok(if tx.capacity() == 0 { 0 } else { WRITE_CHUNK }),
            _ => Err(StreamError::Closed),
        }
    }
}

#[async_trait::async_trait]
impl Pollable for GuestOutput {
    async fn ready(&mut self) {
        let wait = lock(&self.0).sender.as_ref().map(BodySender::ready_shared);
        if let Some(wait) = wait {
            wait.await;
        }
    }
}

impl Drop for GuestOutput {
    fn drop(&mut self) {
        let mut s = lock(&self.0);
        s.gone = true;
        if let Some(tx) = s.sender.take() {
            s.cut("dropped unfinished");
            tx.abort(BodyError::Incomplete);
        }
    }
}

/// What a `next` or endpoint call resolves to.
pub(crate) type Answer = Result<http::Response<Body>, types::Error>;

/// The `pending-response` resource. Dropped while pending, the call is
/// abandoned (its task aborted). Public only because the generated
/// bindings name it; the crate exports nothing of it.
pub struct PendingResponse(Pending);

enum Pending {
    Waiting(AbortOnDropJoinHandle<Answer>),
    Ready(Answer),
    Consumed,
}

impl PendingResponse {
    pub(crate) fn new(handle: AbortOnDropJoinHandle<Answer>) -> Self {
        Self(Pending::Waiting(handle))
    }

    /// The answer if it has arrived, without waiting. `Err(())` once it has
    /// been taken.
    pub(crate) fn poll_take(&mut self) -> Result<Option<Answer>, ()> {
        if let Pending::Waiting(handle) = &mut self.0 {
            match Pin::new(handle).poll(&mut Context::from_waker(Waker::noop())) {
                Poll::Pending => return Ok(None),
                Poll::Ready(answer) => self.0 = Pending::Ready(answer),
            }
        }
        match std::mem::replace(&mut self.0, Pending::Consumed) {
            Pending::Ready(answer) => Ok(Some(answer)),
            Pending::Consumed => Err(()),
            Pending::Waiting(_) => unreachable!("settled above"),
        }
    }

    /// Waits for the answer. `Err(())` once it has been taken.
    pub(crate) async fn wait(self) -> Result<Answer, ()> {
        match self.0 {
            Pending::Waiting(handle) => Ok(handle.await),
            Pending::Ready(answer) => Ok(answer),
            Pending::Consumed => Err(()),
        }
    }
}

#[async_trait::async_trait]
impl Pollable for PendingResponse {
    async fn ready(&mut self) {
        if let Pending::Waiting(handle) = &mut self.0 {
            let answer = handle.await;
            self.0 = Pending::Ready(answer);
        }
    }
}

/// The streams one exchange has handed its guest, by resource index.
#[derive(Default)]
pub(crate) struct Streams {
    inputs: HashMap<u32, Arc<Mutex<InputState>>>,
    outputs: HashMap<u32, Arc<Mutex<OutputState>>>,
}

impl Streams {
    /// Hands `body` to the guest as an `input-stream`.
    pub(crate) fn input(
        &mut self,
        table: &mut ResourceTable,
        body: Body,
    ) -> wasmtime::Result<Resource<DynInputStream>> {
        let state = Arc::new(Mutex::new(InputState {
            body: Some(body),
            buffer: Bytes::new(),
            error: None,
            taken: 0,
            gone: false,
        }));
        let stream: DynInputStream = Box::new(GuestInput(state.clone()));
        let res = table.push(stream)?;
        self.inputs.insert(res.rep(), state);
        Ok(res)
    }

    /// Moves the body behind an `input-stream` this exchange handed out back
    /// host-side, with whatever the guest has not read of it (its known
    /// length less the bytes taken). `None` for a stream that is not one of
    /// those.
    pub(crate) fn take_input(&mut self, res: &Resource<DynInputStream>) -> Option<Body> {
        let state = self.inputs.remove(&res.rep())?;
        let mut s = lock(&state);
        if s.gone {
            return None;
        }
        s.gone = true;
        let rest = match (s.body.take(), s.error.take()) {
            (Some(body), _) => body,
            (None, Some(e)) => {
                let (tx, body) = Body::channel(u64::MAX, None);
                tx.abort(e);
                body
            }
            (None, None) => Body::empty(),
        };
        let first = (!s.buffer.is_empty()).then(|| Frame::data(std::mem::take(&mut s.buffer)));
        Some(if first.is_some() || s.taken > 0 {
            rest.prefixed(first, s.taken)
        } else {
            rest
        })
    }

    /// A body the guest writes: the `output-stream` it gets, and the body
    /// the host reads.
    pub(crate) fn output(
        &mut self,
        table: &mut ResourceTable,
        produced: Produced,
        shared: Arc<ExchangeShared>,
    ) -> wasmtime::Result<(Resource<DynOutputStream>, Body)> {
        let (tx, body) = Body::channel(u64::MAX, None);
        let state = Arc::new(Mutex::new(OutputState {
            sender: Some(tx),
            produced,
            shared,
            gone: false,
        }));
        let stream: DynOutputStream = Box::new(GuestOutput(state.clone()));
        let res = table.push(stream)?;
        self.outputs.insert(res.rep(), state);
        Ok((res, body))
    }

    /// Takes the sender behind an `output-stream` this exchange handed out,
    /// so dropping the guest's handle no longer cuts the body. `None` for a
    /// stream that is not one of those.
    pub(crate) fn take_output(&mut self, res: &Resource<DynOutputStream>) -> Option<BodySender> {
        let state = self.outputs.remove(&res.rep())?;
        let mut s = lock(&state);
        if s.gone {
            return None;
        }
        s.gone = true;
        s.sender.take()
    }
}
