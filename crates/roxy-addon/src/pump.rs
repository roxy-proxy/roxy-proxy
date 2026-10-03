//! Writing a request body to the layer below while its response is read.
//!
//! The layer below may start answering before it has read the whole
//! request (an echo, an early error, a streaming transform), and the host
//! buffers only a chunk or two of either body. Writing the request body to
//! the end before reading the response would deadlock against such a peer,
//! so the request body is pumped *alongside* everything else the layer
//! waits on: the response head in [`crate::Next::run`], and then each read
//! of the response body.

use crate::bindings::wasi::http::types::OutgoingBody;
use crate::bindings::wasi::io::poll::Pollable;
use crate::bindings::wasi::io::streams::OutputStream;
use crate::body::Body;

/// The rest of a request body, on its way down.
pub(crate) struct RequestPump {
    /// Bytes taken from `source` and not yet written.
    pending: Vec<u8>,
    source: Body,
    /// Dropped before `out` when the body is finished.
    stream: Option<OutputStream>,
    out: Option<OutgoingBody>,
}

/// What a pump is waiting for.
pub(crate) enum Wait {
    /// Nothing: it is finished.
    Done,
    /// It can make progress now without waiting.
    Ready,
    /// It can make progress once this is ready.
    On(Pollable),
}

impl RequestPump {
    pub(crate) fn new(out: OutgoingBody, source: Body) -> Self {
        let stream = out.write().ok();
        Self {
            pending: Vec::new(),
            source,
            stream,
            out: Some(out),
        }
    }

    pub(crate) fn is_done(&self) -> bool {
        self.out.is_none()
    }

    /// What the pump needs before it can make progress.
    pub(crate) fn wait(&self) -> Wait {
        let Some(stream) = &self.stream else {
            return Wait::Done;
        };
        if self.pending.is_empty() {
            // Needs the next chunk of the source.
            match self.source.pollable() {
                Some(p) => Wait::On(p),
                None => Wait::Ready,
            }
        } else {
            Wait::On(stream.subscribe())
        }
    }

    /// Makes what progress it can: pulls a chunk from the source if none is
    /// pending, and writes as much as the stream accepts. Blocks only on
    /// the source.
    ///
    /// A source that fails panics: the body must not be finished as if it
    /// were complete, and the host fails the exchange closed when a layer
    /// traps. A reader that goes away (the layer below answered without
    /// reading the rest) ends the pump quietly.
    pub(crate) fn advance(&mut self) {
        let Some(stream) = &self.stream else { return };
        if self.pending.is_empty() {
            match self.source.next() {
                Some(Ok(chunk)) => self.pending = chunk,
                Some(Err(e)) => panic!("request body source failed: {e}"),
                None => {
                    self.finish();
                    return;
                }
            }
        }
        match stream.check_write() {
            Ok(0) => {}
            Ok(n) => {
                let n = usize::try_from(n)
                    .unwrap_or(usize::MAX)
                    .min(self.pending.len());
                if stream.write(&self.pending[..n]).is_err() || stream.flush().is_err() {
                    self.abandon();
                    return;
                }
                self.pending.drain(..n);
            }
            Err(_) => self.abandon(),
        }
    }

    /// Runs the pump to the end, blocking.
    pub(crate) fn drain(&mut self) {
        while !self.is_done() {
            match self.wait() {
                Wait::Done => break,
                Wait::Ready => {}
                Wait::On(p) => p.block(),
            }
            self.advance();
        }
    }

    fn finish(&mut self) {
        // Written bytes are already queued for the reader, which drains
        // them before it sees the end. Waiting for a flush here would wait
        // for the reader, which may be this very layer (reading the
        // response), and deadlock.
        self.stream = None;
        if let Some(out) = self.out.take() {
            let _ = OutgoingBody::finish(out, None);
        }
    }

    /// The reader went away: stop without finishing (nobody is left to
    /// receive the rest).
    fn abandon(&mut self) {
        self.pending.clear();
        self.stream = None;
        self.out = None;
    }
}

impl Drop for RequestPump {
    /// A request passed down is sent in full even if the layer stops
    /// reading the response.
    fn drop(&mut self) {
        if !std::thread::panicking() {
            self.drain();
        }
    }
}
