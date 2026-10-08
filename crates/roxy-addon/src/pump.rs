//! Writing a body to the host while the layer waits on something else.
//!
//! The layer below may start answering before it has read the whole
//! request (an echo, an early error, a streaming transform), and the host
//! buffers only a chunk or two of either body. Writing the request body to
//! the end before reading the response would deadlock against such a peer,
//! so the request body is pumped *alongside* everything else the layer
//! waits on: the response head in [`crate::Next::run`], and then each read
//! of the response body.
//!
//! A body the layer hands on untouched (a host stream it neither read nor
//! transformed) never enters the guest: the host moves it from the input
//! stream to the output stream with `splice`, one call per chunk and no
//! copy into linear memory. Anything else (in-memory bodies, transforms) is
//! pulled a chunk at a time and written.

use crate::bindings::wasi::http::types::OutgoingBody;
use crate::bindings::wasi::io::poll::Pollable;
use crate::bindings::wasi::io::streams::{OutputStream, StreamError};
use crate::body::{Body, Incoming, Pull, READ_CHUNK};

/// Where the bytes come from.
enum Source {
    /// A host stream passed on as is: spliced host-side.
    Stream(Incoming),
    /// Chunks produced in the guest.
    Guest(Body),
}

/// The rest of a body, on its way to the host.
pub(crate) struct RequestPump {
    source: Source,
    /// A guest chunk taken from the source and not yet written.
    pending: Vec<u8>,
    /// Dropped before `out` when the body is finished.
    stream: Option<OutputStream>,
    out: Option<OutgoingBody>,
}

/// What one attempt at moving bytes found.
enum Act {
    /// Progress was made; try again.
    Again,
    /// Blocked until this is ready.
    Wait(Pollable),
    /// The source ended.
    Finish,
    /// The reader is gone.
    Abandon,
    /// The sink takes this many bytes of `pending`.
    Write(u64),
}

/// What a pump is waiting for.
pub(crate) enum Wait {
    /// Nothing: it is finished.
    Done,
    /// It can make progress once this is ready.
    On(Pollable),
}

impl RequestPump {
    pub(crate) fn new(out: OutgoingBody, body: Body) -> Self {
        let stream = out.write().ok();
        let source = match body.into_passthrough() {
            Ok(incoming) => Source::Stream(incoming),
            Err(body) => Source::Guest(body),
        };
        Self {
            source,
            pending: Vec::new(),
            stream,
            out: Some(out),
        }
    }

    pub(crate) fn is_done(&self) -> bool {
        self.out.is_none()
    }

    /// Makes what progress it can without waiting on the host, then says
    /// what it needs next. Blocks only on a source that cannot report its
    /// own readiness (a body with a pump of its own, which this one cannot
    /// drive).
    ///
    /// A source that fails panics: the body must not be finished as if it
    /// were complete, and the host fails the exchange closed when a layer
    /// traps. A reader that goes away (the layer below answered without
    /// reading the rest) ends the pump quietly.
    pub(crate) fn step(&mut self) -> Wait {
        loop {
            match self.act(false) {
                Act::Again => {}
                Act::Wait(p) => return Wait::On(p),
                Act::Finish => {
                    self.finish();
                    return Wait::Done;
                }
                Act::Abandon => {
                    self.abandon();
                    return Wait::Done;
                }
                Act::Write(permit) => {
                    if !self.write_pending(permit) {
                        return Wait::Done;
                    }
                }
            }
        }
    }

    /// Runs the pump to the end, blocking.
    pub(crate) fn drain(&mut self) {
        loop {
            match self.act(true) {
                Act::Again => {}
                Act::Wait(p) => p.block(),
                Act::Finish => return self.finish(),
                Act::Abandon => return self.abandon(),
                Act::Write(permit) => {
                    if !self.write_pending(permit) {
                        return;
                    }
                }
            }
        }
    }

    /// One attempt at moving bytes. `blocking` waits for the host where
    /// it otherwise reports what to wait on.
    fn act(&mut self, blocking: bool) -> Act {
        let Some(stream) = &self.stream else {
            return Act::Finish;
        };
        match &mut self.source {
            Source::Stream(incoming) => {
                let Some(input) = incoming.input() else {
                    return Act::Finish;
                };
                let moved = if blocking {
                    stream.blocking_splice(input, READ_CHUNK)
                } else {
                    stream.splice(input, READ_CHUNK)
                };
                match moved {
                    // Nothing moved: the sink is full, or the source has
                    // nothing yet.
                    Ok(0) => match stream.check_write() {
                        Ok(0) => Act::Wait(stream.subscribe()),
                        Ok(_) => Act::Wait(input.subscribe()),
                        Err(_) => Act::Abandon,
                    },
                    Ok(_) => Act::Again,
                    // The source ended, or the reader is gone (finishing a
                    // body nobody reads is harmless).
                    Err(StreamError::Closed) => Act::Finish,
                    Err(StreamError::LastOperationFailed(e)) => {
                        panic!("request body source failed: {}", e.to_debug_string())
                    }
                }
            }
            Source::Guest(body) => {
                if self.pending.is_empty() {
                    let pulled = if blocking {
                        match body.next() {
                            Some(Ok(chunk)) => Pull::Chunk(chunk),
                            Some(Err(e)) => Pull::Failed(e),
                            None => Pull::End,
                        }
                    } else {
                        body.try_next()
                    };
                    match pulled {
                        Pull::Chunk(chunk) => self.pending = chunk,
                        Pull::End => return Act::Finish,
                        Pull::Failed(e) => panic!("request body source failed: {e}"),
                        Pull::NotReady => {
                            return match body.pollable() {
                                Some(p) => Act::Wait(p),
                                // A source with a pump of its own cannot
                                // say when it is ready: block on it.
                                None => match body.next() {
                                    Some(Ok(chunk)) => {
                                        self.pending = chunk;
                                        Act::Again
                                    }
                                    Some(Err(e)) => panic!("request body source failed: {e}"),
                                    None => Act::Finish,
                                },
                            };
                        }
                    }
                }
                match stream.check_write() {
                    Ok(0) => Act::Wait(stream.subscribe()),
                    Ok(permit) => Act::Write(permit),
                    Err(_) => Act::Abandon,
                }
            }
        }
    }

    /// Writes up to `permit` bytes of `pending`. `false` once the reader is
    /// gone.
    fn write_pending(&mut self, permit: u64) -> bool {
        let Some(stream) = &self.stream else {
            return false;
        };
        let n = usize::try_from(permit)
            .unwrap_or(usize::MAX)
            .min(self.pending.len());
        if stream.write(&self.pending[..n]).is_err() || stream.flush().is_err() {
            self.abandon();
            return false;
        }
        self.pending.drain(..n);
        true
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
