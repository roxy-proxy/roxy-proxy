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
//! Only bodies produced in the guest (in-memory bodies, transforms) come
//! through here, a chunk at a time. A host body the layer hands on untouched
//! is moved host-side by `passthrough` and never enters the guest.

use crate::bindings::roxy::addon::types;
use crate::bindings::wasi::io::poll::Pollable;
use crate::bindings::wasi::io::streams::{OutputStream, StreamError};
use crate::body::{Body, Pull};

/// The rest of a body, on its way to the host.
pub(crate) struct RequestPump {
    source: Body,
    /// A chunk taken from the source and not yet written.
    pending: Vec<u8>,
    /// The host's stream, until the body is finished.
    stream: Option<OutputStream>,
}

/// What one attempt at moving bytes found.
enum Act {
    /// Progress was made; try again.
    Again,
    /// Blocked until this is ready.
    Wait(Pollable),
    /// The source ended, or the reader is gone.
    Finish,
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
    /// A pump from `source` into `stream`; with no stream (the body went to
    /// the host whole) it is done already.
    pub(crate) fn new(stream: Option<OutputStream>, source: Body) -> Self {
        Self {
            source,
            pending: Vec::new(),
            stream,
        }
    }

    pub(crate) fn is_done(&self) -> bool {
        self.stream.is_none()
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
        if self.pending.is_empty() {
            let pulled = if blocking {
                match self.source.next() {
                    Some(Ok(chunk)) => Pull::Chunk(chunk),
                    Some(Err(e)) => Pull::Failed(e),
                    None => Pull::End,
                }
            } else {
                self.source.try_next()
            };
            match pulled {
                Pull::Chunk(chunk) => self.pending = chunk,
                Pull::End => return Act::Finish,
                Pull::Failed(e) => panic!("request body source failed: {e}"),
                Pull::NotReady => {
                    return match self.source.pollable() {
                        Some(p) => Act::Wait(p),
                        // A source with a pump of its own cannot say when
                        // it is ready: block on it.
                        None => match self.source.next() {
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
            // The reader is gone.
            Err(_) => Act::Finish,
        }
    }

    /// Writes up to `permit` bytes of `pending`. `false` once the reader is
    /// gone. roxy's host queues each write for the reader as it is made, so
    /// nothing needs flushing.
    fn write_pending(&mut self, permit: u64) -> bool {
        let Some(stream) = &self.stream else {
            return false;
        };
        let n = usize::try_from(permit)
            .unwrap_or(usize::MAX)
            .min(self.pending.len());
        match stream.write(&self.pending[..n]) {
            Ok(()) => {}
            // The reader is gone: nothing more of this body will be read.
            Err(StreamError::Closed) => {
                self.finish();
                return false;
            }
            // A body never ends as complete short of its bytes.
            Err(e) => panic!("write failed: {e:?}"),
        }
        self.pending.drain(..n);
        true
    }

    /// Ends the body as complete. Written bytes are already queued for the
    /// reader, which drains them before it sees the end; a reader that has
    /// gone away makes the end a no-op on the host.
    fn finish(&mut self) {
        self.pending.clear();
        if let Some(stream) = self.stream.take() {
            types::finish(stream);
        }
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
