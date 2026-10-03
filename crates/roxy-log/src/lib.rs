//! Buffered, single-writer log destinations for roxy (`DESIGN.md` §10.1,
//! "Writing"): the flow log today, body capture and traffic teeing later.
//!
//! # Guarantees
//!
//! - **Appending never does I/O.** [`LogWriter::append`] copies bytes into a
//!   shared buffer under a short lock and wakes the writer. Callers on any
//!   core never touch the destination and never wait for the disk.
//! - **One writer thread** owns each destination. It swaps the whole buffer
//!   out and writes it in one go, so under load each write carries every
//!   record queued since the last one: throughput follows disk bandwidth,
//!   not event rate. At low load each record goes out as it arrives.
//! - **Backpressure, never loss.** Bytes appended but not yet written are
//!   counted. Once they reach [`WriterOptions::high_water`], or the
//!   destination is failing, [`LogWriter::poll_ready`] is `Pending` until
//!   the writer catches up. Producers of traffic wait on it, so a slow or
//!   failing disk slows or stops traffic rather than losing audit records.
//!   `append` itself never refuses: the overshoot past the mark is bounded
//!   by what producers emit between two readiness checks.
//! - **Failures retry, never skip.** A write, rotation or reopen error is
//!   logged, readiness stays `Pending`, and the operation is retried every
//!   [`WriterOptions::retry_interval`] until it succeeds. Only at shutdown,
//!   after [`WriterOptions::flush_timeout`] of failures, does it give up.
//! - **Records stay whole.** One `append` is written contiguously, and a
//!   [`Destination`] may only switch files at a batch boundary
//!   ([`Destination::end_batch`]), so a record never spans two files.
//! - **Flush and close.** [`LogWriter::flush`] waits until everything
//!   appended so far is written; dropping the writer writes what is left and
//!   joins the thread.
//!
//! # Destinations
//!
//! - [`Stream`]: any [`std::io::Write`] (stdout, a socket, a test buffer).
//! - [`RotatingFile`]: an append-only file with size-based rotation,
//!   pruning and optional gzip of rotated files ([`RotateOptions`]), and
//!   reopen for external rotation.
#![forbid(unsafe_code)]

mod rotate;
mod writer;

use std::io::{self, Write};

pub use rotate::{RotateOptions, RotatingFile};
pub use writer::{DEFAULT_HIGH_WATER, LogWriter, WriterOptions};

/// Where a [`LogWriter`] puts bytes. Driven only by the writer thread.
pub trait Destination: Send + 'static {
    /// Writes some of `buf`; may be partial, like [`Write::write`].
    fn write(&mut self, buf: &[u8]) -> io::Result<usize>;

    /// The end of a batch: everything written so far must be flushed. This
    /// is the only point at which a destination may switch files
    /// (rotation). An error is retried, with traffic held.
    fn end_batch(&mut self) -> io::Result<()>;

    /// Reopens the destination (after external rotation). An error is
    /// retried, with traffic held. Default: nothing to reopen.
    fn reopen(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A [`Destination`] over any writer, flushed at every batch boundary.
#[derive(Debug)]
pub struct Stream<W>(pub W);

impl<W: Write + Send + 'static> Destination for Stream<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn end_batch(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
