//! The buffered log writer (`DESIGN.md` §10.1, "Writing"): one writer
//! thread per destination, batched writes, and backpressure that reaches
//! the network instead of dropping audit records.
//!
//! # How it works
//!
//! - **Appending never does I/O.** [`LogWriter::append`] copies the bytes
//!   into a shared buffer under a short lock and wakes the writer. Callers on
//!   any core never touch the file and never wait for the disk.
//! - **One writer thread** owns the destination. It swaps the whole buffer
//!   out and writes it in one go, so under load each write carries every
//!   line queued since the last one: throughput follows disk bandwidth, not
//!   event rate. At low load each line is written as soon as it arrives.
//! - **Backpressure, never loss.** Bytes appended but not yet written are
//!   counted. Once they reach [`WriterOptions::high_water`], or the writer
//!   is failing, [`LogWriter::poll_ready`] is `Pending` until the writer
//!   catches up. Traffic producers wait on it (the start of each exchange,
//!   each forwarded body chunk, each WebSocket read), so a slow or failing
//!   disk slows or stops traffic. `append` itself never refuses: the
//!   overshoot past the mark is bounded by what in-flight exchanges emit
//!   between two readiness checks.
//! - **Failures retry, never skip.** A write error is logged, the writer
//!   waits [`WriterOptions::retry_interval`] and retries the unwritten rest
//!   of the batch. Meanwhile readiness stays `Pending`, so traffic stops
//!   until the destination recovers.
//! - **Flush and close.** [`LogWriter::flush`] waits until everything
//!   appended so far is written (bounded by a timeout); dropping the writer
//!   writes what is left and joins the thread.
//!
//! The same writer is meant to carry body capture and traffic teeing later
//! (§10.2): anything that must reach disk in order, at disk speed, with
//! backpressure.

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Tuning for a [`LogWriter`].
#[derive(Debug, Clone, Copy)]
pub struct WriterOptions {
    /// Unwritten bytes at which producers are held back.
    pub high_water: usize,
    /// Wait between attempts after a write error.
    pub retry_interval: Duration,
    /// Longest [`LogWriter::flush`] waits.
    pub flush_timeout: Duration,
}

impl Default for WriterOptions {
    fn default() -> Self {
        Self {
            high_water: 8 << 20,
            retry_interval: Duration::from_millis(500),
            flush_timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Default)]
struct State {
    buf: Vec<u8>,
    closing: bool,
    /// Bumped by `flush`; the writer reports the generation it has written.
    requested: u64,
    written: u64,
}

struct Core {
    name: &'static str,
    state: Mutex<State>,
    /// Wakes the writer thread.
    work: Condvar,
    /// Wakes `flush` callers.
    progress: Condvar,
    /// Appended but not yet written.
    pending: AtomicUsize,
    /// The last write failed (or the writer is gone).
    failing: AtomicBool,
    /// Producers waiting for readiness.
    waiters: Mutex<Vec<Waker>>,
    opts: WriterOptions,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Core {
    fn ready(&self) -> bool {
        !self.failing.load(Ordering::Acquire)
            && self.pending.load(Ordering::Acquire) < self.opts.high_water
    }

    fn wake_waiters(&self) {
        if self.ready() {
            let waiters = std::mem::take(&mut *lock(&self.waiters));
            for w in waiters {
                w.wake();
            }
        }
    }
}

/// A buffered, single-writer destination. See the module docs.
pub struct LogWriter {
    core: Arc<Core>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for LogWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogWriter")
            .field("name", &self.core.name)
            .field("pending", &self.core.pending.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl LogWriter {
    /// Starts the writer thread for `out`. `name` identifies it in logs.
    pub fn spawn<W: Write + Send + 'static>(
        name: &'static str,
        out: W,
        opts: WriterOptions,
    ) -> io::Result<Self> {
        let core = Arc::new(Core {
            name,
            state: Mutex::new(State::default()),
            work: Condvar::new(),
            progress: Condvar::new(),
            pending: AtomicUsize::new(0),
            failing: AtomicBool::new(false),
            waiters: Mutex::new(Vec::new()),
            opts,
        });
        let c = core.clone();
        let thread = std::thread::Builder::new()
            .name(format!("roxy-log-{name}"))
            .spawn(move || run(&c, out))?;
        Ok(Self {
            core,
            thread: Mutex::new(Some(thread)),
        })
    }

    /// Queues `bytes` for writing. Never blocks on I/O and never drops;
    /// producers are held back through [`LogWriter::poll_ready`] instead.
    pub fn append(&self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let mut st = lock(&self.core.state);
        st.buf.extend_from_slice(bytes);
        self.core.pending.fetch_add(bytes.len(), Ordering::AcqRel);
        drop(st);
        self.core.work.notify_one();
    }

    /// `Ready` while the writer keeps up (unwritten bytes below the high
    /// water mark and no failing write); otherwise `Pending`, with `cx`
    /// woken once it is ready again.
    pub fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<()> {
        if self.core.ready() {
            return Poll::Ready(());
        }
        let mut waiters = lock(&self.core.waiters);
        // Re-check under the lock: the writer may have drained meanwhile.
        if self.core.ready() {
            return Poll::Ready(());
        }
        if !waiters.iter().any(|w| w.will_wake(cx.waker())) {
            waiters.push(cx.waker().clone());
        }
        Poll::Pending
    }

    /// Bytes appended but not yet written.
    pub fn pending(&self) -> usize {
        self.core.pending.load(Ordering::Acquire)
    }

    /// Waits (blocking, up to `flush_timeout`) until everything appended
    /// before the call is written. Returns whether it was.
    pub fn flush(&self) -> bool {
        let core = &self.core;
        let mut st = lock(&core.state);
        st.requested += 1;
        let target = st.requested;
        core.work.notify_one();
        let deadline = Instant::now() + core.opts.flush_timeout;
        while st.written < target {
            let now = Instant::now();
            if now >= deadline {
                tracing::warn!(sink = core.name, "flow log: flush timed out");
                return false;
            }
            st = core
                .progress
                .wait_timeout(st, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        true
    }
}

impl Drop for LogWriter {
    fn drop(&mut self) {
        lock(&self.core.state).closing = true;
        self.core.work.notify_one();
        if let Some(t) = lock(&self.thread).take() {
            let _ = t.join();
        }
    }
}

/// The writer thread.
fn run<W: Write>(core: &Core, mut out: W) {
    // If this thread dies, producers must not proceed as if logging worked.
    struct Dead<'a>(&'a Core);
    impl Drop for Dead<'_> {
        fn drop(&mut self) {
            if std::thread::panicking() {
                self.0.failing.store(true, Ordering::Release);
                tracing::error!(sink = self.0.name, "flow log writer died; traffic is held");
            }
        }
    }
    let _dead = Dead(core);
    let mut batch: Vec<u8> = Vec::new();
    loop {
        let (generation, closing) = {
            let mut st = lock(&core.state);
            while st.buf.is_empty() && !st.closing && st.written == st.requested {
                st = core.work.wait(st).unwrap_or_else(PoisonError::into_inner);
            }
            // Swap, keeping the old allocation for the next batch.
            std::mem::swap(&mut st.buf, &mut batch);
            (st.requested, st.closing)
        };
        if !batch.is_empty() {
            write_batch(core, &mut out, &batch);
            core.pending.fetch_sub(batch.len(), Ordering::AcqRel);
            batch.clear();
        }
        core.wake_waiters();
        {
            let mut st = lock(&core.state);
            st.written = st.written.max(generation);
            core.progress.notify_all();
            if closing && st.buf.is_empty() {
                st.written = st.requested;
                core.progress.notify_all();
                return;
            }
        }
    }
}

/// Writes all of `batch` and flushes, retrying the unwritten rest after an
/// error (never skipping, never duplicating).
fn write_batch<W: Write>(core: &Core, out: &mut W, batch: &[u8]) {
    let mut off = 0;
    let mut first_failure: Option<Instant> = None;
    loop {
        let r = (|| {
            while off < batch.len() {
                match out.write(&batch[off..]) {
                    Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
                    Ok(n) => off += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            out.flush()
        })();
        match r {
            Ok(()) => {
                if core.failing.swap(false, Ordering::AcqRel) {
                    tracing::warn!(sink = core.name, "flow log writes recovered");
                }
                return;
            }
            Err(error) => {
                if !core.failing.swap(true, Ordering::AcqRel) {
                    tracing::error!(sink = core.name, %error, "flow log write failed; holding traffic and retrying");
                }
                let since = *first_failure.get_or_insert_with(Instant::now);
                // At shutdown, do not hang forever on a dead destination.
                if lock(&core.state).closing && since.elapsed() >= core.opts.flush_timeout {
                    tracing::error!(
                        sink = core.name,
                        %error,
                        unwritten = batch.len() - off,
                        "flow log still failing at shutdown; giving up"
                    );
                    return;
                }
                std::thread::sleep(core.opts.retry_interval);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::task::Wake;

    /// A writer whose writes block until released and can be made to fail.
    #[derive(Clone)]
    struct Gate {
        out: Arc<Mutex<Vec<u8>>>,
        open: Arc<(Mutex<bool>, Condvar)>,
        fail: Arc<AtomicBool>,
    }

    impl Gate {
        fn new(open: bool) -> Self {
            Self {
                out: Arc::default(),
                open: Arc::new((Mutex::new(open), Condvar::new())),
                fail: Arc::default(),
            }
        }
        fn set_open(&self, v: bool) {
            *lock(&self.open.0) = v;
            self.open.1.notify_all();
        }
        fn written(&self) -> Vec<u8> {
            lock(&self.out).clone()
        }
    }

    impl Write for Gate {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            let mut open = lock(&self.open.0);
            while !*open {
                open = self.open.1.wait(open).unwrap();
            }
            drop(open);
            if self.fail.load(Ordering::Acquire) {
                return Err(io::Error::other("disk full"));
            }
            // Partial writes exercise the resume logic.
            let n = b.len().min(7);
            lock(&self.out).extend_from_slice(&b[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct Flag(mpsc::Sender<()>);
    impl Wake for Flag {
        fn wake(self: Arc<Self>) {
            let _ = self.0.send(());
        }
    }

    fn opts(high_water: usize) -> WriterOptions {
        WriterOptions {
            high_water,
            retry_interval: Duration::from_millis(5),
            flush_timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn writes_everything_in_order() {
        let g = Gate::new(true);
        let w = LogWriter::spawn("t", g.clone(), opts(1 << 20)).unwrap();
        let mut want = Vec::new();
        for i in 0..1000 {
            let line = format!("line {i}\n");
            want.extend_from_slice(line.as_bytes());
            w.append(line.as_bytes());
        }
        assert!(w.flush());
        assert_eq!(g.written(), want);
        assert_eq!(w.pending(), 0);
    }

    #[test]
    fn concurrent_appends_keep_lines_whole() {
        let g = Gate::new(true);
        let w = Arc::new(LogWriter::spawn("t", g.clone(), opts(1 << 20)).unwrap());
        let threads: Vec<_> = (0..8)
            .map(|t| {
                let w = w.clone();
                std::thread::spawn(move || {
                    for i in 0..500 {
                        w.append(format!("{t}:{i}\n").as_bytes());
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert!(w.flush());
        let text = String::from_utf8(g.written()).unwrap();
        assert_eq!(text.lines().count(), 4000);
        for t in 0..8 {
            let mine: Vec<usize> = text
                .lines()
                .filter_map(|l| l.strip_prefix(&format!("{t}:")))
                .map(|n| n.parse().unwrap())
                .collect();
            assert_eq!(mine, (0..500).collect::<Vec<_>>(), "per-thread order");
        }
    }

    #[test]
    fn backpressure_holds_producers_until_the_writer_catches_up() {
        let g = Gate::new(false);
        let w = LogWriter::spawn("t", g.clone(), opts(100)).unwrap();
        let (tx, rx) = mpsc::channel();
        let waker = Waker::from(Arc::new(Flag(tx)));
        let mut cx = Context::from_waker(&waker);
        assert!(w.poll_ready(&mut cx).is_ready());
        w.append(&[b'x'; 150]);
        assert!(
            w.poll_ready(&mut cx).is_pending(),
            "over the high water mark"
        );
        assert!(rx.try_recv().is_err());
        g.set_open(true);
        rx.recv_timeout(Duration::from_secs(5))
            .expect("woken once drained");
        assert!(w.poll_ready(&mut cx).is_ready());
        assert!(w.flush());
        assert_eq!(g.written().len(), 150);
    }

    #[test]
    fn failing_writes_hold_traffic_and_lose_nothing() {
        let g = Gate::new(true);
        g.fail.store(true, Ordering::Release);
        let w = LogWriter::spawn("t", g.clone(), opts(1 << 20)).unwrap();
        w.append(b"audit record\n");
        let (tx, rx) = mpsc::channel();
        let waker = Waker::from(Arc::new(Flag(tx)));
        let mut cx = Context::from_waker(&waker);
        // The writer notices the failure: readiness goes Pending.
        let deadline = Instant::now() + Duration::from_secs(5);
        while w.poll_ready(&mut cx).is_ready() {
            assert!(Instant::now() < deadline, "failure never held traffic");
            std::thread::sleep(Duration::from_millis(1));
        }
        g.fail.store(false, Ordering::Release);
        rx.recv_timeout(Duration::from_secs(5))
            .expect("woken on recovery");
        assert!(w.flush());
        assert_eq!(g.written(), b"audit record\n");
    }

    #[test]
    fn drop_writes_what_is_left() {
        let g = Gate::new(true);
        let w = LogWriter::spawn("t", g.clone(), opts(1 << 20)).unwrap();
        w.append(b"last words\n");
        drop(w);
        assert_eq!(g.written(), b"last words\n");
    }
}
