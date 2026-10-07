//! [`LogWriter`]: one writer thread per destination, batched writes, and
//! backpressure instead of loss. See the crate docs for the guarantees.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::Destination;

/// Tuning for a [`LogWriter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriterOptions {
    /// Unwritten bytes at which producers are held back.
    pub high_water: usize,
    /// Wait between attempts after a write (or rotation, or reopen) error.
    pub retry_interval: Duration,
    /// Longest [`LogWriter::flush`] waits, and how long a failing
    /// destination may hold up shutdown.
    pub flush_timeout: Duration,
    /// How long the writer waits for more records after the first one of
    /// a batch, so that one write carries a burst. A flush, reopen or
    /// shutdown cuts the wait short, as does a batch reaching
    /// `high_water / 64` bytes.
    pub linger: Duration,
}

/// Default [`WriterOptions::high_water`]: 8 MiB.
pub const DEFAULT_HIGH_WATER: usize = 8 << 20;

impl Default for WriterOptions {
    fn default() -> Self {
        Self {
            high_water: DEFAULT_HIGH_WATER,
            retry_interval: Duration::from_millis(500),
            flush_timeout: Duration::from_secs(10),
            linger: Duration::from_millis(2),
        }
    }
}

#[derive(Default)]
struct State {
    buf: Vec<u8>,
    closing: bool,
    /// Set by [`LogWriter::reopen`]; handled before the next batch.
    reopen: bool,
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
    /// Unwritten bytes at which the writer stops lingering and the next
    /// `append` wakes it.
    fn batch_bytes(&self) -> usize {
        self.opts.high_water / 64
    }

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

/// A buffered, single-writer destination. See the crate docs.
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
    /// Starts the writer thread for `dest`. `name` identifies it in logs.
    pub fn spawn<D: Destination>(
        name: &'static str,
        dest: D,
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
            .spawn(move || run(&c, dest))?;
        Ok(Self {
            core,
            thread: Mutex::new(Some(thread)),
        })
    }

    /// Queues `bytes` for writing. Never blocks on I/O and never drops;
    /// producers are held back through [`LogWriter::poll_ready`] instead.
    /// One call's bytes are written contiguously and never split across a
    /// rotation, so append whole records.
    pub fn append(&self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let Ok(()) = self.append_with(|buf| {
            buf.extend_from_slice(bytes);
            Ok::<(), std::convert::Infallible>(())
        });
    }

    /// [`LogWriter::append`] for a record produced straight into the
    /// buffer: `fill` appends it to `buf` and must not touch what is
    /// already there. It runs under the writer's lock, so it should only
    /// serialise, not block. If it fails (or panics) nothing is queued.
    pub fn append_with<E>(
        &self,
        fill: impl FnOnce(&mut Vec<u8>) -> Result<(), E>,
    ) -> Result<(), E> {
        let mut st = lock(&self.core.state);
        let before = st.buf.len();
        let mut record = Rollback {
            buf: &mut st.buf,
            start: before,
            keep: false,
        };
        fill(record.buf)?;
        record.keep = true;
        drop(record);
        let after = st.buf.len();
        self.core
            .pending
            .fetch_add(after - before, Ordering::AcqRel);
        drop(st);
        // The writer is woken by the first record of a batch and when the
        // batch gets large; between those it is already due to run.
        let batch = self.core.batch_bytes();
        if after > before && (before == 0 || (before < batch && after >= batch)) {
            self.core.work.notify_one();
        }
        Ok(())
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

    /// Whether the writer currently holds producers back.
    pub fn is_holding(&self) -> bool {
        !self.core.ready()
    }

    /// Bytes appended but not yet written.
    pub fn pending(&self) -> usize {
        self.core.pending.load(Ordering::Acquire)
    }

    /// Asks the writer to reopen its destination (after external log
    /// rotation) before the next batch. A failing reopen holds traffic and
    /// is retried like a failing write.
    pub fn reopen(&self) {
        lock(&self.core.state).reopen = true;
        self.core.work.notify_one();
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
                tracing::warn!(sink = core.name, "log flush timed out");
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

/// Truncates a half-written record unless `keep` is set, so a failed or
/// panicking producer never leaves part of one in the buffer.
struct Rollback<'a> {
    buf: &'a mut Vec<u8>,
    start: usize,
    keep: bool,
}

impl Drop for Rollback<'_> {
    fn drop(&mut self) {
        if !self.keep {
            self.buf.truncate(self.start);
        }
    }
}

/// The writer thread.
fn run<D: Destination>(core: &Core, mut dest: D) {
    // If this thread dies, producers must not proceed as if logging worked.
    struct Dead<'a>(&'a Core);
    impl Drop for Dead<'_> {
        fn drop(&mut self) {
            if std::thread::panicking() {
                self.0.failing.store(true, Ordering::Release);
                tracing::error!(sink = self.0.name, "log writer died; traffic is held");
            }
        }
    }
    let _dead = Dead(core);
    let mut batch: Vec<u8> = Vec::new();
    let urgent = |st: &State| st.closing || st.reopen || st.written != st.requested;
    loop {
        let (generation, closing, reopen) = {
            let mut st = lock(&core.state);
            while st.buf.is_empty() && !urgent(&st) {
                st = core.work.wait(st).unwrap_or_else(PoisonError::into_inner);
            }
            // Linger so one write carries a burst, unless the batch is
            // already large or something more pressing is wanted.
            let deadline = Instant::now() + core.opts.linger;
            while st.buf.len() < core.batch_bytes() && !urgent(&st) {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                st = core
                    .work
                    .wait_timeout(st, deadline - now)
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
            }
            // Swap, keeping the old allocation for the next batch.
            std::mem::swap(&mut st.buf, &mut batch);
            (st.requested, st.closing, std::mem::take(&mut st.reopen))
        };
        if reopen {
            retry(core, "reopen", || dest.reopen());
        }
        if !batch.is_empty() {
            let mut off = 0;
            retry(core, "write", || {
                while off < batch.len() {
                    match dest.write(&batch[off..]) {
                        Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
                        Ok(n) => off += n,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) => return Err(e),
                    }
                }
                // Batch boundary: flush, and rotate if due.
                dest.end_batch()
            });
            core.pending.fetch_sub(batch.len(), Ordering::AcqRel);
            batch.clear();
        }
        core.wake_waiters();
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

/// Runs `op` until it succeeds. While it fails, producers are held
/// (`failing`) and it is retried every `retry_interval`: nothing is skipped.
/// Only at shutdown, after `flush_timeout` of failures, does it give up.
fn retry(core: &Core, what: &str, mut op: impl FnMut() -> io::Result<()>) {
    let mut first_failure: Option<Instant> = None;
    loop {
        match op() {
            Ok(()) => {
                if core.failing.swap(false, Ordering::AcqRel) {
                    tracing::warn!(sink = core.name, what, "log destination recovered");
                }
                return;
            }
            Err(error) => {
                if !core.failing.swap(true, Ordering::AcqRel) {
                    tracing::error!(sink = core.name, what, %error, "log destination failing; holding traffic and retrying");
                }
                let since = *first_failure.get_or_insert_with(Instant::now);
                if lock(&core.state).closing && since.elapsed() >= core.opts.flush_timeout {
                    tracing::error!(sink = core.name, what, %error, "log destination still failing at shutdown; giving up");
                    return;
                }
                std::thread::sleep(core.opts.retry_interval);
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::Stream;
    use std::io::Write;
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

    pub(crate) fn opts(high_water: usize) -> WriterOptions {
        WriterOptions {
            high_water,
            retry_interval: Duration::from_millis(5),
            flush_timeout: Duration::from_secs(5),
            linger: Duration::from_millis(2),
        }
    }

    #[test]
    fn writes_everything_in_order() {
        let g = Gate::new(true);
        let w = LogWriter::spawn("t", Stream(g.clone()), opts(1 << 20)).unwrap();
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

    /// Counts batches: every [`Destination::end_batch`] is one write to the
    /// underlying file.
    #[derive(Clone, Default)]
    struct Batches {
        out: Arc<Mutex<Vec<u8>>>,
        batches: Arc<AtomicUsize>,
    }

    impl Destination for Batches {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            lock(&self.out).extend_from_slice(b);
            Ok(b.len())
        }
        fn end_batch(&mut self) -> io::Result<()> {
            self.batches.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn a_burst_of_records_is_one_write_in_order() {
        let d = Batches::default();
        let w = LogWriter::spawn(
            "t",
            d.clone(),
            WriterOptions {
                linger: Duration::from_secs(1),
                ..opts(1 << 20)
            },
        )
        .unwrap();
        let n = 200;
        let mut want = Vec::new();
        for i in 0..n {
            let line = format!("record {i}\n");
            want.extend_from_slice(line.as_bytes());
            w.append(line.as_bytes());
        }
        // A flush cuts the linger short: the batch is written now.
        assert!(w.flush());
        assert_eq!(*lock(&d.out), want);
        assert_eq!(
            d.batches.load(Ordering::SeqCst),
            1,
            "a burst within the linger is one batch"
        );
    }

    #[test]
    fn a_lone_record_is_written_within_the_linger() {
        let d = Batches::default();
        let linger = Duration::from_millis(2);
        let w = LogWriter::spawn(
            "t",
            d.clone(),
            WriterOptions {
                linger,
                ..opts(1 << 20)
            },
        )
        .unwrap();
        let start = Instant::now();
        w.append(b"only one\n");
        // Generous for a loaded CI machine; the failure this pins is a
        // record that waits for the next one, a flush or shutdown.
        let bound = linger * 50;
        while lock(&d.out).is_empty() {
            assert!(
                start.elapsed() < bound,
                "record not written within {bound:?}"
            );
            std::thread::sleep(Duration::from_micros(200));
        }
        assert_eq!(*lock(&d.out), b"only one\n");
        assert_eq!(d.batches.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn concurrent_appends_keep_lines_whole() {
        let g = Gate::new(true);
        let w = Arc::new(LogWriter::spawn("t", Stream(g.clone()), opts(1 << 20)).unwrap());
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
        let w = LogWriter::spawn("t", Stream(g.clone()), opts(100)).unwrap();
        let (tx, rx) = mpsc::channel();
        let waker = Waker::from(Arc::new(Flag(tx)));
        let mut cx = Context::from_waker(&waker);
        assert!(w.poll_ready(&mut cx).is_ready());
        w.append(&[b'x'; 150]);
        assert!(
            w.poll_ready(&mut cx).is_pending(),
            "over the high water mark"
        );
        assert!(w.is_holding());
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
        let w = LogWriter::spawn("t", Stream(g.clone()), opts(1 << 20)).unwrap();
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

    /// A destination that panics kills the writer thread. Producers must
    /// not carry on as if the log were being written: readiness turns
    /// Pending and stays there.
    #[test]
    fn a_writer_thread_panic_holds_traffic() {
        struct Panics;
        impl Write for Panics {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                panic!("destination blew up")
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let w = LogWriter::spawn("t", Stream(Panics), opts(1 << 20)).unwrap();
        let (tx, _rx) = mpsc::channel();
        let waker = Waker::from(Arc::new(Flag(tx)));
        let mut cx = Context::from_waker(&waker);
        assert!(w.poll_ready(&mut cx).is_ready());
        w.append(b"audit record\n");
        let deadline = Instant::now() + Duration::from_secs(5);
        while w.poll_ready(&mut cx).is_ready() {
            assert!(
                Instant::now() < deadline,
                "a dead writer never held traffic"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(w.is_holding());
        std::thread::sleep(Duration::from_millis(20));
        assert!(
            w.poll_ready(&mut cx).is_pending(),
            "nothing recovers a dead writer"
        );
    }

    #[test]
    fn drop_writes_what_is_left() {
        let g = Gate::new(true);
        let w = LogWriter::spawn("t", Stream(g.clone()), opts(1 << 20)).unwrap();
        w.append(b"last words\n");
        drop(w);
        assert_eq!(g.written(), b"last words\n");
    }
}
