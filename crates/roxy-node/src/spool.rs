//! The flow spool: flow-log lines tagged with `seq`, held in memory until
//! the control plane acknowledges them. Bounded by the lease's
//! `spool_high_water_bytes`; what happens past that is the lease's
//! `on_high_water`: `hold` reports not-ready so traffic waits, `spool`
//! drops the oldest.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

use crate::protocol::{FlowSettings, OnHighWater};

/// How many `seq` values are reserved (persisted) at a time. A restart
/// skips to the end of the last block, so the gap is at most this.
pub const SEQ_BLOCK: u64 = 1024;

/// Settings before the first lease: spool, bounded, never hold traffic
/// for a control plane that has not spoken yet.
pub const BOOTSTRAP_SETTINGS: FlowSettings = FlowSettings {
    ship: true,
    batch_max_bytes: 1 << 20,
    flush_interval_seconds: 5,
    spool_high_water_bytes: 8 << 20,
    on_high_water: OnHighWater::Spool,
};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Debug)]
struct Spooled {
    seq: u64,
    /// One JSON object, `seq` included, no trailing newline.
    line: Vec<u8>,
}

#[derive(Debug, Default)]
struct Queue {
    events: VecDeque<Spooled>,
    bytes: u64,
    /// The next `seq` to assign.
    next_seq: u64,
    /// `seq` values below this are persisted as used.
    reserved_through: u64,
}

/// A batch handed to the shipper. Its events stay in the spool until
/// [`Spool::ack`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    pub seq_first: u64,
    pub seq_last: u64,
    pub lines: Vec<Vec<u8>>,
    pub bytes: u64,
}

/// Persists the reserved `seq` high mark; see [`SEQ_BLOCK`].
pub type SeqStore = Box<dyn Fn(u64) -> Result<(), String> + Send + Sync>;

/// The bounded, acknowledged queue of flow lines.
pub struct Spool {
    queue: Mutex<Queue>,
    settings: Mutex<FlowSettings>,
    waiters: Mutex<Vec<Waker>>,
    /// Wakes the shipper when there is something new to send.
    pub(crate) pushed: tokio::sync::Notify,
    bytes: AtomicU64,
    /// Set while the spool is dropping (`spool` mode past the high water),
    /// so the loss is logged once per episode rather than per event.
    dropping: AtomicBool,
    dropped_total: AtomicU64,
    /// Shipping has ended (quota exhausted, or revoked and drained): new
    /// events are not spooled.
    closed: AtomicBool,
    persist: SeqStore,
}

impl std::fmt::Debug for Spool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Spool")
            .field("bytes", &self.bytes.load(Ordering::Relaxed))
            .field("settings", &*lock(&self.settings))
            .finish_non_exhaustive()
    }
}

impl Spool {
    /// A spool whose first `seq` is `first_seq` (the end of the last
    /// reserved block), persisting reservations through `persist`.
    pub fn new(first_seq: u64, persist: SeqStore) -> Self {
        Self {
            queue: Mutex::new(Queue {
                next_seq: first_seq,
                reserved_through: first_seq,
                ..Queue::default()
            }),
            settings: Mutex::new(BOOTSTRAP_SETTINGS),
            waiters: Mutex::new(Vec::new()),
            pushed: tokio::sync::Notify::new(),
            bytes: AtomicU64::new(0),
            dropping: AtomicBool::new(false),
            dropped_total: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            persist,
        }
    }

    pub fn settings(&self) -> FlowSettings {
        *lock(&self.settings)
    }

    /// Applies a lease's flow settings. A lower high water in `spool` mode
    /// drops down to it at once; in `hold` mode the next `poll_ready`
    /// holds until the shipper catches up.
    pub fn configure(&self, settings: FlowSettings) {
        *lock(&self.settings) = settings;
        if settings.on_high_water == OnHighWater::Spool {
            let mut q = lock(&self.queue);
            self.drop_to(&mut q, settings.spool_high_water_bytes);
        }
        self.wake();
        self.pushed.notify_one();
    }

    /// Stops spooling new events. Already spooled ones stay for draining.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.wake();
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Bytes spooled and not yet acknowledged.
    pub fn pending_bytes(&self) -> u64 {
        self.bytes.load(Ordering::Acquire)
    }

    pub fn pending_events(&self) -> usize {
        lock(&self.queue).events.len()
    }

    /// Events dropped in `spool` mode since start.
    pub fn dropped(&self) -> u64 {
        self.dropped_total.load(Ordering::Relaxed)
    }

    /// Spools one flow-log line (a JSON object, with or without the
    /// trailing newline), tagging it with the next `seq`. Never blocks;
    /// over the high water it holds (`hold`) through [`Spool::poll_ready`]
    /// or drops the oldest (`spool`).
    pub fn push(&self, line: &[u8]) {
        let settings = self.settings();
        if !settings.ship || self.is_closed() {
            return;
        }
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        let Some(rest) = line.strip_prefix(b"{") else {
            tracing::warn!("flow spool: not a JSON object; dropped");
            return;
        };
        let mut q = lock(&self.queue);
        let seq = q.next_seq;
        q.next_seq += 1;
        if q.next_seq > q.reserved_through {
            let through = q.next_seq + SEQ_BLOCK;
            if let Err(e) = (self.persist)(through) {
                tracing::error!(error = %e, "flow spool: cannot persist the sequence counter; a restart may reuse sequence numbers");
            }
            q.reserved_through = through;
        }
        let mut tagged = Vec::with_capacity(line.len() + 24);
        tagged.extend_from_slice(format!("{{\"seq\":{seq}").as_bytes());
        if !rest.is_empty() && rest != b"}" {
            tagged.push(b',');
        }
        tagged.extend_from_slice(rest);
        let len = tagged.len() as u64;
        q.events.push_back(Spooled { seq, line: tagged });
        q.bytes += len;
        if settings.on_high_water == OnHighWater::Spool {
            self.drop_to(&mut q, settings.spool_high_water_bytes);
        }
        self.bytes.store(q.bytes, Ordering::Release);
        drop(q);
        self.pushed.notify_one();
    }

    /// Drops the oldest events until the spool is within `limit`, logging
    /// the first drop of an episode.
    fn drop_to(&self, q: &mut Queue, limit: u64) {
        let mut dropped = 0u64;
        while q.bytes > limit {
            let Some(oldest) = q.events.pop_front() else {
                break;
            };
            q.bytes -= oldest.line.len() as u64;
            dropped += 1;
        }
        self.bytes.store(q.bytes, Ordering::Release);
        if dropped > 0 {
            self.dropped_total.fetch_add(dropped, Ordering::Relaxed);
            if !self.dropping.swap(true, Ordering::AcqRel) {
                tracing::warn!(
                    high_water_bytes = limit,
                    "flow spool over its high water with on_high_water=spool; dropping the oldest unshipped events until it drains"
                );
            }
        }
    }

    /// `Ready` unless the spool is at its high water in `hold` mode, in
    /// which case `cx` is woken when an ack brings it back under.
    pub fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<()> {
        if self.ready() {
            return Poll::Ready(());
        }
        let mut waiters = lock(&self.waiters);
        if self.ready() {
            return Poll::Ready(());
        }
        if !waiters.iter().any(|w| w.will_wake(cx.waker())) {
            waiters.push(cx.waker().clone());
        }
        Poll::Pending
    }

    /// Whether traffic is being held.
    pub fn is_holding(&self) -> bool {
        !self.ready()
    }

    fn ready(&self) -> bool {
        let settings = self.settings();
        settings.on_high_water != OnHighWater::Hold
            || !settings.ship
            || self.is_closed()
            || self.pending_bytes() < settings.spool_high_water_bytes
    }

    fn wake(&self) {
        if self.ready() {
            for w in std::mem::take(&mut *lock(&self.waiters)) {
                w.wake();
            }
        }
    }

    /// The oldest unacknowledged events, up to `max_bytes` of lines (at
    /// least one). `None` when empty.
    pub fn batch(&self, max_bytes: u64) -> Option<Batch> {
        let q = lock(&self.queue);
        let first = q.events.front()?;
        let mut lines = vec![first.line.clone()];
        let mut bytes = first.line.len() as u64;
        let (seq_first, mut seq_last) = (first.seq, first.seq);
        for e in q.events.iter().skip(1) {
            let len = e.line.len() as u64;
            if bytes + len > max_bytes {
                break;
            }
            lines.push(e.line.clone());
            bytes += len;
            seq_last = e.seq;
        }
        Some(Batch {
            seq_first,
            seq_last,
            lines,
            bytes,
        })
    }

    /// Drops every event with `seq <= through`.
    pub fn ack(&self, through: u64) {
        let mut q = lock(&self.queue);
        while let Some(front) = q.events.front() {
            if front.seq > through {
                break;
            }
            let len = front.line.len() as u64;
            q.events.pop_front();
            q.bytes -= len;
        }
        self.bytes.store(q.bytes, Ordering::Release);
        let under = q.bytes < self.settings().spool_high_water_bytes;
        drop(q);
        if under {
            self.dropping.store(false, Ordering::Release);
        }
        self.wake();
    }

    /// The next `seq` that will be assigned.
    pub fn next_seq(&self) -> u64 {
        lock(&self.queue).next_seq
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;

    use super::*;

    fn spool(first: u64) -> (Spool, Arc<AtomicU64>) {
        let persisted = Arc::new(AtomicU64::new(0));
        let p = persisted.clone();
        let spool = Spool::new(
            first,
            Box::new(move |n| {
                p.store(n, Ordering::Relaxed);
                Ok(())
            }),
        );
        (spool, persisted)
    }

    fn with(spool: &Spool, high_water: u64, mode: OnHighWater) {
        spool.configure(FlowSettings {
            spool_high_water_bytes: high_water,
            on_high_water: mode,
            ..BOOTSTRAP_SETTINGS
        });
    }

    fn ready(spool: &Spool) -> bool {
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        spool.poll_ready(&mut cx).is_ready()
    }

    #[test]
    fn events_are_tagged_with_contiguous_seq_and_blocks_are_persisted() {
        let (s, persisted) = spool(2048);
        s.push(b"{\"event\":\"a\"}\n");
        s.push(b"{}");
        assert_eq!(s.next_seq(), 2050);
        let b = s.batch(1 << 20).unwrap();
        assert_eq!((b.seq_first, b.seq_last), (2048, 2049));
        assert_eq!(b.lines[0], b"{\"seq\":2048,\"event\":\"a\"}");
        assert_eq!(b.lines[1], b"{\"seq\":2049}");
        // The first push past the reserved mark reserves the next block.
        assert_eq!(persisted.load(Ordering::Relaxed), 2049 + SEQ_BLOCK);
        s.ack(2048);
        assert_eq!(s.pending_events(), 1);
        assert_eq!(s.batch(1 << 20).unwrap().seq_first, 2049);
        s.ack(5000);
        assert!(s.batch(1 << 20).is_none());
        assert_eq!(s.pending_bytes(), 0);
    }

    #[test]
    fn a_batch_respects_the_byte_cap_but_always_carries_one_event() {
        let (s, _) = spool(0);
        for _ in 0..10 {
            s.push(br#"{"k":"0123456789"}"#);
        }
        let line_len = s.batch(1).unwrap().bytes;
        assert_eq!(s.batch(1).unwrap().lines.len(), 1, "never empty");
        assert_eq!(s.batch(line_len * 2 + 1).unwrap().lines.len(), 2);
        assert_eq!(s.batch(1 << 20).unwrap().lines.len(), 10);
    }

    #[test]
    fn hold_mode_reports_not_ready_at_the_high_water_until_acked() {
        let (s, _) = spool(0);
        with(&s, 40, OnHighWater::Hold);
        let line = br#"{"k":"0123456789"}"#; // 25 bytes with the seq tag
        s.push(line);
        assert!(ready(&s));
        s.push(line);
        assert!(!ready(&s), "at or over the high water holds");
        assert!(s.is_holding());
        assert_eq!(s.pending_events(), 2, "hold never drops");
        s.ack(0);
        assert!(ready(&s));
        // Switching to spool mode trims and releases.
        s.push(line);
        s.push(line);
        assert!(!ready(&s));
        with(&s, 40, OnHighWater::Spool);
        assert!(ready(&s));
        assert_eq!(s.pending_events(), 1);
    }

    #[test]
    fn spool_mode_drops_the_oldest_and_counts_them() {
        let (s, _) = spool(0);
        with(&s, 60, OnHighWater::Spool);
        for i in 0..5 {
            s.push(format!(r#"{{"k":"01234567{i}"}}"#).as_bytes());
        }
        assert!(ready(&s), "spool mode never holds");
        assert!(s.pending_bytes() <= 60);
        let b = s.batch(1 << 20).unwrap();
        assert_eq!(b.seq_first, 5 - b.lines.len() as u64, "the newest survive");
        assert_eq!(s.dropped(), 5 - b.lines.len() as u64);
        assert_eq!(s.next_seq(), 5, "dropped events keep their seq");
    }

    #[test]
    fn ship_false_and_closed_spool_nothing() {
        let (s, _) = spool(0);
        s.configure(FlowSettings {
            ship: false,
            ..BOOTSTRAP_SETTINGS
        });
        s.push(b"{}");
        assert_eq!(s.pending_events(), 0);
        assert_eq!(s.next_seq(), 0, "unshipped events take no seq");
        with(&s, 1 << 20, OnHighWater::Hold);
        s.push(b"{}");
        assert_eq!(s.pending_events(), 1);
        s.close();
        s.push(b"{}");
        assert_eq!(s.pending_events(), 1, "closed: not spooled");
        assert!(ready(&s), "a closed spool never holds traffic");
    }
}
