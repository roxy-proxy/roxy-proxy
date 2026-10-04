//! Bucket geometry and the ring of buckets behind a windowed series.

use std::time::Duration;

/// Buckets per window.
const BUCKETS: u64 = 60;
/// Smallest bucket width.
const MIN_BUCKET_NS: u64 = 1_000_000;

/// Bucket layout of a windowed metric. Times are signed nanoseconds since
/// the store's origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Geometry {
    pub width: i64,
    /// Buckets covering the window; `n + 1` are kept (plus the partial one).
    pub n: i64,
}

impl Geometry {
    pub(super) fn new(window: Duration) -> Self {
        let d = u64::try_from(window.as_nanos())
            .unwrap_or(u64::MAX)
            .clamp(1, i64::MAX.unsigned_abs());
        let width = d.div_ceil(BUCKETS).max(MIN_BUCKET_NS);
        let n = d.div_ceil(width).max(1);
        Self {
            width: i64::try_from(width).unwrap_or(i64::MAX),
            n: i64::try_from(n).unwrap_or(1),
        }
    }

    pub(super) fn bucket(self, t: i64) -> i64 {
        t.div_euclid(self.width)
    }
}

pub(super) trait Slot: Default + Clone {
    /// Reset; returns the heap bytes released (as charged).
    fn clear(&mut self) -> usize;
    /// Heap bytes charged for this slot beyond its inline size.
    fn heap_bytes(&self) -> usize;
}

impl Slot for u64 {
    fn clear(&mut self) -> usize {
        *self = 0;
        0
    }

    fn heap_bytes(&self) -> usize {
        0
    }
}

/// A ring of buckets. `head` is the bucket number of the newest slot;
/// cumulative metrics use one slot and ignore `head`.
#[derive(Debug, Clone)]
pub(super) struct Window<T> {
    head: i64,
    slots: Box<[T]>,
}

fn ring_index(bucket: i64, len: usize) -> usize {
    let len_i = i64::try_from(len).unwrap_or(i64::MAX);
    usize::try_from(bucket.rem_euclid(len_i)).unwrap_or(0)
}

impl<T: Slot> Window<T> {
    pub(super) fn new(geom: Option<Geometry>, now: i64) -> Self {
        let (len, head) = match geom {
            Some(g) => (usize::try_from(g.n + 1).unwrap_or(1), g.bucket(now)),
            None => (1, 0),
        };
        Self {
            head,
            slots: vec![T::default(); len].into_boxed_slice(),
        }
    }

    /// The slot for an event at `now`, rotating out expired buckets. An
    /// event "before" `head` (clock skew across a reload) goes into the head
    /// bucket, which only makes it live longer. Also returns the bytes
    /// released by the rotation.
    pub(super) fn current(&mut self, geom: Option<Geometry>, now: i64) -> (&mut T, usize) {
        let len = self.slots.len();
        let Some(g) = geom else {
            return (&mut self.slots[0], 0);
        };
        let b = g.bucket(now);
        let mut freed = 0;
        if b > self.head {
            let steps = (b - self.head).min(g.n + 1);
            for k in 1..=steps {
                freed += self.slots[ring_index(self.head + k, len)].clear();
            }
            self.head = b;
        }
        (&mut self.slots[ring_index(self.head, len)], freed)
    }

    /// Bytes charged for the bucket array and every bucket's contents.
    pub(super) fn bytes(&self) -> usize {
        size_of_val::<[T]>(&self.slots) + self.slots.iter().map(T::heap_bytes).sum::<usize>()
    }

    /// Buckets still inside the window at `now`.
    pub(super) fn live(&self, geom: Option<Geometry>, now: i64) -> impl Iterator<Item = &T> {
        let len = self.slots.len();
        let oldest = geom.map_or(i64::MIN, |g| g.bucket(now) - g.n);
        let head = self.head;
        (0..len).filter_map(move |k| {
            let b = head - i64::try_from(k).unwrap_or(0);
            (b >= oldest).then(|| &self.slots[ring_index(b, len)])
        })
    }

    /// Every bucket has left the window (never true for cumulative).
    pub(super) fn expired(&self, geom: Option<Geometry>, now: i64) -> bool {
        geom.is_some_and(|g| self.head < g.bucket(now) - g.n)
    }

    /// Move to a store whose clock origin is `shift` ns earlier (event at
    /// old time `t` is at new time `t + shift`). Rounds to the later bucket.
    pub(super) fn shift(&mut self, geom: Option<Geometry>, shift: i64) {
        if let Some(g) = geom {
            let whole = shift.div_euclid(g.width) + i64::from(shift.rem_euclid(g.width) != 0);
            self.head = self.head.saturating_add(whole);
            // Keep bucket b in ring slot b mod len.
            let len = self.slots.len();
            self.slots.rotate_right(ring_index(whole, len));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geometry() {
        let g = Geometry::new(Duration::from_secs(60));
        assert_eq!((g.width, g.n), (1_000_000_000, 60));
        let g = Geometry::new(Duration::from_millis(10));
        assert_eq!((g.width, g.n), (1_000_000, 10));
        let g = Geometry::new(Duration::from_nanos(1));
        assert_eq!((g.width, g.n), (1_000_000, 1));
    }

    #[test]
    fn window_shift_rounds_later() {
        let g = Some(Geometry::new(Duration::from_secs(60)));
        let mut w: Window<u64> = Window::new(g, 0);
        *w.current(g, 0).0 += 1;
        w.shift(g, -1); // within the bucket: rounds to the later one
        assert_eq!(w.head, 0);
        w.shift(g, -1_500_000_000);
        assert_eq!(w.head, -1);
        assert_eq!(w.live(g, -1).copied().sum::<u64>(), 1);
        assert_eq!(w.slots[ring_index(-1, w.slots.len())], 1);
        w.shift(g, 1);
        assert_eq!(w.head, 0);
        assert_eq!(w.slots[0], 1);
    }
}
