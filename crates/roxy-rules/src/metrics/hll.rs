//! `HyperLogLog` sketches for `unique(<field>)`: one per window bucket,
//! exact while small, dense registers after [`SPARSE_MAX`] distinct values.

use super::budget::{Budget, Refused};
use super::window::Slot;

/// Bytes charged for one hash in a `unique` bucket's exact set.
pub(super) const HASH_BYTES: usize = size_of::<u64>();
/// Bytes charged for a dense `unique` bucket.
pub(super) const DENSE_BYTES: usize = HLL_M;
/// A `unique` bucket's exact set grows its capacity by this many entries at
/// a time, so its charge is exact (capacity × 8) without reallocating on
/// every insert.
pub(crate) const SPARSE_CHUNK: usize = 32;

const HLL_P: u32 = 12;
const HLL_M: usize = 1 << HLL_P;
const HLL_Q: u32 = 64 - HLL_P;
/// Distinct hashes kept exactly before a bucket switches to registers.
pub(super) const SPARSE_MAX: usize = 256;

type Registers = [u8; HLL_M];

/// A `HyperLogLog` sketch over pre-hashed 64-bit values: an exact sorted
/// hash set while small, dense registers after [`SPARSE_MAX`] values.
#[derive(Debug, Clone)]
pub(super) enum Hll {
    Sparse(Vec<u64>),
    Dense(Box<Registers>),
}

impl Default for Hll {
    fn default() -> Self {
        Self::Sparse(Vec::new())
    }
}

fn set_register(regs: &mut Registers, h: u64) {
    let idx = usize::try_from(h >> HLL_Q).unwrap_or(0);
    let w = h & ((1 << HLL_Q) - 1);
    let rho = if w == 0 {
        HLL_Q + 1
    } else {
        w.leading_zeros() - HLL_P + 1
    };
    let rho = u8::try_from(rho).unwrap_or(u8::MAX);
    if regs[idx] < rho {
        regs[idx] = rho;
    }
}

/// Bytes charged to / released from the budget by one change.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Change {
    pub added: usize,
    pub freed: usize,
}

impl Hll {
    /// Bytes this sketch is charged.
    pub(super) fn heap_bytes(&self) -> usize {
        match self {
            Self::Sparse(v) => v.capacity() * HASH_BYTES,
            Self::Dense(_) => DENSE_BYTES,
        }
    }

    /// Insert `h`, charging any growth to `budget` first. On `Err` the
    /// sketch is unchanged. The returned change has already been applied
    /// to `budget`.
    pub(super) fn insert(&mut self, h: u64, budget: &Budget) -> Result<Change, Refused> {
        match self {
            Self::Sparse(v) => match v.binary_search(&h) {
                Ok(_) => Ok(Change::default()),
                Err(i) if v.len() < SPARSE_MAX => {
                    let mut change = Change::default();
                    if v.len() == v.capacity() {
                        let want = SPARSE_CHUNK.min(SPARSE_MAX - v.len());
                        budget.take(want * HASH_BYTES)?;
                        let before = v.capacity();
                        v.reserve_exact(want);
                        change.added = (v.capacity() - before) * HASH_BYTES;
                        budget.settle(want * HASH_BYTES, change.added);
                    }
                    v.insert(i, h);
                    Ok(change)
                }
                Err(_) => {
                    let freed = v.capacity() * HASH_BYTES;
                    budget.take(DENSE_BYTES.saturating_sub(freed))?;
                    budget.give(freed.saturating_sub(DENSE_BYTES));
                    let mut regs = Box::new([0u8; HLL_M]);
                    for &x in v.iter() {
                        set_register(&mut regs, x);
                    }
                    set_register(&mut regs, h);
                    *self = Self::Dense(regs);
                    Ok(Change {
                        added: DENSE_BYTES,
                        freed,
                    })
                }
            },
            Self::Dense(regs) => {
                set_register(regs, h);
                Ok(Change::default())
            }
        }
    }
}

/// Cardinality of the union of `sketches`: exact if all are sparse,
/// otherwise the `HyperLogLog` estimate of the merged registers.
pub(super) fn cardinality<'a>(sketches: impl Iterator<Item = &'a Hll>) -> u64 {
    let mut exact: Vec<u64> = Vec::new();
    let mut dense: Option<Box<Registers>> = None;
    for s in sketches {
        match s {
            Hll::Sparse(v) => exact.extend_from_slice(v),
            Hll::Dense(r) => {
                let acc = dense.get_or_insert_with(|| Box::new([0u8; HLL_M]));
                for (a, b) in acc.iter_mut().zip(r.iter()) {
                    *a = (*a).max(*b);
                }
            }
        }
    }
    match dense {
        None => {
            exact.sort_unstable();
            exact.dedup();
            exact.len() as u64
        }
        Some(mut regs) => {
            for h in exact {
                set_register(&mut regs, h);
            }
            round_estimate(estimate(&regs))
        }
    }
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "a finite, non-negative estimate far below u64::MAX"
)]
fn round_estimate(e: f64) -> u64 {
    if e.is_finite() && e > 0.0 {
        e.round() as u64
    } else {
        0
    }
}

/// Ertl's improved raw estimator ("New cardinality estimation algorithms
/// for `HyperLogLog` sketches", 2017): unbiased over the whole range without
/// empirical correction tables.
fn estimate(regs: &Registers) -> f64 {
    let q = HLL_Q as usize;
    let mut hist = [0u32; HLL_Q as usize + 2];
    for &r in regs {
        hist[usize::from(r).min(q + 1)] += 1;
    }
    let m = f64::from(1u32 << HLL_P);
    let mut z = m * tau(1.0 - f64::from(hist[q + 1]) / m);
    for k in (1..=q).rev() {
        z = f64::midpoint(z, f64::from(hist[k]));
    }
    z += m * sigma(f64::from(hist[0]) / m);
    let alpha_inf = 0.5 / std::f64::consts::LN_2;
    alpha_inf * m * m / z
}

#[allow(
    clippy::float_cmp,
    reason = "fixed-point iteration ends when z stops changing"
)]
fn sigma(mut x: f64) -> f64 {
    if x == 1.0 {
        return f64::INFINITY;
    }
    let mut y = 1.0;
    let mut z = x;
    loop {
        x *= x;
        let prev = z;
        z += x * y;
        y += y;
        if z == prev {
            return z;
        }
    }
}

#[allow(
    clippy::float_cmp,
    reason = "fixed-point iteration ends when z stops changing"
)]
fn tau(mut x: f64) -> f64 {
    if x == 0.0 || x == 1.0 {
        return 0.0;
    }
    let mut y = 1.0;
    let mut z = 1.0 - x;
    loop {
        x = x.sqrt();
        let prev = z;
        y *= 0.5;
        z -= (1.0 - x).powi(2) * y;
        if z == prev {
            return z / 3.0;
        }
    }
}

impl Slot for Hll {
    fn clear(&mut self) -> usize {
        let freed = Hll::heap_bytes(self);
        *self = Self::default();
        freed
    }

    fn heap_bytes(&self) -> usize {
        Hll::heap_bytes(self)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::*;

    /// A fixed, well-mixed hash (splitmix64) so accuracy tests are
    /// deterministic.
    fn mix(mut x: u64) -> u64 {
        x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
        x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        x ^ (x >> 31)
    }

    fn ins(h: &mut Hll, x: u64) {
        static UNLIMITED: OnceLock<Budget> = OnceLock::new();
        h.insert(x, UNLIMITED.get_or_init(|| Budget::new(usize::MAX)))
            .unwrap();
    }

    #[test]
    fn hll_charges_match_capacity() {
        let b = Budget::new(usize::MAX);
        let mut h = Hll::default();
        let mut charged = 0usize;
        for i in 0..1_000 {
            let c = h.insert(mix(i), &b).unwrap();
            charged = charged + c.added - c.freed;
            assert_eq!(charged, h.heap_bytes(), "i={i}");
            assert_eq!(b.used(), charged);
            if let Hll::Sparse(v) = &h {
                assert!(v.capacity() <= SPARSE_MAX);
            }
        }
        assert_eq!(charged, DENSE_BYTES);
        assert_eq!(Slot::clear(&mut h), DENSE_BYTES);
    }

    #[test]
    fn hll_refused_growth_leaves_sketch_unchanged() {
        // Room for exactly one chunk.
        let b = Budget::new(SPARSE_CHUNK * HASH_BYTES);
        let mut h = Hll::default();
        for i in 0..SPARSE_CHUNK as u64 {
            h.insert(mix(i), &b).unwrap();
        }
        assert_eq!(h.insert(mix(9_999), &b), Err(Refused));
        assert_eq!(cardinality(std::iter::once(&h)), SPARSE_CHUNK as u64);
        // Values already present need no growth.
        assert!(h.insert(mix(0), &b).is_ok());
        assert_eq!(b.used(), SPARSE_CHUNK * HASH_BYTES);
    }

    fn count(n: u64) -> u64 {
        let mut h = Hll::default();
        for i in 0..n {
            ins(&mut h, mix(i));
            ins(&mut h, mix(i)); // duplicates do not count
        }
        cardinality(std::iter::once(&h))
    }

    #[test]
    #[allow(clippy::cast_precision_loss, reason = "test arithmetic")]
    fn hll_accuracy() {
        for n in 0..=SPARSE_MAX as u64 {
            assert_eq!(count(n), n, "exact below the sparse threshold");
        }
        for n in [257, 1_000, 3_000, 10_000, 30_000, 100_000, 1_000_000] {
            let e = count(n) as f64;
            let err = (e - n as f64).abs() / n as f64;
            assert!(err < 0.05, "n={n} estimate={e} err={err}");
        }
    }

    #[test]
    fn hll_merge_is_union() {
        let mut a = Hll::default();
        let mut b = Hll::default();
        for i in 0..5_000 {
            ins(&mut a, mix(i));
        }
        for i in 2_500..7_500 {
            ins(&mut b, mix(i));
        }
        let small = {
            let mut s = Hll::default();
            ins(&mut s, mix(1));
            ins(&mut s, mix(100_000));
            s
        };
        #[allow(clippy::cast_precision_loss, reason = "test arithmetic")]
        let e = cardinality([&a, &b, &small].into_iter()) as f64;
        assert!((e - 7_501.0).abs() / 7_501.0 < 0.05, "{e}");
        // Sparse-only unions are exact.
        let mut c = Hll::default();
        ins(&mut c, mix(1));
        ins(&mut c, mix(2));
        assert_eq!(cardinality([&small, &c].into_iter()), 3);
    }
}
