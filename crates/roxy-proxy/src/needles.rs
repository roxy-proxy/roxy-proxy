//! Secret values to find and mask: the one matcher behind the flow log's
//! redaction and the masking of responses. Each byte of an occurrence
//! becomes [`MASK`], so a masked string keeps its length.

use std::borrow::Cow;

/// What each byte of a secret becomes.
pub const MASK: u8 = b'*';

/// A set of secret values. `Debug` prints only a count.
#[derive(Clone, Default)]
pub struct Needles {
    values: Vec<String>,
}

impl std::fmt::Debug for Needles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Needles")
            .field("values", &self.values.len())
            .finish()
    }
}

impl Needles {
    /// Adds a value. Empty and repeated values are ignored.
    pub fn add(&mut self, value: impl Into<String>) {
        let value = value.into();
        if !value.is_empty() && !self.values.contains(&value) {
            self.values.push(value);
        }
    }

    /// Whether there is nothing to find.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// The length of the longest value; 0 with none.
    pub fn longest(&self) -> usize {
        self.values.iter().map(String::len).max().unwrap_or(0)
    }

    /// Where the values occur in `b`, overlapping and adjoining occurrences
    /// merged, in order.
    pub fn ranges(&self, b: &[u8]) -> Vec<(usize, usize)> {
        let mut ranges: Vec<(usize, usize)> = Vec::new();
        for value in &self.values {
            let finder = memchr::memmem::Finder::new(value.as_bytes());
            // Every start position, overlapping ones included.
            let mut from = 0;
            while let Some(i) = finder.find(&b[from..]) {
                let start = from + i;
                ranges.push((start, start + value.len()));
                from = start + 1;
            }
        }
        ranges.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
        for (start, end) in ranges {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        merged
    }

    /// The length of the longest suffix of `b` that is a proper prefix of
    /// a value: bytes that may begin a value whose rest has not arrived
    /// yet.
    pub fn partial_suffix(&self, b: &[u8]) -> usize {
        self.values
            .iter()
            .filter_map(|value| {
                let value = value.as_bytes();
                (1..value.len().min(b.len() + 1))
                    .rev()
                    .find(|&k| b.ends_with(&value[..k]))
            })
            .max()
            .unwrap_or(0)
    }

    /// `b` with every occurrence masked.
    pub fn mask_bytes<'a>(&self, b: &'a [u8]) -> Cow<'a, [u8]> {
        let ranges = self.ranges(b);
        if ranges.is_empty() {
            return Cow::Borrowed(b);
        }
        let mut out = b.to_vec();
        mask(&mut out, &ranges);
        Cow::Owned(out)
    }

    /// `s` with every occurrence masked.
    pub fn mask_str<'a>(&self, s: &'a str) -> Cow<'a, str> {
        match self.mask_bytes(s.as_bytes()) {
            Cow::Borrowed(_) => Cow::Borrowed(s),
            // A value is whole UTF-8, so in UTF-8 text it matches only on
            // char boundaries, and the mask is ASCII.
            Cow::Owned(b) => Cow::Owned(
                String::from_utf8(b).expect("masking UTF-8 on char boundaries keeps it UTF-8"),
            ),
        }
    }
}

/// Masks every byte of `b` inside `ranges`.
fn mask(b: &mut [u8], ranges: &[(usize, usize)]) {
    for &(start, end) in ranges {
        b[start..end].fill(MASK);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn needles(values: &[&str]) -> Needles {
        let mut n = Needles::default();
        for v in values {
            n.add(*v);
        }
        n
    }

    #[test]
    fn masks_every_occurrence_byte_for_byte() {
        let n = needles(&["sk-live-123", ""]);
        assert!(matches!(n.mask_str("nothing here"), Cow::Borrowed(_)));
        assert_eq!(
            n.mask_str("Bearer sk-live-123 and sk-live-123!"),
            "Bearer *********** and ***********!"
        );
    }

    #[test]
    fn overlapping_occurrences_are_one_run() {
        let n = needles(&["abcd", "cdef", "aa"]);
        assert_eq!(n.mask_str("xabcdefx"), "x******x");
        assert_eq!(n.mask_str("aaa"), "***");
        assert_eq!(n.mask_str("é-abcd-é"), "é-****-é");
    }

    #[test]
    fn a_partial_suffix_is_a_prefix_of_a_value() {
        let n = needles(&["sk-live-123", "ghp_"]);
        assert_eq!(n.partial_suffix(b"data: sk-li"), 5);
        assert_eq!(n.partial_suffix(b"x gh"), 2);
        assert_eq!(n.partial_suffix(b"data\n\n"), 0);
        // A whole value is not partial.
        assert_eq!(n.partial_suffix(b"ghp_"), 0);
    }
}
