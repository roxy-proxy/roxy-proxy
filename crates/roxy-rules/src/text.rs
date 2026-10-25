//! `body.text` and `response.body.text` tests, decided as the body streams.
//!
//! A comparison of a body's text with a quoted string compiles to a
//! [`TextTest`]. The policy collects each direction's tests in a
//! [`TextTests`], and a [`TextScan`] runs them over one body, chunk by
//! chunk, holding only a few bytes of state per test. A test reads the
//! bytes of the body as decoded from its `content-encoding`, not a text
//! decoding of them; for a needle that is valid UTF-8 (every quoted string
//! is) this is the same answer as searching the text.
//!
//! Each test is undecided until the bytes settle it: `contains` once the
//! needle has been seen, `starts_with` once as many bytes as the needle has
//! arrived or one differs, `==` once a byte differs or there are too many,
//! and anything else when the body ends. While a test is undecided,
//! [`TextScan::hold`] says how many of the latest bytes must not be
//! forwarded yet, so that a rule matching on them can still stop them.

use std::sync::Arc;

/// Which body a text test reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BodySide {
    /// `body.text`.
    Request,
    /// `response.body.text`.
    Response,
}

impl BodySide {
    /// The field name.
    pub const fn field(self) -> &'static str {
        match self {
            Self::Request => "body.text",
            Self::Response => "response.body.text",
        }
    }
}

/// The comparison a text test makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum TextOp {
    Contains,
    StartsWith,
    EndsWith,
    Equals,
}

/// A comparison of a body's text with a literal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct TextTest {
    op: TextOp,
    needle: Box<[u8]>,
    /// For `contains` and `ends_with`, the prefix function of the needle:
    /// `border[k]` is the length of the longest proper prefix of
    /// `needle[..k]` that is also a suffix of it. It lets the scan follow
    /// every partial match at once, one step per byte.
    border: Box<[usize]>,
}

impl TextTest {
    pub(crate) fn new(op: TextOp, needle: &str) -> Self {
        let needle: Box<[u8]> = needle.as_bytes().into();
        let border = match op {
            TextOp::Contains | TextOp::EndsWith => borders(&needle),
            TextOp::StartsWith | TextOp::Equals => Box::default(),
        };
        Self { op, needle, border }
    }

    /// The test over a whole body.
    pub(crate) fn eval(&self, body: &[u8]) -> bool {
        let mut c = Cursor::new(self);
        c.feed(self, body);
        c.finish(self);
        c.result == Some(true)
    }

    /// The next partial-match length after `b`, from `k` bytes of the
    /// needle matched (the whole needle, for `ends_with`, once it is).
    fn step(&self, mut k: usize, b: u8) -> usize {
        if k == self.needle.len() {
            k = self.border[k];
        }
        while k > 0 && self.needle[k] != b {
            k = self.border[k];
        }
        if self.needle[k] == b { k + 1 } else { 0 }
    }
}

fn borders(needle: &[u8]) -> Box<[usize]> {
    let mut border = vec![0; needle.len() + 1];
    let mut k = 0;
    for i in 1..needle.len() {
        while k > 0 && needle[i] != needle[k] {
            k = border[k];
        }
        if needle[i] == needle[k] {
            k += 1;
        }
        border[i + 1] = k;
    }
    border.into()
}

/// One test's progress through a body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cursor {
    /// `contains`, `ends_with`: the longest suffix of the body so far that
    /// is a prefix of the needle. `starts_with`, `==`: the bytes matched,
    /// which is every byte so far while undecided.
    k: usize,
    result: Option<bool>,
}

impl Cursor {
    fn new(t: &TextTest) -> Self {
        // An empty needle is in every body, at its start and at its end.
        let decided = t.needle.is_empty() && t.op != TextOp::Equals;
        Self {
            k: 0,
            result: decided.then_some(true),
        }
    }

    fn feed(&mut self, t: &TextTest, bytes: &[u8]) {
        if self.result.is_some() {
            return;
        }
        let n = t.needle.len();
        match t.op {
            TextOp::Contains => {
                for &b in bytes {
                    self.k = t.step(self.k, b);
                    if self.k == n {
                        self.result = Some(true);
                        return;
                    }
                }
            }
            TextOp::EndsWith => {
                for &b in bytes {
                    self.k = t.step(self.k, b);
                }
            }
            TextOp::StartsWith | TextOp::Equals => {
                let take = bytes.len().min(n - self.k);
                if bytes[..take] != t.needle[self.k..self.k + take] {
                    self.result = Some(false);
                    return;
                }
                self.k += take;
                if t.op == TextOp::StartsWith && self.k == n {
                    self.result = Some(true);
                } else if take < bytes.len() {
                    // `==`: more bytes than the needle has.
                    self.result = Some(false);
                }
            }
        }
    }

    fn finish(&mut self, t: &TextTest) {
        if self.result.is_none() {
            self.result = Some(match t.op {
                TextOp::Contains | TextOp::StartsWith => false,
                TextOp::EndsWith | TextOp::Equals => self.k == t.needle.len(),
            });
        }
    }

    /// The latest bytes this test still needs held back: the partial
    /// match a rule matching on `true` waits on, and the last byte for a
    /// rule matching on `false`, which can be decided by the end alone.
    fn hold(&self, want: Want) -> usize {
        if self.result.is_some() {
            return 0;
        }
        let partial = if want.on_true { self.k } else { 0 };
        partial.max(usize::from(want.on_false))
    }
}

/// Which answers of a test some rule matches on, so which bytes are worth
/// holding back.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Want {
    pub on_true: bool,
    pub on_false: bool,
}

/// The text tests of one direction of a policy, each once.
#[derive(Debug, Default)]
pub struct TextTests {
    tests: Vec<(TextTest, Want)>,
}

impl TextTests {
    /// Whether no rule reads this body's text.
    pub fn is_empty(&self) -> bool {
        self.tests.is_empty()
    }

    /// How many distinct tests the rules make.
    pub fn len(&self) -> usize {
        self.tests.len()
    }

    /// The index of `test`, added if new.
    pub(crate) fn add(&mut self, test: &TextTest, want: Want) -> usize {
        if let Some(i) = self.tests.iter().position(|(t, _)| t == test) {
            let w = &mut self.tests[i].1;
            w.on_true |= want.on_true;
            w.on_false |= want.on_false;
            return i;
        }
        self.tests.push((test.clone(), want));
        self.tests.len() - 1
    }

    /// A scan of one body.
    pub fn scan(self: &Arc<Self>) -> TextScan {
        TextScan {
            cursors: self.tests.iter().map(|(t, _)| Cursor::new(t)).collect(),
            results: self
                .tests
                .iter()
                .map(|(t, _)| Cursor::new(t).result)
                .collect(),
            tests: self.clone(),
            seen: 0,
        }
    }
}

/// The text tests run over one body as it streams.
#[derive(Debug, Clone)]
pub struct TextScan {
    tests: Arc<TextTests>,
    cursors: Vec<Cursor>,
    /// Each test's answer, `None` while undecided; what the rules read.
    results: Vec<Option<bool>>,
    seen: u64,
}

impl TextScan {
    /// Feeds the next bytes of the body. Whether any test was decided.
    pub fn feed(&mut self, bytes: &[u8]) -> bool {
        self.seen += bytes.len() as u64;
        self.update(|c, t| c.feed(t, bytes))
    }

    /// The body ended: every test is decided. Whether any test was decided
    /// now.
    pub fn finish(&mut self) -> bool {
        self.update(Cursor::finish)
    }

    fn update(&mut self, f: impl Fn(&mut Cursor, &TextTest)) -> bool {
        let mut decided = false;
        for ((c, r), (t, _)) in self
            .cursors
            .iter_mut()
            .zip(&mut self.results)
            .zip(&self.tests.tests)
        {
            if r.is_none() {
                f(c, t);
                *r = c.result;
                decided |= r.is_some();
            }
        }
        decided
    }

    /// Each test's answer so far, by index; `None` while undecided.
    pub fn results(&self) -> &[Option<bool>] {
        &self.results
    }

    /// How many of the latest bytes fed must not be forwarded yet. It
    /// never grows by more than the bytes fed since it was last read, so
    /// the bytes it covers are always ones still held.
    pub fn hold(&self) -> usize {
        let hold = self
            .cursors
            .iter()
            .zip(&self.tests.tests)
            .map(|(c, (_, want))| c.hold(*want))
            .max()
            .unwrap_or(0);
        hold.min(usize::try_from(self.seen).unwrap_or(usize::MAX))
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const BOTH: Want = Want {
        on_true: true,
        on_false: true,
    };

    fn reference(op: TextOp, body: &[u8], needle: &[u8]) -> bool {
        match op {
            TextOp::Contains => {
                needle.is_empty() || body.windows(needle.len()).any(|w| w == needle)
            }
            TextOp::StartsWith => body.starts_with(needle),
            TextOp::EndsWith => body.ends_with(needle),
            TextOp::Equals => body == needle,
        }
    }

    const OPS: [TextOp; 4] = [
        TextOp::Contains,
        TextOp::StartsWith,
        TextOp::EndsWith,
        TextOp::Equals,
    ];

    #[test]
    fn whole_bodies() {
        for (op, body, needle, want) in [
            (TextOp::Contains, "xxBEGIN KEYxx", "BEGIN KEY", true),
            (TextOp::Contains, "aaab", "aab", true),
            (TextOp::Contains, "abab", "abb", false),
            (TextOp::Contains, "", "", true),
            (TextOp::StartsWith, "abc", "ab", true),
            (TextOp::StartsWith, "a", "ab", false),
            (TextOp::EndsWith, "xabab", "abab", true),
            (TextOp::EndsWith, "ababx", "abab", false),
            (TextOp::Equals, "", "", true),
            (TextOp::Equals, "ab", "a", false),
        ] {
            let t = TextTest::new(op, needle);
            assert_eq!(t.eval(body.as_bytes()), want, "{op:?} {body:?} {needle:?}");
        }
    }

    /// The hold covers a partial match, so a needle is never released
    /// whole before its test is decided.
    #[test]
    fn a_partial_match_is_held() {
        let mut tests = TextTests::default();
        tests.add(
            &TextTest::new(TextOp::Contains, "SECRET"),
            Want {
                on_true: true,
                on_false: false,
            },
        );
        let mut scan = Arc::new(tests).scan();
        assert!(!scan.feed(b"a SEC"));
        assert_eq!(scan.hold(), 3);
        assert!(!scan.feed(b"x"));
        assert_eq!(scan.hold(), 0);
        assert!(scan.feed(b"SECRET"));
        assert_eq!(scan.results(), [Some(true)]);
        assert_eq!(scan.hold(), 0);
    }

    /// A rule on `not contains` is decided by the end, so the last byte is
    /// held until then; one on `contains` holds nothing outside a partial
    /// match.
    #[test]
    fn a_test_wanted_false_holds_the_last_byte() {
        let test = TextTest::new(TextOp::Contains, "z");
        for (want, hold) in [
            (
                Want {
                    on_true: false,
                    on_false: true,
                },
                1,
            ),
            (
                Want {
                    on_true: true,
                    on_false: false,
                },
                0,
            ),
        ] {
            let mut tests = TextTests::default();
            tests.add(&test, want);
            let mut scan = Arc::new(tests).scan();
            assert_eq!(scan.hold(), 0, "nothing fed");
            scan.feed(b"abc");
            assert_eq!(scan.hold(), hold, "{want:?}");
            assert!(scan.finish());
            assert_eq!(scan.results(), [Some(false)]);
            assert_eq!(scan.hold(), 0);
        }
    }

    #[test]
    fn equal_tests_share_an_index() {
        let mut tests = TextTests::default();
        let a = tests.add(&TextTest::new(TextOp::Contains, "x"), Want::default());
        let b = tests.add(&TextTest::new(TextOp::EndsWith, "x"), Want::default());
        let c = tests.add(&TextTest::new(TextOp::Contains, "x"), BOTH);
        assert_eq!((a, b, c), (0, 1, 0));
        assert_eq!(tests.tests[0].1, BOTH);
    }

    fn body() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(prop::sample::select(b"ab\xff".to_vec()), 0..24)
    }

    proptest! {
        /// However the body is split, each test answers as it would on the
        /// whole body, and the hold never reaches back past what is still
        /// held.
        #[test]
        fn chunked_scans_match_the_whole_body(
            body in body(),
            needles in prop::collection::vec(body(), 1..4),
            cuts in prop::collection::vec(0usize..24, 0..6),
        ) {
            let mut tests = TextTests::default();
            let mut expect = Vec::new();
            for needle in &needles {
                // Needles are quoted strings, so valid UTF-8.
                let needle = String::from_utf8_lossy(needle);
                for op in OPS {
                    let i = tests.add(&TextTest::new(op, &needle), BOTH);
                    if i == expect.len() {
                        expect.push(reference(op, &body, needle.as_bytes()));
                    }
                }
            }
            let mut scan = Arc::new(tests).scan();
            let mut cuts: Vec<usize> = cuts.into_iter().map(|c| c.min(body.len())).collect();
            cuts.push(body.len());
            cuts.sort_unstable();
            let (mut from, mut held) = (0, 0);
            for to in cuts {
                scan.feed(&body[from..to]);
                held += to - from;
                let hold = scan.hold();
                prop_assert!(hold <= held, "hold {hold} > held {held}");
                held = hold;
                from = to;
            }
            scan.finish();
            let got: Vec<bool> = scan.results().iter().map(|r| r.unwrap()).collect();
            prop_assert_eq!(got, expect);
            prop_assert_eq!(scan.hold(), 0);
        }

        /// A test decided before the end gives the answer the whole body
        /// gives.
        #[test]
        fn an_early_answer_is_final(body in body(), needle in body()) {
            let needle = String::from_utf8_lossy(&needle);
            for op in OPS {
                let mut tests = TextTests::default();
                tests.add(&TextTest::new(op, &needle), BOTH);
                let mut scan = Arc::new(tests).scan();
                let mut early = scan.results()[0];
                for b in &body {
                    scan.feed(std::slice::from_ref(b));
                    early = early.or(scan.results()[0]);
                }
                let whole = reference(op, &body, needle.as_bytes());
                if let Some(e) = early {
                    prop_assert_eq!(e, whole);
                }
            }
        }
    }
}
