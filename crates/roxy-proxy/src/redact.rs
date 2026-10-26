//! Scrubbing injected secrets from a response on its way to the client
//! (`http.redact_response_secrets`).
//!
//! An exchange scrubs the values its own `set_header` effects put into the
//! request, and nothing else: those are what its upstream holds that the
//! client was never given. Each occurrence is masked with [`MASK`] byte for
//! byte, so a plain body keeps its length. The stage runs in the core,
//! after the response rules, the in-flight byte counts and the capture
//! tap, which all see the response as the upstream sent it, and before
//! the addon layers and the client. An encoded body is decoded for it by
//! [`crate::recode`], and encoded again on its way to the client.
//!
//! Matching is literal, so this stops a verbatim echo only: a value the
//! upstream transforms (base64, escaping, a change of case) passes.

use std::borrow::Cow;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue};
use http_body::Frame;
use roxy_http::{Body, BodyError, CanonicalResponse, Headers};

use crate::config::ResponseRedaction;
use crate::needles::{MASK, Needles};
use crate::pipeline::{FlowCx, response_known_empty};
use crate::quarantine::{QuarantineCause, ResponsePart as Part};
use crate::server::Shared;

/// The values this exchange's response is masked for: those its own
/// `set_header` effects injected. `None` when nothing is to be masked.
pub(crate) fn needles(cx: &FlowCx) -> Option<Arc<Needles>> {
    let switches = cx.snap.http.redact_response_secrets;
    if !(switches.headers || switches.bodies) {
        return None;
    }
    // A short value would mask unrelated bytes wherever it happens to
    // occur, so values under `min_length` are left alone.
    let mut needles = Needles::default();
    for value in cx
        .injected
        .iter()
        .filter(|v| v.len() >= switches.min_length)
    {
        needles.add(value.clone());
    }
    (!needles.is_empty()).then(|| Arc::new(needles))
}

/// Whether this exchange's response body is masked. Such a response is
/// read whole: [`crate::recode::request_whole`] keeps a range from being
/// asked for.
pub(crate) fn masks_body(cx: &FlowCx) -> bool {
    cx.snap.http.redact_response_secrets.bodies && needles(cx).is_some()
}

/// Masks `needles` in `res` as `http.redact_response_secrets` asks. With
/// `bodies` on, the body is plain bytes by now: [`crate::recode`] decoded
/// it or refused it.
pub(crate) fn response(cx: &FlowCx, res: &mut CanonicalResponse, needles: Arc<Needles>) {
    let switches = cx.snap.http.redact_response_secrets;
    let alarm = Alarm {
        shared: switches.quarantine.then(|| cx.shared.clone()),
        flow: cx.flow.to_string(),
    };
    if switches.headers && mask_headers(&needles, &mut res.headers) {
        alarm.raise(Part::Headers);
    }
    if response_known_empty(cx, res) {
        return;
    }
    let body = std::mem::take(&mut res.body);
    res.body = MaskedBody::wrap(body, needles, switches, alarm);
}

/// Masks every value in `headers`; whether any held a secret.
fn mask_headers(needles: &Needles, headers: &mut Headers) -> bool {
    let mut found = false;
    headers.replace_values(|v| {
        let new = mask_value(needles, v)?;
        found = true;
        Some(new)
    });
    found
}

/// Masks every value in a trailer block; whether any held a secret.
fn mask_trailers(needles: &Needles, trailers: &mut HeaderMap) -> bool {
    let mut found = false;
    for v in trailers.values_mut() {
        if let Some(new) = mask_value(needles, v) {
            *v = new;
            found = true;
        }
    }
    found
}

/// `v` masked, or `None` when it holds no secret.
fn mask_value(needles: &Needles, v: &HeaderValue) -> Option<HeaderValue> {
    let Cow::Owned(b) = needles.mask_bytes(v.as_bytes()) else {
        return None;
    };
    // A valid value with some bytes swapped for visible ASCII is valid.
    Some(HeaderValue::from_bytes(&b).expect("a masked header value stays valid"))
}

/// Reports a secret found in a response, and quarantines the process
/// when `http.redact_response_secrets.quarantine` is on.
struct Alarm {
    shared: Option<Arc<Shared>>,
    flow: String,
}

impl Alarm {
    fn raise(&self, part: Part) {
        tracing::warn!(flow = %self.flow, ?part, "injected secret found in the response; masked");
        if let Some(shared) = &self.shared {
            shared.trip_quarantine(QuarantineCause::SecretInResponse {
                flow: self.flow.clone(),
                part,
            });
        }
    }
}

/// A response body with secrets masked in its data, its trailers, or
/// both, as it streams. A secret can straddle two frames, so bytes that
/// end a frame and begin a secret (at most `longest secret - 1`) are held
/// back until the next frame or the end shows whether the rest follows.
/// Nothing else is buffered, so a stream of events is not delayed unless
/// an event ends in what could start a secret.
struct MaskedBody {
    inner: Body,
    needles: Arc<Needles>,
    /// `bodies` masks the data, `headers` the trailers.
    switches: ResponseRedaction,
    /// `longest secret - 1`: the most a secret can reach back into bytes
    /// already released.
    keep: usize,
    /// Bytes not yet released: a secret could begin in them.
    held: Vec<u8>,
    /// The last `keep` bytes released, unmasked.
    behind: Vec<u8>,
    /// Trailers to send once `held` is flushed.
    pending_trailers: Option<HeaderMap>,
    alarm: Alarm,
    /// A secret was found in the data already: the alarm is raised once.
    found: bool,
    inner_done: bool,
    done: bool,
}

impl MaskedBody {
    fn wrap(inner: Body, needles: Arc<Needles>, switches: ResponseRedaction, alarm: Alarm) -> Body {
        let keep = needles.longest().saturating_sub(1);
        // Masking keeps every length.
        let length = inner.known_length();
        Body::wrap_native(
            Self {
                inner,
                needles,
                switches,
                keep,
                held: Vec::new(),
                behind: Vec::new(),
                pending_trailers: None,
                alarm,
                found: false,
                inner_done: false,
                done: false,
            },
            u64::MAX,
            length,
        )
    }

    /// The masked bytes of `held` that no later byte can change, or all of
    /// it at the end. A match that runs past the hold-back point is
    /// complete, so it is released whole rather than split. A secret that
    /// began in bytes already released is found against `behind`, so its
    /// rest is masked too, and the output is the same however the body is
    /// split.
    fn release(&mut self, end: bool) -> Option<Bytes> {
        let from = self.behind.len();
        let mut buf = std::mem::take(&mut self.behind);
        buf.extend_from_slice(&self.held);
        let ranges = self.needles.ranges(&buf);
        let mut cut = if end {
            buf.len()
        } else {
            // A secret begun in `behind` may still be arriving: its rest
            // waits too.
            (buf.len() - self.needles.partial_suffix(&buf)).max(from)
        };
        if let Some(&(_, e)) = ranges.iter().find(|&&(s, e)| s < cut && e > cut) {
            cut = e;
        }
        let mut out = buf[from..cut].to_vec();
        let mut hit = false;
        for &(s, e) in ranges.iter().filter(|&&(s, e)| s < cut && e > from) {
            out[s.max(from) - from..e - from].fill(MASK);
            hit = true;
        }
        if hit && !self.found {
            self.found = true;
            self.alarm.raise(Part::Body);
        }
        self.held = buf.split_off(cut);
        self.behind = buf.split_off(cut.saturating_sub(self.keep));
        (!out.is_empty()).then(|| Bytes::from(out))
    }
}

impl http_body::Body for MaskedBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = &mut *self;
        loop {
            if this.done {
                return Poll::Ready(None);
            }
            if this.inner_done {
                if let Some(out) = this.release(true) {
                    return Poll::Ready(Some(Ok(Frame::data(out))));
                }
                this.done = true;
                return Poll::Ready(this.pending_trailers.take().map(|t| Ok(Frame::trailers(t))));
            }
            match ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
                Some(Ok(f)) => match f.into_data() {
                    Ok(d) if !this.switches.bodies => return Poll::Ready(Some(Ok(Frame::data(d)))),
                    Ok(d) => {
                        this.held.extend_from_slice(&d);
                        if let Some(out) = this.release(false) {
                            return Poll::Ready(Some(Ok(Frame::data(out))));
                        }
                    }
                    Err(f) => {
                        if let Ok(mut t) = f.into_trailers() {
                            if this.switches.headers && mask_trailers(&this.needles, &mut t) {
                                this.alarm.raise(Part::Trailers);
                            }
                            this.pending_trailers = Some(t);
                        }
                    }
                },
                Some(Err(e)) => {
                    this.done = true;
                    return Poll::Ready(Some(Err(e)));
                }
                None => this.inner_done = true,
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    fn needles(values: &[&str]) -> Arc<Needles> {
        let mut n = Needles::default();
        for v in values {
            n.add(*v);
        }
        Arc::new(n)
    }

    const ALL: ResponseRedaction = ResponseRedaction {
        headers: true,
        bodies: true,
        quarantine: false,
        min_length: 1,
    };

    fn quiet() -> Alarm {
        Alarm {
            shared: None,
            flow: "test".to_owned(),
        }
    }

    /// `input` masked whole.
    fn masked(values: &[&str], input: &[u8]) -> Vec<u8> {
        needles(values).mask_bytes(input).into_owned()
    }

    /// `input` fed to the body `chunk` bytes at a time.
    async fn stream(values: &[&str], input: &[u8], chunk: usize) -> Vec<u8> {
        let sizes = std::iter::repeat_n(chunk, input.len().div_ceil(chunk)).collect();
        stream_split(values, input, sizes).await
    }

    /// `input` fed to the body in frames of `sizes` bytes (the last frame
    /// takes what is left).
    async fn stream_split(values: &[&str], input: &[u8], sizes: Vec<usize>) -> Vec<u8> {
        let (mut tx, body) = Body::channel(u64::MAX, None);
        let input = input.to_vec();
        let feed = tokio::spawn(async move {
            let mut rest = &input[..];
            for n in sizes {
                let (c, r) = rest.split_at(n.min(rest.len()));
                tx.send_data(Bytes::copy_from_slice(c)).await.unwrap();
                rest = r;
            }
            tx.send_data(Bytes::copy_from_slice(rest)).await.unwrap();
            tx.finish().await.unwrap();
        });
        let body = MaskedBody::wrap(body, needles(values), ALL, quiet());
        let out = body.collect().await.unwrap().to_bytes().to_vec();
        feed.await.unwrap();
        out
    }

    proptest::proptest! {
        /// However the body is split, the stream comes out as masking it
        /// whole would: overlapping and repeated secrets over a small
        /// alphabet make every straddle likely.
        #[test]
        fn streaming_matches_masking_whole(
            input in proptest::collection::vec(proptest::sample::select(b"abc".to_vec()), 0..64),
            sizes in proptest::collection::vec(1usize..8, 0..16),
        ) {
            let values = ["abca", "cab", "bb", "aaaa"];
            let got = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(stream_split(&values, &input, sizes));
            proptest::prop_assert_eq!(got, masked(&values, &input));
        }
    }

    #[tokio::test]
    async fn masks_secrets_straddling_frames() {
        let input = b"key sk-live-123, token ghp_abc and sk-live-123x";
        let want = b"key ***********, token ******* and ***********x";
        for chunk in 1..=input.len() {
            assert_eq!(
                stream(&["sk-live-123", "ghp_abc"], input, chunk).await,
                want,
                "chunk size {chunk}"
            );
        }
    }

    #[tokio::test]
    async fn overlapping_secrets_are_masked_as_one_run() {
        let input = b"x abcdef y aaabcd";
        assert_eq!(masked(&["abcd", "cdef"], input), b"x ****** y aa****");
        for chunk in 1..=input.len() {
            assert_eq!(
                stream(&["abcd", "cdef"], input, chunk).await,
                masked(&["abcd", "cdef"], input),
                "chunk size {chunk}"
            );
        }
    }

    #[tokio::test]
    async fn a_body_without_secrets_is_unchanged() {
        let input = b"nothing to see; sk-live-12 is not the whole secret";
        for chunk in [1, 7, input.len()] {
            assert_eq!(stream(&["sk-live-123"], input, chunk).await, input);
        }
    }

    /// A frame is held back only as far as its end could begin a secret,
    /// so a stream of events is not delayed waiting for the next.
    #[tokio::test]
    async fn only_a_possible_secret_start_is_held_back() {
        let (mut tx, body) = Body::channel(u64::MAX, None);
        let mut body = MaskedBody::wrap(body, needles(&["sk-live-123"]), ALL, quiet());
        tx.send_data(Bytes::from_static(b"data: one\n\n"))
            .await
            .unwrap();
        let f = body.frame().await.unwrap().unwrap();
        assert_eq!(f.into_data().unwrap(), &b"data: one\n\n"[..]);
        tx.send_data(Bytes::from_static(b"data: sk-li"))
            .await
            .unwrap();
        let f = body.frame().await.unwrap().unwrap();
        assert_eq!(f.into_data().unwrap(), &b"data: "[..]);
        tx.send_data(Bytes::from_static(b"ve-123\n\n"))
            .await
            .unwrap();
        tx.finish().await.unwrap();
        let rest = body.collect().await.unwrap().to_bytes();
        assert_eq!(rest, &b"***********\n\n"[..]);
    }

    #[tokio::test]
    async fn trailers_are_masked_after_the_held_bytes() {
        let mut trailers = HeaderMap::new();
        trailers.insert("x-echo", HeaderValue::from_static("Bearer sk-live-123"));
        let body = Body::from_parts(Bytes::from_static(b"tail sk-live"), Some(trailers));
        let body = MaskedBody::wrap(body, needles(&["sk-live-123"]), ALL, quiet());
        let collected = body.collect().await.unwrap();
        let trailers = collected.trailers().cloned().unwrap();
        assert_eq!(trailers["x-echo"], "Bearer ***********");
        assert_eq!(collected.to_bytes(), &b"tail sk-live"[..]);
    }

    #[test]
    fn header_values_keep_their_other_bytes() {
        let r = needles(&["sk-live-123"]);
        let mut h = Headers::new();
        h.append("location", "https://x.test/cb?key=sk-live-123&a=1")
            .unwrap();
        h.append("x-other", "fine").unwrap();
        assert!(mask_headers(&r, &mut h));
        assert_eq!(
            h.get("location"),
            Some("https://x.test/cb?key=***********&a=1")
        );
        assert_eq!(h.get("x-other"), Some("fine"));
        assert!(!mask_headers(&r, &mut h));
    }
}
