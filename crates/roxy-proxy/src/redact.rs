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
/// both, as it streams. A secret can straddle two frames, so the last
/// `longest secret - 1` bytes of what has arrived are held back until the
/// next frame or the end, whatever they are: a hold that depended on the
/// bytes would tell the client, byte by byte, what the secret begins
/// with. Nothing else is buffered. The cost is that a frame reaches the
/// client complete only when the next one, or the end, arrives.
struct MaskedBody {
    inner: Body,
    needles: Arc<Needles>,
    /// `bodies` masks the data, `headers` the trailers.
    switches: ResponseRedaction,
    /// `longest secret - 1`: the most of a secret that can have arrived
    /// without the rest.
    keep: usize,
    /// Bytes not yet released, as the upstream sent them.
    held: Vec<u8>,
    /// How many of the first bytes of `held` are the rest of a secret
    /// whose start was released masked: they are masked when released,
    /// whatever else is found around them.
    pre_masked: usize,
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
                pre_masked: 0,
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

    /// All of `held` but its last `keep` bytes, masked, or all of it at the
    /// end. How much goes depends only on how much has arrived. A secret
    /// that overlaps the released bytes has arrived whole (it is at most
    /// `keep + 1` long), so it is found now; the part of it still held is
    /// remembered as `pre_masked` and masked when it goes, whatever is
    /// found around it then. The output is the same however the body is
    /// split.
    fn release(&mut self, end: bool) -> Option<Bytes> {
        let cut = if end {
            self.held.len()
        } else {
            self.held.len().saturating_sub(self.keep)
        };
        if cut == 0 {
            return None;
        }
        let ranges = self.needles.ranges(&self.held);
        let mut out = self.held[..cut].to_vec();
        let mut hit = self.pre_masked > 0;
        out[..self.pre_masked.min(cut)].fill(MASK);
        let mut pre_masked = self.pre_masked.saturating_sub(cut);
        for &(s, e) in ranges.iter().filter(|&&(s, _)| s < cut) {
            out[s..e.min(cut)].fill(MASK);
            pre_masked = pre_masked.max(e - cut.min(e));
            hit = true;
        }
        if hit && !self.found {
            self.found = true;
            self.alarm.raise(Part::Body);
        }
        self.held.drain(..cut);
        self.pre_masked = pre_masked;
        Some(Bytes::from(out))
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

    /// The last `longest - 1` bytes of what has arrived wait for the next
    /// frame or the end, whatever they are.
    #[tokio::test]
    async fn the_last_bytes_are_held_back_whatever_they_are() {
        let (mut tx, body) = Body::channel(u64::MAX, None);
        let mut body = MaskedBody::wrap(body, needles(&["sk-live-123"]), ALL, quiet());
        tx.send_data(Bytes::from_static(b"data: one\n\n"))
            .await
            .unwrap();
        let f = body.frame().await.unwrap().unwrap();
        assert_eq!(f.into_data().unwrap(), &b"d"[..]);
        tx.send_data(Bytes::from_static(b"data: sk-li"))
            .await
            .unwrap();
        let f = body.frame().await.unwrap().unwrap();
        assert_eq!(f.into_data().unwrap(), &b"ata: one\n\nd"[..]);
        tx.send_data(Bytes::from_static(b"ve-123\n\n"))
            .await
            .unwrap();
        let f = body.frame().await.unwrap().unwrap();
        assert_eq!(f.into_data().unwrap(), &b"ata: ***"[..]);
        tx.finish().await.unwrap();
        let rest = body.collect().await.unwrap().to_bytes();
        assert_eq!(rest, &b"********\n\n"[..]);
    }

    /// What the client can see of the hold says nothing about the secret.
    /// The client (the attacker) can get an allowed upstream that streams
    /// its own bytes back to end a frame with bytes of its choosing, and
    /// it sees how much of that frame roxy passes on at once. The amount
    /// must be the same whether the frame ends in the start of the secret
    /// or not; with a hold that depended on the bytes, this probe read the
    /// secret off one byte per guess (found in review).
    #[tokio::test]
    async fn the_hold_back_is_not_an_oracle_for_the_secret() {
        const SECRET: &str = "sk-live-0123456789";
        for (good, bad) in [
            ("s", "x"),
            ("sk-live-01", "sk-live-0x"),
            ("sk-live-012345678", "zzzzzzzzzzzzzzzzz"),
        ] {
            let mut released = Vec::new();
            for probe in [good, bad] {
                let (mut tx, body) = Body::channel(u64::MAX, None);
                let mut body = MaskedBody::wrap(body, needles(&[SECRET]), ALL, quiet());
                let mut cx = Context::from_waker(std::task::Waker::noop());
                let text = format!("a frame of some text that ends in: {probe}");
                tx.send_data(Bytes::from(text.clone())).await.unwrap();
                let mut out = Vec::new();
                while let Poll::Ready(Some(Ok(f))) =
                    http_body::Body::poll_frame(Pin::new(&mut body), &mut cx)
                {
                    if let Ok(d) = f.into_data() {
                        out.extend_from_slice(&d);
                    }
                }
                assert_eq!(out, &text.as_bytes()[..out.len()], "{probe:?}");
                released.push(out.len());
            }
            assert_eq!(released[0], released[1], "{good:?} vs {bad:?}");
        }
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
