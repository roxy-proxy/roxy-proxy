//! Scrubbing injected secrets from a response on its way to the client
//! (`http.redact_response_secrets`).
//!
//! Only an exchange that injected a secret is scrubbed: it is the one
//! whose upstream holds a value the client was never given. The stage runs
//! in the core, after the response rules and before the in-flight body
//! checks, the capture tap and the addon layers, so everything downstream
//! of the upstream sees the scrubbed response.
//!
//! Matching is literal, so this stops a verbatim echo only: a value the
//! upstream transforms (base64, escaping, a change of case) passes.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode};
use http_body::Frame;
use roxy_http::{Body, BodyError, CanonicalResponse, Headers, coding};

use crate::config::ResponseRedaction;
use crate::flowlog::{REDACTED, Redactor, replace_ranges};
use crate::pipeline::{FlowCx, Refusal, response_known_empty};
use crate::quarantine::QuarantineCause;
use crate::secrets::Secrets;
use crate::server::Shared;

/// Flow-log `reason` of a response whose body cannot be scrubbed: its
/// content coding is one roxy does not decode, or it is a range of an
/// encoded body.
const UNDECODABLE: &str = "unsupported_content_encoding";

/// Scrubs `res` as `http.redact_response_secrets` asks, if this exchange
/// injected a secret. A body that cannot be read as plain bytes is refused
/// rather than passed unscrubbed.
pub(crate) fn response(cx: &FlowCx, res: &mut CanonicalResponse) -> Result<(), Refusal> {
    let switches = cx.snap.http.redact_response_secrets;
    if !cx.injected_secret || !(switches.headers || switches.bodies) {
        return Ok(());
    }
    let alarm = Alarm {
        shared: switches.quarantine.then(|| cx.shared.clone()),
        flow: cx.flow.to_string(),
    };
    let secrets = cx.secrets().clone();
    if switches.headers && redact_headers(secrets.redactor(), &mut res.headers) {
        alarm.raise(Part::Headers);
    }
    if response_known_empty(cx, res) {
        return Ok(());
    }
    if switches.bodies {
        decode(cx, res)?;
    }
    let body = std::mem::take(&mut res.body);
    res.body = RedactedBody::wrap(body, secrets, switches, alarm);
    Ok(())
}

/// Leaves `res`'s body as plain bytes: decoded by its `content-encoding`,
/// or refused when it cannot be. A range of an encoded body cannot be
/// decoded on its own; a range of a plain one is scrubbed as it is.
fn decode(cx: &FlowCx, res: &mut CanonicalResponse) -> Result<(), Refusal> {
    let codings =
        coding::content_codings(&res.headers).map_err(|_| Refusal::fail_closed(UNDECODABLE))?;
    if codings.is_empty() {
        return Ok(());
    }
    if res.status == StatusCode::PARTIAL_CONTENT || res.headers.contains("content-range") {
        return Err(Refusal::fail_closed(UNDECODABLE));
    }
    res.headers.remove("content-encoding");
    res.body = coding::decode_body(
        std::mem::take(&mut res.body),
        &codings,
        cx.snap.limits.max_response_body_bytes,
        cx.shared.window_meter(),
    );
    Ok(())
}

/// Scrubs every value in `headers`; whether any held a secret.
fn redact_headers(r: &Redactor, headers: &mut Headers) -> bool {
    let mut found = false;
    headers.replace_values(|v| {
        let new = redact_value(r, v)?;
        found = true;
        Some(new)
    });
    found
}

/// Scrubs every value in a trailer block; whether any held a secret.
fn redact_trailers(r: &Redactor, trailers: &mut HeaderMap) -> bool {
    let mut found = false;
    for v in trailers.values_mut() {
        if let Some(new) = redact_value(r, v) {
            *v = new;
            found = true;
        }
    }
    found
}

/// `v` scrubbed, or `None` when it holds no secret.
fn redact_value(r: &Redactor, v: &HeaderValue) -> Option<HeaderValue> {
    let ranges = r.secret_ranges(v.as_bytes());
    if ranges.is_empty() {
        return None;
    }
    // The marker is visible ASCII and the bytes around it were already a
    // valid value, so this cannot fail; the whole marker is the fallback.
    Some(
        HeaderValue::from_bytes(&replace_ranges(v.as_bytes(), &ranges))
            .unwrap_or_else(|_| HeaderValue::from_static(REDACTED)),
    )
}

/// The part of a response a secret was found in.
#[derive(Debug, Clone, Copy)]
enum Part {
    Headers,
    Body,
    Trailers,
}

impl Part {
    fn as_str(self) -> &'static str {
        match self {
            Self::Headers => "headers",
            Self::Body => "body",
            Self::Trailers => "trailers",
        }
    }
}

/// Reports a secret found in a response, and quarantines the process
/// when `http.redact_response_secrets.quarantine` is on.
struct Alarm {
    shared: Option<Arc<Shared>>,
    flow: String,
}

impl Alarm {
    fn raise(&self, part: Part) {
        tracing::warn!(flow = %self.flow, part = part.as_str(), "injected secret found in the response; redacted");
        if let Some(shared) = &self.shared {
            shared.trip_quarantine(QuarantineCause::SecretInResponse {
                flow: self.flow.clone(),
                part: part.as_str().to_owned(),
            });
        }
    }
}

/// A response body with secrets scrubbed from its data, its trailers, or
/// both, as it streams. A secret can straddle two frames, so bytes that
/// end a frame and begin a secret (at most `longest secret - 1`) are held
/// back until the next frame or the end shows whether the rest follows.
/// Nothing else is buffered, so a stream of events is not delayed by them
/// unless an event ends in what could start a secret.
struct RedactedBody {
    inner: Body,
    secrets: Arc<Secrets>,
    /// `bodies` scrubs the data, `headers` the trailers.
    switches: ResponseRedaction,
    /// The most bytes ever held back: `longest secret - 1`.
    keep: usize,
    /// Bytes not yet released: a secret could begin in them.
    held: Vec<u8>,
    /// The last `keep + 1` bytes released, unscrubbed.
    behind: Vec<u8>,
    /// Trailers to send once `held` is flushed.
    pending_trailers: Option<HeaderMap>,
    alarm: Alarm,
    /// A secret was found in the data already: the alarm is raised once.
    found: bool,
    inner_done: bool,
    done: bool,
}

impl RedactedBody {
    fn wrap(inner: Body, secrets: Arc<Secrets>, switches: ResponseRedaction, alarm: Alarm) -> Body {
        let keep = secrets.redactor().longest_secret().saturating_sub(1);
        Body::wrap_native(
            Self {
                inner,
                secrets,
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
            None,
        )
    }

    /// The scrubbed bytes of `held` that no later byte can change, or all
    /// of it at the end. A match that runs past the hold-back point is
    /// complete, so it is released whole rather than split. A secret
    /// overlapping one already released is found against `behind`, the
    /// raw bytes released last; its released part is already under a
    /// marker, so the rest is dropped without another (as is one adjoining
    /// it, which the log merges too), and the output is the same however
    /// the body is split.
    fn release(&mut self, end: bool) -> Option<Bytes> {
        let from = self.behind.len();
        let mut buf = std::mem::take(&mut self.behind);
        buf.extend_from_slice(&self.held);
        let ranges = self.secrets.redactor().secret_ranges(&buf);
        let mut cut = if end {
            buf.len()
        } else {
            // A secret begun in `behind` may still be arriving: its rest
            // waits too, to be dropped as a continuation.
            (buf.len() - self.secrets.redactor().partial_suffix(&buf)).max(from)
        };
        if let Some(&(_, e)) = ranges.iter().find(|&&(s, e)| s < cut && e > cut) {
            cut = e;
        }
        let mut out = Vec::with_capacity(cut - from);
        let mut pos = from;
        for &(s, e) in ranges.iter().filter(|&&(s, e)| s < cut && e > from) {
            if s >= from {
                out.extend_from_slice(&buf[pos..s]);
                out.extend_from_slice(REDACTED.as_bytes());
                if !self.found {
                    self.found = true;
                    self.alarm.raise(Part::Body);
                }
            }
            pos = e;
        }
        out.extend_from_slice(&buf[pos.min(cut)..cut]);
        self.held = buf.split_off(cut);
        // One byte more than is held back: a secret ending right where the
        // release ended is whole in it, so a match adjoining it merges.
        let keep_from = cut.saturating_sub(self.keep + 1);
        self.behind = buf.split_off(keep_from);
        (!out.is_empty()).then(|| Bytes::from(out))
    }
}

impl http_body::Body for RedactedBody {
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
                            if this.switches.headers
                                && redact_trailers(this.secrets.redactor(), &mut t)
                            {
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

    fn secrets(values: &[&str]) -> Arc<Secrets> {
        let map = values
            .iter()
            .enumerate()
            .map(|(i, v)| (format!("s{i}"), (*v).to_owned()))
            .collect();
        crate::secrets::SecretStore::new(map, Redactor::new()).load()
    }

    const ALL: ResponseRedaction = ResponseRedaction {
        headers: true,
        bodies: true,
        quarantine: false,
    };

    fn quiet() -> Alarm {
        Alarm {
            shared: None,
            flow: "test".to_owned(),
        }
    }

    /// `input` fed to the redactor `chunk` bytes at a time.
    async fn redact(values: &[&str], input: &[u8], chunk: usize) -> Vec<u8> {
        let sizes = std::iter::repeat_n(chunk, input.len().div_ceil(chunk)).collect();
        redact_split(values, input, sizes).await
    }

    /// `input` fed to the redactor in frames of `sizes` bytes (the last
    /// frame takes what is left).
    async fn redact_split(values: &[&str], input: &[u8], sizes: Vec<usize>) -> Vec<u8> {
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
        let body = RedactedBody::wrap(body, secrets(values), ALL, quiet());
        let out = body.collect().await.unwrap().to_bytes().to_vec();
        feed.await.unwrap();
        out
    }

    proptest::proptest! {
        /// However the body is split, the stream comes out as the flow log
        /// would redact it whole: overlapping and repeated secrets over a
        /// small alphabet make every straddle likely.
        #[test]
        fn streaming_matches_redacting_whole(
            input in proptest::collection::vec(proptest::sample::select(b"abc".to_vec()), 0..64),
            sizes in proptest::collection::vec(1usize..8, 0..16),
        ) {
            let values = ["abca", "cab", "bb", "aaaa"];
            let want = secrets(&values).redactor().redact_bytes(&input).into_owned();
            let got = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(redact_split(&values, &input, sizes));
            proptest::prop_assert_eq!(got, want);
        }
    }

    #[tokio::test]
    async fn scrubs_secrets_straddling_frames() {
        let input = b"key sk-live-123, token ghp_abc and sk-live-123x";
        let want = b"key [REDACTED], token [REDACTED] and [REDACTED]x";
        for chunk in 1..=input.len() {
            assert_eq!(
                redact(&["sk-live-123", "ghp_abc"], input, chunk).await,
                want,
                "chunk size {chunk}"
            );
        }
    }

    /// Overlapping occurrences merge into one marker, as in the flow log,
    /// however the body is split.
    #[tokio::test]
    async fn overlapping_secrets_merge_as_in_the_log() {
        let r = secrets(&["abcd", "cdef"]);
        let input = b"x abcdef y aaabcd";
        let want = r.redactor().redact_bytes(input).into_owned();
        assert_eq!(want, b"x [REDACTED] y aa[REDACTED]");
        for chunk in 1..=input.len() {
            assert_eq!(
                redact(&["abcd", "cdef"], input, chunk).await,
                want,
                "chunk size {chunk}"
            );
        }
    }

    #[tokio::test]
    async fn a_body_without_secrets_is_unchanged() {
        let input = b"nothing to see; sk-live-12 is not the whole secret";
        for chunk in [1, 7, input.len()] {
            assert_eq!(redact(&["sk-live-123"], input, chunk).await, input);
        }
    }

    /// A frame is held back only as far as its end could begin a secret,
    /// so a stream of events is not delayed waiting for the next.
    #[tokio::test]
    async fn only_a_possible_secret_start_is_held_back() {
        let (mut tx, body) = Body::channel(u64::MAX, None);
        let mut body = RedactedBody::wrap(body, secrets(&["sk-live-123"]), ALL, quiet());
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
        assert_eq!(rest, &b"[REDACTED]\n\n"[..]);
    }

    #[tokio::test]
    async fn trailers_are_scrubbed_after_the_held_bytes() {
        let mut trailers = HeaderMap::new();
        trailers.insert("x-echo", HeaderValue::from_static("Bearer sk-live-123"));
        let body = Body::from_parts(Bytes::from_static(b"tail sk-live"), Some(trailers));
        let body = RedactedBody::wrap(body, secrets(&["sk-live-123"]), ALL, quiet());
        let collected = body.collect().await.unwrap();
        let trailers = collected.trailers().cloned().unwrap();
        assert_eq!(trailers["x-echo"], "Bearer [REDACTED]");
        assert_eq!(collected.to_bytes(), &b"tail sk-live"[..]);
    }

    #[test]
    fn header_values_keep_their_other_bytes() {
        let r = secrets(&["sk-live-123"]);
        let mut h = Headers::new();
        h.append("location", "https://x.test/cb?key=sk-live-123&a=1")
            .unwrap();
        h.append("x-other", "fine").unwrap();
        assert!(redact_headers(r.redactor(), &mut h));
        assert_eq!(
            h.get("location"),
            Some("https://x.test/cb?key=[REDACTED]&a=1")
        );
        assert_eq!(h.get("x-other"), Some("fine"));
        assert!(!redact_headers(r.redactor(), &mut h));
    }
}
