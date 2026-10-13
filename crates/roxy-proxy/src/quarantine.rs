//! Quarantine: a process-wide state in which every exchange is refused
//! with `403` and rule id `_quarantined`, before the addons and the rules
//! run. It is tripped by a rule's `quarantine` action or by a listener's
//! parse-error threshold, written to a marker file so it survives a
//! restart, and lifted only from outside the process: a control plane's
//! release, or an operator removing the marker before a restart.

use std::collections::VecDeque;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use ulid::Ulid;

/// Why the proxy is quarantined. Serialised into the marker file, the
/// `quarantined` flow event and the node's lease poll.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum QuarantineCause {
    /// A rule's `quarantine` action matched.
    Rule { rule: String, flow: String },
    /// A listener's parse-error threshold was reached.
    Threshold {
        listener: String,
        counter: String,
        count: u32,
        window_seconds: u64,
    },
}

/// One quarantine incident. `id` is minted here per trip; a release names
/// it, so a release decided before a later trip lifts nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineRecord {
    pub id: String,
    pub since: DateTime<Utc>,
    pub cause: QuarantineCause,
}

/// A listener's `quarantine_on.parse_errors`: `count` parse errors within
/// `window` trip the quarantine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseErrorThreshold {
    pub count: u32,
    pub window: Duration,
}

/// The counter name `QuarantineCause::Threshold` reports for parse errors.
pub const PARSE_ERRORS: &str = "parse_errors";

/// Parse-error reasons that do not count towards a threshold: the client
/// did not send anything malformed, it was slow, left, or roxy itself
/// failed.
const NOT_A_PROBE: &[&str] = &[
    "header_timeout",
    "body_timeout",
    "tunnel_timeout",
    "tls_handshake_timeout",
    "h2_handshake_timeout",
    "unexpected_eof",
    "io_error",
    "connect_write_failed",
    "leaf_mint_failed",
    "invalid_state",
];

/// Whether a parse-error `reason` counts towards a listener's threshold.
pub(crate) fn counts_as_probe(reason: &str) -> bool {
    !NOT_A_PROBE.contains(&reason)
}

/// The reason for a TLS or h2 handshake that did not complete: `protocol`
/// when the client sent something roxy would not accept, the transport's
/// own reason when it left or reset instead, which is no probe. Both
/// libraries report a departure as an I/O error (rustls wraps its protocol
/// errors as `InvalidData`).
pub(crate) fn handshake_reason(protocol: &'static str, io: Option<&io::Error>) -> &'static str {
    match io.map(io::Error::kind) {
        Some(io::ErrorKind::UnexpectedEof) => "unexpected_eof",
        Some(
            io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
            | io::ErrorKind::TimedOut,
        ) => "io_error",
        _ => protocol,
    }
}

/// The sliding count behind one listener's threshold. Keeps at most
/// `count` instants, so its memory is fixed by the config.
#[derive(Debug)]
pub(crate) struct TripCounter {
    threshold: ParseErrorThreshold,
    hits: Mutex<VecDeque<Instant>>,
}

impl TripCounter {
    pub(crate) fn new(threshold: ParseErrorThreshold) -> Self {
        Self {
            threshold,
            // Grows to `count` as hits arrive; `count` is unbounded in the
            // config, so nothing is reserved up front.
            hits: Mutex::new(VecDeque::new()),
        }
    }

    pub(crate) fn threshold(&self) -> ParseErrorThreshold {
        self.threshold
    }

    /// Records a hit at `now`; `true` when it is the `count`th within the
    /// window.
    pub(crate) fn note(&self, now: Instant) -> bool {
        let mut hits = self.hits.lock().unwrap_or_else(PoisonError::into_inner);
        let horizon = now.checked_sub(self.threshold.window);
        while hits
            .front()
            .is_some_and(|t| horizon.is_some_and(|h| *t < h))
        {
            hits.pop_front();
        }
        if hits.len() >= self.threshold.count as usize {
            hits.pop_front();
        }
        hits.push_back(now);
        hits.len() >= self.threshold.count as usize
    }
}

/// The outcome of [`QuarantineState::trip`].
pub(crate) struct Trip {
    pub record: Arc<QuarantineRecord>,
    /// This call tripped the quarantine (false: it was already active, and
    /// `record` is the incident in force).
    pub tripped: bool,
    /// The marker write, when this call tripped it. A failure leaves the
    /// process quarantined in memory only.
    pub persisted: io::Result<()>,
}

/// The quarantine state shared by every connection and every server the
/// process starts.
#[derive(Debug)]
pub struct QuarantineState {
    active: ArcSwapOption<QuarantineRecord>,
    /// The marker file; `None` keeps the state in memory only.
    marker: Option<PathBuf>,
    /// Cancelled by a trip, so the connections open at that moment end;
    /// replaced at once, so connections accepted afterwards (which the gate
    /// refuses) are not cut by the same trip.
    cut: Mutex<CancellationToken>,
    /// Held for the whole of a trip or a release, memory and marker
    /// together, so a release cannot slip between a trip's record and its
    /// marker write and leave the two disagreeing.
    transition: Mutex<()>,
    /// A restored quarantine is logged by the first server to start.
    announced: AtomicBool,
}

impl QuarantineState {
    /// A state with no marker file: a trip does not survive a restart.
    pub fn in_memory() -> Self {
        Self::with_marker(None, None)
    }

    /// Opens the state behind `marker`: quarantined if the file is there.
    /// A marker that is present but not a record is an error, not a clear
    /// state; the operator who put it there decides what it meant.
    pub fn load(marker: &Path) -> io::Result<Self> {
        let active = match std::fs::read(marker) {
            Ok(bytes) => Some(
                serde_json::from_slice::<QuarantineRecord>(&bytes).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{}: not a quarantine record: {e}", marker.display()),
                    )
                })?,
            ),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("{}: {e}", marker.display()),
                ));
            }
        };
        Ok(Self::with_marker(Some(marker.to_path_buf()), active))
    }

    fn with_marker(marker: Option<PathBuf>, active: Option<QuarantineRecord>) -> Self {
        Self {
            active: ArcSwapOption::from_pointee(active),
            marker,
            cut: Mutex::new(CancellationToken::new()),
            transition: Mutex::new(()),
            announced: AtomicBool::new(false),
        }
    }

    /// The marker file, if the state has one.
    pub fn marker(&self) -> Option<&Path> {
        self.marker.as_deref()
    }

    /// The incident in force, if any.
    pub fn active(&self) -> Option<Arc<QuarantineRecord>> {
        self.active.load_full()
    }

    pub fn is_active(&self) -> bool {
        self.active.load().is_some()
    }

    /// Whether a restored quarantine still needs logging; flips once.
    pub(crate) fn take_announce(&self) -> bool {
        !self.announced.swap(true, Ordering::AcqRel)
    }

    /// Puts the process into quarantine for `cause`. The in-memory state
    /// changes first, so the gate refuses the next exchange whether or not
    /// the marker can be written.
    pub(crate) fn trip(&self, cause: QuarantineCause) -> Trip {
        let _transition = self
            .transition
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(existing) = self.active.load_full() {
            return Trip {
                record: existing,
                tripped: false,
                persisted: Ok(()),
            };
        }
        let fresh = Arc::new(QuarantineRecord {
            id: format!("q-{}", Ulid::generate()),
            since: Utc::now(),
            cause,
        });
        self.active.store(Some(fresh.clone()));
        // The cut starts now, not after the marker write: a stalled disk
        // must not let open connections carry on past the grace.
        let token = {
            let mut cut = self.cut.lock().unwrap_or_else(PoisonError::into_inner);
            std::mem::replace(&mut *cut, CancellationToken::new())
        };
        token.cancel();
        let persisted = match &self.marker {
            Some(path) => write_marker(path, &fresh),
            None => Ok(()),
        };
        Trip {
            record: fresh,
            tripped: true,
            persisted,
        }
    }

    /// Lifts the quarantine if `id` is the incident in force: the marker
    /// goes first, so a failure leaves the process quarantined. `Ok(false)`
    /// when `id` is not the active incident.
    pub fn release(&self, id: &str) -> io::Result<bool> {
        let _transition = self
            .transition
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let Some(active) = self.active.load_full() else {
            return Ok(false);
        };
        if active.id != id {
            return Ok(false);
        }
        if let Some(path) = &self.marker {
            remove_marker(path)
                .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
        }
        self.active.store(None);
        Ok(true)
    }

    /// The token the connections accepted now are cut by.
    pub(crate) fn cut_token(&self) -> CancellationToken {
        self.cut
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// Writes the record to the marker, mode 0600, so a crash leaves either the
/// old marker or the new one.
fn write_marker(path: &Path, record: &QuarantineRecord) -> io::Result<()> {
    let mut bytes = serde_json::to_vec_pretty(record).map_err(io::Error::other)?;
    bytes.push(b'\n');
    roxy_state::write_atomic(path, &bytes, 0o600)
}

/// Removes the marker; a marker already gone counts as removed.
fn remove_marker(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        // An unlink whose directory sync failed last time is retried
        // here as the sync alone, so a release is durable before it is
        // reported.
        Ok(()) => roxy_state::sync_parent(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => roxy_state::sync_parent(path),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cause() -> QuarantineCause {
        QuarantineCause::Rule {
            rule: "r".into(),
            flow: "f".into(),
        }
    }

    #[test]
    fn a_trip_persists_and_a_restart_restores_it() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("quarantine");
        let state = QuarantineState::load(&marker).unwrap();
        assert!(!state.is_active());
        let token = state.cut_token();

        let trip = state.trip(cause());
        assert!(trip.tripped);
        trip.persisted.unwrap();
        assert!(token.is_cancelled(), "connections open at the trip are cut");
        assert!(
            !state.cut_token().is_cancelled(),
            "connections accepted after it are not"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&marker).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let again = state.trip(QuarantineCause::Threshold {
            listener: "proxy".into(),
            counter: PARSE_ERRORS.into(),
            count: 3,
            window_seconds: 60,
        });
        assert!(!again.tripped);
        assert_eq!(again.record, trip.record, "the first incident stands");

        let restored = QuarantineState::load(&marker).unwrap();
        assert_eq!(restored.active().as_deref(), Some(&*trip.record));
    }

    #[test]
    fn release_needs_the_active_id_and_removes_the_marker() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("quarantine");
        let state = QuarantineState::load(&marker).unwrap();
        assert!(!state.release("q-nothing").unwrap());
        let trip = state.trip(cause());
        assert!(!state.release("q-other").unwrap());
        assert!(state.is_active());
        assert!(state.release(&trip.record.id).unwrap());
        assert!(!state.is_active());
        assert!(!marker.exists());
        assert!(!QuarantineState::load(&marker).unwrap().is_active());
    }

    #[test]
    fn a_marker_that_is_not_a_record_refuses_to_load() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("quarantine");
        std::fs::write(&marker, "yes\n").unwrap();
        let err = QuarantineState::load(&marker).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("not a quarantine record"), "{err}");
    }

    #[test]
    fn a_trip_without_a_marker_is_in_memory_only() {
        let state = QuarantineState::in_memory();
        let trip = state.trip(cause());
        assert!(trip.tripped);
        trip.persisted.unwrap();
        assert!(state.is_active());
        assert!(state.release(&trip.record.id).unwrap());
    }

    #[test]
    fn the_counter_trips_on_the_nth_hit_within_the_window() {
        let c = TripCounter::new(ParseErrorThreshold {
            count: 3,
            window: Duration::from_secs(10),
        });
        let t0 = Instant::now();
        assert!(!c.note(t0));
        assert!(!c.note(t0 + Duration::from_secs(1)));
        assert!(c.note(t0 + Duration::from_secs(2)));
        // A hit outside the window no longer counts.
        let c = TripCounter::new(ParseErrorThreshold {
            count: 3,
            window: Duration::from_secs(10),
        });
        assert!(!c.note(t0));
        assert!(!c.note(t0 + Duration::from_secs(1)));
        assert!(!c.note(t0 + Duration::from_secs(11)), "t0 has aged out");
        assert!(!c.note(t0 + Duration::from_secs(12)), "and t0+1");
        assert!(c.note(t0 + Duration::from_secs(13)));
        // A count of one trips on the first hit.
        let c = TripCounter::new(ParseErrorThreshold {
            count: 1,
            window: Duration::from_secs(10),
        });
        assert!(c.note(t0));
    }

    #[test]
    fn a_handshake_the_client_left_is_not_a_probe() {
        let io = |k| io::Error::new(k, "x");
        assert_eq!(
            handshake_reason(
                "tls_handshake_failed",
                Some(&io(io::ErrorKind::UnexpectedEof))
            ),
            "unexpected_eof"
        );
        assert_eq!(
            handshake_reason(
                "h2_handshake_failed",
                Some(&io(io::ErrorKind::ConnectionReset))
            ),
            "io_error"
        );
        // rustls reports a bad ClientHello as `InvalidData`.
        assert_eq!(
            handshake_reason(
                "tls_handshake_failed",
                Some(&io(io::ErrorKind::InvalidData))
            ),
            "tls_handshake_failed"
        );
        assert_eq!(
            handshake_reason("h2_handshake_failed", None),
            "h2_handshake_failed"
        );
    }

    #[test]
    fn timeouts_and_roxy_failures_are_not_probes() {
        for r in [
            "header_timeout",
            "tunnel_timeout",
            "leaf_mint_failed",
            "unexpected_eof",
        ] {
            assert!(!counts_as_probe(r), "{r}");
        }
        for r in [
            "bare_lf",
            "bad_sni",
            "non_http_in_connect",
            "h2_bad_pseudo_header",
        ] {
            assert!(counts_as_probe(r), "{r}");
        }
    }
}
