//! The node's lifecycle: enrol or load the identity, then refresh the lease
//! at `refresh_after`, renew the certificate inside its window and ship
//! spooled flows. What a lease means for the proxy is the [`LeaseHandler`]'s
//! business; this module decides *when* and *whether* to call it.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

use crate::client::{
    CertificateError, ClientError, ControlPlane, LeaseFetch, NodeInfo, ShipOutcome, Trust,
};
use crate::identity::{self, IdentityError};
use crate::protocol::{Lease, NodeState, PROTOCOL_VERSION, PolicyState, encode_flow_batch};
use crate::spool::Spool;
use crate::state::{StateDir, StateError};

/// Backoff for a failed lease fetch, certificate call or flow upload.
const BACKOFF_FIRST: Duration = Duration::from_secs(1);
const BACKOFF_CAP: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error("no node identity in {} and no enrolment token file given", dir.display())]
    NotEnrolled { dir: PathBuf },
    #[error("reading the enrolment token {}: {source}", path.display())]
    Token {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("enrolment rejected by the control plane: {0}")]
    EnrolRejected(String),
    #[error("reading the control plane CA bundle {}: {source}", path.display())]
    CaBundle {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// What changed between the lease the node runs and the one it fetched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Change {
    /// `config` differs: the policy must be recompiled and swapped.
    pub config: bool,
    /// `secrets` differ: the secret map must be swapped.
    pub secrets: bool,
    /// `state_epoch` differs: rule state and metric windows are cleared.
    pub state_epoch: bool,
}

/// The future a [`LeaseHandler`] method returns.
pub type HandlerFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Applies leases to the proxy. The methods run on the node's lease task,
/// one at a time.
pub trait LeaseHandler: Send + Sync {
    /// Applies `lease`, received at `received_at` (the base of
    /// `valid_until`). A lease with no change in `change` still moves
    /// `valid_until`. `Err` keeps the running policy; the error is logged
    /// and the node reports the old lease id on its next fetch.
    fn apply<'a>(
        &'a self,
        lease: &'a Lease,
        received_at: DateTime<Utc>,
        change: Change,
    ) -> HandlerFuture<'a, Result<(), String>>;

    /// The node is revoked: deny everything, at once.
    fn revoke(&self) -> HandlerFuture<'_, ()>;

    /// What the proxy is running, for the lease fetch body.
    fn policy_state(&self) -> PolicyState;
}

/// How to reach the control plane and where the node keeps its state.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub control_plane: String,
    pub trust: Trust,
    pub state_dir: PathBuf,
    /// Read once, on a start with no identity in the state dir.
    pub enrol_token_file: Option<PathBuf>,
    pub info: NodeInfo,
    /// Multiplies every protocol wait (refresh, backoff, renewal). 1.0 in
    /// production; tests shrink it.
    #[doc(hidden)]
    pub time_scale: f64,
}

/// The lease the node runs: what the next one is compared with.
#[derive(Default)]
struct Current {
    lease_id: Option<String>,
    config: Option<String>,
    secrets: Option<BTreeMap<String, String>>,
    state_epoch: Option<String>,
}

/// Never prints the secret values.
impl std::fmt::Debug for Current {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Current")
            .field("lease_id", &self.lease_id)
            .field("state_epoch", &self.state_epoch)
            .finish_non_exhaustive()
    }
}

/// The node's identity as the shipper and the lease loop see it.
struct Identity {
    client: ControlPlane,
    node_id: String,
    not_after: DateTime<Utc>,
    renew_at: Instant,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A running node.
pub struct Node {
    config: NodeConfig,
    state: StateDir,
    handler: Arc<dyn LeaseHandler>,
    spool: Arc<Spool>,
    identity: Mutex<Option<Arc<Identity>>>,
    current: Mutex<Current>,
    revoked: AtomicBool,
    started: Instant,
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node")
            .field("control_plane", &self.config.control_plane)
            .field("state_dir", &self.state.path())
            .finish_non_exhaustive()
    }
}

impl Node {
    /// Opens the state dir and the spool. Nothing talks to the control
    /// plane until [`Node::run`].
    pub fn new(config: NodeConfig, handler: Arc<dyn LeaseHandler>) -> Result<Arc<Self>, NodeError> {
        let state = StateDir::open(&config.state_dir)?;
        let first_seq = state.load_seq()?;
        let persist_to = state.clone();
        let spool = Arc::new(Spool::new(
            first_seq,
            Box::new(move |n| persist_to.store_seq(n).map_err(|e| e.to_string())),
        ));
        Ok(Arc::new(Self {
            config,
            state,
            handler,
            spool,
            identity: Mutex::new(None),
            current: Mutex::new(Current::default()),
            revoked: AtomicBool::new(false),
            started: Instant::now(),
        }))
    }

    pub fn state_dir(&self) -> &StateDir {
        &self.state
    }

    /// The spool the proxy's flow sink writes into.
    pub fn spool(&self) -> &Arc<Spool> {
        &self.spool
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }

    /// The node id once enrolled or loaded.
    pub fn node_id(&self) -> Option<String> {
        lock(&self.identity).as_ref().map(|i| i.node_id.clone())
    }

    fn scaled(&self, d: Duration) -> Duration {
        d.mul_f64(self.config.time_scale)
    }

    fn client(&self) -> Option<Arc<Identity>> {
        lock(&self.identity).clone()
    }

    /// Enrols (first start) or loads the identity, then runs the lease loop,
    /// the certificate renewal and the shipper until revoked or aborted.
    /// Returns `Err` only for what a retry cannot fix.
    pub async fn run(self: Arc<Self>) -> Result<(), NodeError> {
        self.establish_identity().await?;
        let shipper = tokio::spawn(self.clone().ship_loop());
        let renewer = tokio::spawn(self.clone().renew_loop());
        self.lease_loop().await;
        // Revoked: ship what is spooled, then stop.
        self.spool.close();
        let _ = tokio::time::timeout(self.scaled(Duration::from_secs(30)), shipper).await;
        renewer.abort();
        Ok(())
    }

    /// Ships whatever is still spooled, within `grace`.
    pub async fn drain(&self, grace: Duration) {
        self.spool.close();
        let deadline = Instant::now() + grace;
        while self.spool.pending_events() > 0 && Instant::now() < deadline {
            if !self.ship_once(&mut Stopped::default()).await {
                break;
            }
        }
    }

    async fn establish_identity(&self) -> Result<(), NodeError> {
        let (stored, renew_after) = match self.state.identity()? {
            Some(stored) => (stored, None),
            None => self.enrol().await?,
        };
        let info = identity::cert_info(&stored.cert_pem)?;
        let client = ControlPlane::with_identity(
            &self.config.control_plane,
            &self.config.trust,
            self.config.info.clone(),
            &stored.cert_pem,
            &stored.key_pem,
        )?;
        tracing::info!(
            node_id = %info.node_id,
            not_after = %info.not_after.to_rfc3339(),
            "node identity loaded"
        );
        self.install_identity(client, info.node_id, info.not_after, renew_after);
        Ok(())
    }

    fn install_identity(
        &self,
        client: ControlPlane,
        node_id: String,
        not_after: DateTime<Utc>,
        renew_after: Option<Duration>,
    ) {
        // Without a stated window, renew at two thirds of what is left.
        let renew_after = renew_after.unwrap_or_else(|| {
            let left = (not_after - Utc::now()).to_std().unwrap_or_default();
            left.mul_f64(2.0 / 3.0)
        });
        *lock(&self.identity) = Some(Arc::new(Identity {
            client,
            node_id,
            not_after,
            renew_at: Instant::now() + self.scaled(renew_after),
        }));
    }

    /// Enrols with the token, storing the identity. Also returns the
    /// renewal window the server stated.
    async fn enrol(&self) -> Result<(crate::state::StoredIdentity, Option<Duration>), NodeError> {
        let Some(token_path) = &self.config.enrol_token_file else {
            return Err(NodeError::NotEnrolled {
                dir: self.state.path().to_path_buf(),
            });
        };
        let token = std::fs::read_to_string(token_path).map_err(|source| NodeError::Token {
            path: token_path.clone(),
            source,
        })?;
        let anon = ControlPlane::unauthenticated(
            &self.config.control_plane,
            &self.config.trust,
            self.config.info.clone(),
        )?;
        let key = identity::generate_key()?;
        let mut backoff = Backoff::new();
        let issued = loop {
            let csr = identity::csr_pem(&key)?;
            match anon.enrol(&token, csr).await {
                Ok(issued) => break issued,
                Err(CertificateError::Rejected(why)) => {
                    return Err(NodeError::EnrolRejected(why));
                }
                Err(CertificateError::Failed(e)) => {
                    let wait = backoff.wait();
                    tracing::warn!(error = %e, retry_in = ?wait, "enrolment failed; retrying");
                    tokio::time::sleep(self.scaled(wait)).await;
                }
            }
        };
        let key_pem = key.serialize_pem();
        self.state
            .store_identity(&issued.certificate_chain, &key_pem)?;
        tracing::info!(node_id = %issued.node_id, "enrolled with the control plane");
        Ok((
            crate::state::StoredIdentity {
                cert_pem: issued.certificate_chain,
                key_pem,
            },
            Some(Duration::from_secs(issued.renew_after_seconds)),
        ))
    }

    fn node_state(&self) -> NodeState {
        NodeState {
            lease_id: lock(&self.current).lease_id.clone(),
            roxy_version: self.config.info.roxy_version.clone(),
            protocol_version: PROTOCOL_VERSION,
            uptime_seconds: self.started.elapsed().as_secs(),
            policy_state: self.handler.policy_state(),
            spooled_bytes: self.spool.pending_bytes(),
        }
    }

    /// Fetches at `refresh_after`, with backoff while the control plane
    /// cannot be reached; the lease runs down on its own meanwhile. Ends
    /// on revocation.
    async fn lease_loop(&self) {
        let mut backoff = Backoff::new();
        loop {
            let Some(id) = self.client() else { return };
            let state = self.node_state();
            let wait = match id.client.fetch_lease(&state).await {
                LeaseFetch::Lease(lease) => {
                    backoff.reset();
                    self.apply(&lease).await
                }
                LeaseFetch::Revoked => {
                    tracing::warn!(
                        "control plane says this node is revoked; denying everything and stopping"
                    );
                    self.revoked.store(true, Ordering::Release);
                    self.handler.revoke().await;
                    return;
                }
                LeaseFetch::Unsupported(e) => {
                    tracing::error!(
                        missing = %e.missing.join(","),
                        message = %e.message,
                        "control plane will not serve this roxy or protocol version; the lease runs down"
                    );
                    backoff.wait()
                }
                LeaseFetch::Unauthorized => {
                    tracing::error!(
                        not_after = %id.not_after.to_rfc3339(),
                        "control plane does not recognise the node certificate; the lease runs down (re-enrolment needs a new token and an empty state dir)"
                    );
                    backoff.wait()
                }
                LeaseFetch::Failed(e) => {
                    tracing::warn!(error = %e, "lease fetch failed; retrying while the lease runs down");
                    backoff.wait()
                }
            };
            tokio::time::sleep(self.scaled(wait)).await;
        }
    }

    /// Applies a fetched lease, diffing it against the one the node runs;
    /// returns how long to wait for the next fetch.
    async fn apply(&self, lease: &Lease) -> Duration {
        let received_at = Utc::now();
        let refresh = Duration::from_secs(
            lease
                .refresh_after_seconds
                .clamp(1, lease.valid_for_seconds.max(1)),
        );
        let change = {
            let current = lock(&self.current);
            Change {
                config: current.config.as_deref() != Some(&lease.config),
                secrets: current.secrets.as_ref() != Some(&lease.secrets),
                // The first lease sets the epoch without clearing anything.
                state_epoch: current
                    .state_epoch
                    .as_deref()
                    .is_some_and(|e| e != lease.state_epoch),
            }
        };
        let applied = self.handler.apply(lease, received_at, change).await;
        let mut current = lock(&self.current);
        match applied {
            Ok(()) => {
                tracing::info!(
                    lease_id = %lease.lease_id,
                    valid_for_seconds = lease.valid_for_seconds,
                    config_changed = change.config,
                    secrets_changed = change.secrets,
                    state_epoch_changed = change.state_epoch,
                    "lease applied"
                );
                self.spool.configure(lease.flow);
                *current = Current {
                    lease_id: Some(lease.lease_id.clone()),
                    config: Some(lease.config.clone()),
                    secrets: Some(lease.secrets.clone()),
                    state_epoch: Some(lease.state_epoch.clone()),
                };
            }
            Err(e) => {
                // The next fetch reports the old lease id, which is how the
                // control plane learns the lease did not take.
                tracing::error!(lease_id = %lease.lease_id, error = %e, "lease could not be applied; keeping the running policy");
            }
        }
        refresh
    }

    /// Renews the certificate at its renewal time, retrying with backoff
    /// on failure while the current one stays in use.
    async fn renew_loop(self: Arc<Self>) {
        let mut backoff = Backoff::new();
        loop {
            let Some(id) = self.client() else { return };
            tokio::time::sleep_until(id.renew_at.into()).await;
            let Some(stored) = self.state.identity().ok().flatten() else {
                return;
            };
            let Ok(key) = identity::load_key(&stored.key_pem) else {
                tracing::error!("node key in the state dir no longer parses; cannot renew");
                return;
            };
            let Ok(csr) = identity::csr_pem(&key) else {
                return;
            };
            match id.client.renew(csr).await {
                Ok(issued) => match identity::cert_info(&issued.certificate_chain) {
                    Ok(info) if info.node_id == id.node_id => {
                        if let Err(e) = self.state.store_cert(&issued.certificate_chain) {
                            tracing::error!(error = %e, "renewed certificate could not be stored; using it until restart");
                        }
                        match ControlPlane::with_identity(
                            &self.config.control_plane,
                            &self.config.trust,
                            self.config.info.clone(),
                            &issued.certificate_chain,
                            &stored.key_pem,
                        ) {
                            Ok(client) => {
                                tracing::info!(not_after = %info.not_after.to_rfc3339(), "node certificate renewed");
                                self.install_identity(
                                    client,
                                    info.node_id,
                                    info.not_after,
                                    Some(Duration::from_secs(issued.renew_after_seconds)),
                                );
                                backoff.reset();
                            }
                            Err(e) => {
                                tracing::error!(error = %e, "renewed certificate is unusable");
                            }
                        }
                    }
                    Ok(info) => tracing::error!(
                        got = %info.node_id,
                        "renewed certificate names another node; ignored"
                    ),
                    Err(e) => {
                        tracing::error!(error = %e, "renewed certificate does not parse; ignored");
                    }
                },
                Err(e) => {
                    let wait = backoff.wait();
                    tracing::warn!(error = %e, retry_in = ?wait, not_after = %id.not_after.to_rfc3339(), "certificate renewal failed; the current certificate stays in use");
                    tokio::time::sleep(self.scaled(wait)).await;
                    continue;
                }
            }
            if self.client().is_some_and(|i| Arc::ptr_eq(&i, &id)) {
                // Not replaced: try again after a backoff rather than spin.
                tokio::time::sleep(self.scaled(backoff.wait())).await;
            }
        }
    }

    /// Ships batches as they fill or every `flush_interval`, until the
    /// spool is closed and drained, or the quota is exhausted.
    async fn ship_loop(self: Arc<Self>) {
        let mut stopped = Stopped::default();
        let mut backoff = Backoff::new();
        loop {
            let settings = self.spool.settings();
            let flush = self.scaled(Duration::from_secs(settings.flush_interval_seconds.max(1)));
            let full = self.spool.pending_bytes() >= settings.batch_max_bytes;
            // Before the first lease there is nothing to tag a batch with.
            let no_lease = lock(&self.current).lease_id.is_none();
            if (!full || no_lease) && !self.spool.is_closed() {
                let _ = tokio::time::timeout(flush, self.spool.pushed.notified()).await;
            }
            if self.spool.pending_events() == 0 {
                if self.spool.is_closed() {
                    return;
                }
                continue;
            }
            if lock(&self.current).lease_id.is_none() && !self.spool.is_closed() {
                continue;
            }
            let lease_id = lock(&self.current).lease_id.clone();
            if stopped.under.is_some() && stopped.under == lease_id {
                // Shipping resumes with a new lease id; meanwhile the spool
                // applies `on_high_water`.
                let _ = tokio::time::timeout(flush, self.spool.pushed.notified()).await;
                continue;
            }
            stopped.under = None;
            if self.ship_once(&mut stopped).await {
                backoff.reset();
            } else if stopped.under.is_some() {
                if self.spool.is_closed() {
                    return;
                }
            } else {
                tokio::time::sleep(self.scaled(backoff.wait())).await;
            }
        }
    }

    /// One upload attempt. `true` when a batch was acknowledged.
    async fn ship_once(&self, stopped: &mut Stopped) -> bool {
        let Some(id) = self.client() else {
            return false;
        };
        let settings = self.spool.settings();
        let Some(batch) = self.spool.batch(settings.batch_max_bytes) else {
            return false;
        };
        let lease_id = lock(&self.current).lease_id.clone().unwrap_or_default();
        let body = encode_flow_batch(&id.node_id, &lease_id, batch.seq_first, &batch.lines);
        match id.client.ship_flows(&body).await {
            ShipOutcome::Acked(ack) => {
                self.spool.ack(ack.acked_through);
                true
            }
            ShipOutcome::QuotaExhausted => {
                tracing::error!(
                    lease_id = %lease_id,
                    spooled_bytes = self.spool.pending_bytes(),
                    on_high_water = ?settings.on_high_water,
                    "control plane flow quota exhausted for this node; flow shipping stops until a new lease"
                );
                stopped.under = Some(lease_id);
                false
            }
            ShipOutcome::Revoked => {
                tracing::warn!(
                    "control plane refuses flows from a revoked node; flow shipping stops"
                );
                stopped.under = Some(lease_id);
                false
            }
            ShipOutcome::Failed(e) => {
                tracing::warn!(error = %e, spooled_bytes = self.spool.pending_bytes(), "flow upload failed; keeping the batch");
                false
            }
        }
    }
}

/// The lease under which shipping stopped (507 or 410), if any.
#[derive(Debug, Default)]
struct Stopped {
    under: Option<String>,
}

/// Exponential backoff with jitter, capped.
#[derive(Debug)]
pub struct Backoff {
    next: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}

impl Backoff {
    pub fn new() -> Self {
        Self {
            next: BACKOFF_FIRST,
        }
    }

    pub fn reset(&mut self) {
        self.next = BACKOFF_FIRST;
    }

    /// The next wait: doubles each call up to the cap, with up to a quarter
    /// of jitter so a fleet does not retry in step.
    pub fn wait(&mut self) -> Duration {
        let base = self.next;
        self.next = (self.next * 2).min(BACKOFF_CAP);
        let jitter = {
            let mut seed = [0u8; 4];
            let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut seed);
            f64::from(u32::from_le_bytes(seed)) / f64::from(u32::MAX)
        };
        base.mul_f64(1.0 + jitter * 0.25)
    }
}

/// Reads a CA bundle for [`Trust`] from `path`.
pub fn read_trust(path: Option<&Path>) -> Result<Trust, NodeError> {
    Ok(Trust {
        ca_pem: path
            .map(|p| {
                std::fs::read_to_string(p).map_err(|source| NodeError::CaBundle {
                    path: p.to_path_buf(),
                    source,
                })
            })
            .transpose()?,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;
    use crate::protocol::FlowAck;
    use crate::testkit::{MockServer, Reply};

    struct Recorder {
        applied: Mutex<Vec<(Lease, DateTime<Utc>, Change)>>,
        revoked: AtomicUsize,
        state: Mutex<PolicyState>,
        fail_next: AtomicBool,
    }

    impl Recorder {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                applied: Mutex::new(Vec::new()),
                revoked: AtomicUsize::new(0),
                state: Mutex::new(PolicyState::None),
                fail_next: AtomicBool::new(false),
            })
        }
    }

    impl LeaseHandler for Recorder {
        fn apply<'a>(
            &'a self,
            lease: &'a Lease,
            at: DateTime<Utc>,
            change: Change,
        ) -> HandlerFuture<'a, Result<(), String>> {
            Box::pin(async move {
                if self.fail_next.swap(false, Ordering::AcqRel) {
                    return Err("config invalid: boom".into());
                }
                lock(&self.applied).push((lease.clone(), at, change));
                *lock(&self.state) = PolicyState::Loaded;
                Ok(())
            })
        }

        fn revoke(&self) -> HandlerFuture<'_, ()> {
            self.revoked.fetch_add(1, Ordering::AcqRel);
            *lock(&self.state) = PolicyState::Expired;
            Box::pin(async {})
        }

        fn policy_state(&self) -> PolicyState {
            *lock(&self.state)
        }
    }

    /// A lease whose `secrets` is `{token: <secret>}`.
    fn lease(id: &str, config: &str, secret: &str, epoch: &str) -> Lease {
        Lease {
            config: config.to_owned(),
            secrets: [("token".to_owned(), secret.to_owned())].into(),
            state_epoch: epoch.to_owned(),
            ..crate::client::tests::lease(id)
        }
    }

    struct Harness {
        mock: MockServer,
        dir: tempfile::TempDir,
        token: PathBuf,
    }

    impl Harness {
        async fn new() -> Self {
            let mock = MockServer::start().await;
            let dir = tempfile::tempdir().unwrap();
            let token = dir.path().join("token");
            std::fs::write(&token, "tok-1\n").unwrap();
            Self { mock, dir, token }
        }

        fn config(&self, with_token: bool) -> NodeConfig {
            NodeConfig {
                control_plane: self.mock.url(),
                trust: Trust {
                    ca_pem: Some(self.mock.ca.pem.clone()),
                },
                state_dir: self.dir.path().join("state"),
                enrol_token_file: with_token.then(|| self.token.clone()),
                info: NodeInfo {
                    roxy_version: "test".into(),
                },
                time_scale: 0.01,
            }
        }

        fn node(&self, with_token: bool) -> (Arc<Node>, Arc<Recorder>) {
            let rec = Recorder::new();
            let node = Node::new(self.config(with_token), rec.clone()).unwrap();
            (node, rec)
        }
    }

    const LEASE: &str = "/roxy/v1/lease";
    const FLOWS: &str = "/roxy/v1/flows";

    #[tokio::test]
    async fn first_start_enrols_and_a_restart_reuses_the_identity() {
        let h = Harness::new().await;
        h.mock.push("/roxy/v1/enrol", Reply::issue("n1"));
        let l1 = lease("L1", "version: 1\n", "s1", "e1");
        h.mock.fallback(LEASE, Reply::json(200, &l1));
        let (node, rec) = h.node(true);
        let task = tokio::spawn(node.clone().run());
        h.mock.wait_for(LEASE, 2).await;
        let fetches = h.mock.requests_to(LEASE);
        assert_eq!(fetches[0].client.as_deref(), Some("n1"));
        let first = fetches[0].node_state();
        assert_eq!(first.policy_state, PolicyState::None);
        assert_eq!(first.lease_id, None);
        let second = fetches[1].node_state();
        assert_eq!(second.lease_id.as_deref(), Some("L1"));
        assert_eq!(second.policy_state, PolicyState::Loaded);
        let applied = lock(&rec.applied).clone();
        assert_eq!(applied.len(), 1, "an identical lease is not re-applied");
        let (lease, at, change) = &applied[0];
        assert_eq!(lease.lease_id, "L1");
        assert!((Utc::now() - *at).num_seconds() < 5);
        assert_eq!(
            *change,
            Change {
                config: true,
                secrets: true,
                state_epoch: false
            },
            "the first lease sets the epoch without clearing"
        );
        assert_eq!(node.node_id().as_deref(), Some("n1"));
        task.abort();
        drop(node);

        let state = StateDir::open(&h.dir.path().join("state")).unwrap();
        assert!(state.identity().unwrap().is_some());
        let files: Vec<_> = std::fs::read_dir(h.dir.path().join("state"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert!(
            files
                .iter()
                .all(|f| ["node.crt", "node.key", "flow.seq"].contains(&f.as_str())),
            "only the identity and the counter are written: {files:?}"
        );

        // Second start: no token file, no enrol request, straight to the lease.
        let (node, _rec) = h.node(false);
        let task = tokio::spawn(node.clone().run());
        h.mock.wait_for(LEASE, 3).await;
        assert_eq!(h.mock.requests_to("/roxy/v1/enrol").len(), 1);
        task.abort();
    }

    #[tokio::test]
    async fn without_identity_or_token_the_node_cannot_start() {
        let h = Harness::new().await;
        let (node, _) = h.node(false);
        assert!(matches!(
            node.run().await,
            Err(NodeError::NotEnrolled { .. })
        ));
        h.mock.push("/roxy/v1/enrol", Reply::status(401));
        let (node, _) = h.node(true);
        assert!(matches!(node.run().await, Err(NodeError::EnrolRejected(_))));
        assert!(
            StateDir::open(&h.dir.path().join("state"))
                .unwrap()
                .identity()
                .unwrap()
                .is_none(),
            "a rejected enrolment stores nothing"
        );
    }

    #[tokio::test]
    async fn enrolment_retries_through_an_outage() {
        let h = Harness::new().await;
        h.mock.push("/roxy/v1/enrol", Reply::status(503));
        h.mock.push("/roxy/v1/enrol", Reply::Hangup);
        h.mock.push("/roxy/v1/enrol", Reply::issue("n1"));
        h.mock.fallback(LEASE, Reply::status(500));
        let (node, _) = h.node(true);
        let task = tokio::spawn(node.clone().run());
        h.mock.wait_for(LEASE, 1).await;
        assert_eq!(h.mock.requests_to("/roxy/v1/enrol").len(), 3);
        task.abort();
    }

    #[tokio::test]
    async fn the_local_diff_selects_what_is_applied() {
        let h = Harness::new().await;
        h.mock.push("/roxy/v1/enrol", Reply::issue("n1"));
        let cfg = "version: 1\n";
        h.mock
            .push(LEASE, Reply::json(200, &lease("L1", cfg, "s1", "e1")));
        // Secrets only.
        h.mock
            .push(LEASE, Reply::json(200, &lease("L2", cfg, "s2", "e1")));
        // Nothing but the lease itself: applied, so valid_until moves.
        h.mock
            .push(LEASE, Reply::json(200, &lease("L3", cfg, "s2", "e1")));
        // Config and epoch.
        let l4 = lease("L4", "version: 1\nrules: []\n", "s2", "e2");
        h.mock.push(LEASE, Reply::json(200, &l4));
        // The same lease again: nothing to apply.
        h.mock.fallback(LEASE, Reply::json(200, &l4));
        let (node, rec) = h.node(true);
        let task = tokio::spawn(node.clone().run());
        h.mock.wait_for(LEASE, 6).await;
        let changes: Vec<(String, Change)> = lock(&rec.applied)
            .iter()
            .map(|(l, _, c)| (l.lease_id.clone(), *c))
            .collect();
        let c = |config, secrets, state_epoch| Change {
            config,
            secrets,
            state_epoch,
        };
        assert_eq!(
            changes[..4],
            [
                ("L1".to_owned(), c(true, true, false)),
                ("L2".to_owned(), c(false, true, false)),
                ("L3".to_owned(), c(false, false, false)),
                ("L4".to_owned(), c(true, false, true)),
            ]
        );
        // Every later poll re-applies L4 with nothing changed, which is
        // what moves `valid_until` forward.
        assert!(changes.len() > 4);
        assert!(
            changes[4..]
                .iter()
                .all(|(id, ch)| id == "L4" && *ch == c(false, false, false)),
            "{changes:?}"
        );
        let last = h.mock.requests_to(LEASE).pop().unwrap();
        assert_eq!(last.node_state().lease_id.as_deref(), Some("L4"));
        task.abort();
    }

    #[tokio::test]
    async fn a_lease_the_handler_refuses_keeps_the_old_one_reported() {
        let h = Harness::new().await;
        h.mock.push("/roxy/v1/enrol", Reply::issue("n1"));
        let l1 = lease("L1", "version: 1\n", "s1", "e1");
        h.mock.push(LEASE, Reply::json(200, &l1));
        h.mock.push(
            LEASE,
            Reply::json(200, &lease("L2", "version: 2\n", "s1", "e1")),
        );
        h.mock.fallback(LEASE, Reply::json(200, &l1));
        let (node, rec) = h.node(true);
        let task = tokio::spawn(node.clone().run());
        tokio::time::timeout(Duration::from_secs(10), async {
            while lock(&rec.applied).is_empty() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        rec.fail_next.store(true, Ordering::Release);
        h.mock.wait_for(LEASE, 3).await;
        let third = &h.mock.requests_to(LEASE)[2];
        assert_eq!(third.node_state().lease_id.as_deref(), Some("L1"));
        assert_eq!(lock(&rec.applied).len(), 1);
        task.abort();
    }

    #[tokio::test]
    async fn revocation_denies_at_once_and_ends_the_node() {
        let h = Harness::new().await;
        h.mock.push("/roxy/v1/enrol", Reply::issue("n1"));
        h.mock.push(
            LEASE,
            Reply::json(200, &lease("L1", "version: 1\n", "s1", "e1")),
        );
        h.mock.push(LEASE, Reply::status(410));
        h.mock.fallback(LEASE, Reply::status(500));
        h.mock.fallback(
            FLOWS,
            Reply::json(
                200,
                &FlowAck {
                    acked_through: u64::MAX,
                },
            ),
        );
        let (node, rec) = h.node(true);
        let spool = node.spool().clone();
        let task = tokio::spawn(node.clone().run());
        h.mock.wait_for(LEASE, 1).await;
        spool.push(b"{\"event\":\"request\"}");
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("run ends on revocation")
            .unwrap()
            .unwrap();
        assert_eq!(rec.revoked.load(Ordering::Acquire), 1);
        assert!(node.is_revoked());
        assert_eq!(h.mock.requests_to(LEASE).len(), 2, "no fetch after 410");
        assert!(
            !h.mock.requests_to(FLOWS).is_empty(),
            "spooled flows drained"
        );
        assert!(spool.is_closed());
        spool.push(b"{}");
        assert_eq!(spool.pending_events(), 0);
    }

    #[tokio::test]
    async fn errors_let_the_lease_run_down_and_keep_polling() {
        let h = Harness::new().await;
        h.mock.push("/roxy/v1/enrol", Reply::issue("n1"));
        h.mock.push(
            LEASE,
            Reply::json(200, &lease("L1", "version: 1\n", "s1", "e1")),
        );
        h.mock.push(LEASE, Reply::status(401));
        h.mock.push(
            LEASE,
            Reply::json(
                426,
                &crate::protocol::ErrorBody {
                    error: "unsupported".into(),
                    message: "roxy test is below the floor".into(),
                    missing: vec!["roxy_version:9".into()],
                },
            ),
        );
        h.mock.push(LEASE, Reply::status(500));
        h.mock.push(LEASE, Reply::Hangup);
        let l2 = lease("L2", "version: 1\n", "s1", "e1");
        h.mock.push(LEASE, Reply::json(200, &l2));
        h.mock.fallback(LEASE, Reply::json(200, &l2));
        let (node, rec) = h.node(true);
        let task = tokio::spawn(node.clone().run());
        h.mock.wait_for(LEASE, 7).await;
        let ids: Vec<_> = lock(&rec.applied)
            .iter()
            .map(|(l, ..)| l.lease_id.clone())
            .collect();
        assert_eq!(ids, ["L1", "L2"]);
        assert_eq!(rec.revoked.load(Ordering::Acquire), 0);
        assert!(!node.is_revoked());
        assert_eq!(
            h.mock.requests_to("/roxy/v1/enrol").len(),
            1,
            "401 never re-enrols"
        );
        task.abort();
    }

    #[tokio::test]
    async fn flows_ship_in_seq_order_and_acks_drop_them() {
        let h = Harness::new().await;
        h.mock.push("/roxy/v1/enrol", Reply::issue("n1"));
        let mut l = lease("L1", "version: 1\n", "s1", "e1");
        // Two tagged events of the shape pushed below fit; three do not.
        l.flow.batch_max_bytes = 70;
        l.flow.flush_interval_seconds = 1;
        h.mock.fallback(LEASE, Reply::json(200, &l));
        h.mock
            .push(FLOWS, Reply::json(200, &FlowAck { acked_through: 1 }));
        h.mock.push(FLOWS, Reply::status(503));
        h.mock
            .push(FLOWS, Reply::json(200, &FlowAck { acked_through: 2 }));
        let (node, _) = h.node(true);
        let spool = node.spool().clone();
        let task = tokio::spawn(node.clone().run());
        h.mock.wait_for(LEASE, 1).await;
        for i in 0..3 {
            spool.push(format!("{{\"event\":\"request\",\"i\":{i}}}").as_bytes());
        }
        let posts = h.mock.wait_for(FLOWS, 3).await;
        let first = posts[0].json();
        assert_eq!(first["node_id"], "n1");
        assert_eq!(first["lease_id"], "L1");
        assert_eq!(first["seq_first"], 0);
        assert_eq!(first["events"].as_array().unwrap().len(), 2);
        assert_eq!(first["events"][1]["seq"], 1);
        assert_eq!(first["events"][1]["i"], 1);
        // After the 503 the same batch (seq 2) is retried: at-least-once.
        assert_eq!(posts[1].json()["seq_first"], 2);
        assert_eq!(posts[2].json()["seq_first"], 2);
        tokio::time::timeout(Duration::from_secs(5), async {
            while spool.pending_events() > 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        task.abort();
    }

    #[tokio::test]
    async fn quota_exhaustion_stops_shipping_until_a_new_lease() {
        let h = Harness::new().await;
        h.mock.push("/roxy/v1/enrol", Reply::issue("n1"));
        let mut l = lease("L1", "version: 1\n", "s1", "e1");
        l.flow.flush_interval_seconds = 1;
        h.mock.fallback(LEASE, Reply::json(200, &l));
        // A 413 for a batch within the stated size is a server error: the
        // same batch is retried whole.
        h.mock.push(FLOWS, Reply::status(413));
        h.mock
            .push(FLOWS, Reply::json(200, &FlowAck { acked_through: 1 }));
        h.mock.push(FLOWS, Reply::status(507));
        h.mock.fallback(
            FLOWS,
            Reply::json(
                200,
                &FlowAck {
                    acked_through: u64::MAX,
                },
            ),
        );
        let (node, _) = h.node(true);
        let spool = node.spool().clone();
        let task = tokio::spawn(node.clone().run());
        h.mock.wait_for(LEASE, 1).await;
        for i in 0..4 {
            spool.push(format!("{{\"i\":{i}}}").as_bytes());
        }
        let posts = h.mock.wait_for(FLOWS, 3).await;
        assert_eq!(posts[0].json()["events"].as_array().unwrap().len(), 4);
        assert_eq!(
            posts[1].json()["events"].as_array().unwrap().len(),
            4,
            "retried whole"
        );
        assert_eq!(posts[2].json()["seq_first"], 2);
        // 507: nothing more is sent under this lease, whatever is pushed.
        for i in 4..8 {
            spool.push(format!("{{\"i\":{i}}}").as_bytes());
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(h.mock.requests_to(FLOWS).len(), 3);
        assert_eq!(
            spool.pending_events(),
            6,
            "events stay spooled up to the high water"
        );
        // A new lease id resumes shipping.
        let mut l2 = lease("L2", "version: 1\n", "s1", "e1");
        l2.flow.flush_interval_seconds = 1;
        h.mock.fallback(LEASE, Reply::json(200, &l2));
        h.mock.wait_for(FLOWS, 4).await;
        assert_eq!(h.mock.requests_to(FLOWS)[3].json()["lease_id"], "L2");
        task.abort();
    }

    #[tokio::test]
    async fn the_certificate_is_renewed_inside_its_window() {
        let h = Harness::new().await;
        h.mock.push(
            "/roxy/v1/enrol",
            Reply::Issue {
                node_id: "n1".into(),
                lifetime_secs: 3600,
                renew_after_seconds: 1,
            },
        );
        h.mock.push(
            "/roxy/v1/renew",
            Reply::Issue {
                node_id: "n1".into(),
                lifetime_secs: 7200,
                renew_after_seconds: 3000,
            },
        );
        h.mock.fallback(
            LEASE,
            Reply::json(200, &lease("L1", "version: 1\n", "s1", "e1")),
        );
        let (node, _) = h.node(true);
        let state = node.state_dir().clone();
        let task = tokio::spawn(node.clone().run());
        h.mock.wait_for(LEASE, 1).await;
        let before = state.identity().unwrap().unwrap().cert_pem;
        let renew = h.mock.wait_for("/roxy/v1/renew", 1).await;
        assert_eq!(
            renew[0].client.as_deref(),
            Some("n1"),
            "renewal is under the old cert"
        );
        assert!(
            renew[0].json()["csr"]
                .as_str()
                .unwrap()
                .contains("CERTIFICATE REQUEST")
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            while state.identity().unwrap().unwrap().cert_pem == before {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the stored certificate is replaced");
        let after = identity::cert_info(&state.identity().unwrap().unwrap().cert_pem).unwrap();
        assert!((after.not_after - Utc::now()).num_seconds() > 7000);
        // Later fetches use the new certificate.
        h.mock.wait_for(LEASE, 3).await;
        assert_eq!(
            h.mock.requests_to(LEASE).last().unwrap().client.as_deref(),
            Some("n1")
        );
        task.abort();
    }

    #[tokio::test]
    async fn a_failed_renewal_keeps_the_current_certificate_and_retries() {
        let h = Harness::new().await;
        h.mock.push(
            "/roxy/v1/enrol",
            Reply::Issue {
                node_id: "n1".into(),
                lifetime_secs: 3600,
                renew_after_seconds: 1,
            },
        );
        h.mock.push("/roxy/v1/renew", Reply::status(500));
        h.mock.push("/roxy/v1/renew", Reply::status(401));
        h.mock.fallback(
            "/roxy/v1/renew",
            Reply::Issue {
                node_id: "n1".into(),
                lifetime_secs: 7200,
                renew_after_seconds: 3000,
            },
        );
        h.mock.fallback(
            LEASE,
            Reply::json(200, &lease("L1", "version: 1\n", "s1", "e1")),
        );
        let (node, _) = h.node(true);
        let task = tokio::spawn(node.clone().run());
        let renewals = h.mock.wait_for("/roxy/v1/renew", 3).await;
        assert!(renewals.iter().all(|r| r.client.as_deref() == Some("n1")));
        h.mock.wait_for(LEASE, 2).await;
        task.abort();
    }

    #[test]
    fn backoff_doubles_to_the_cap() {
        let mut b = Backoff::new();
        let waits: Vec<_> = (0..8).map(|_| b.wait()).collect();
        assert!(waits[0] >= Duration::from_secs(1) && waits[0] < Duration::from_millis(1250));
        assert!(waits[1] >= Duration::from_secs(2) && waits[1] < Duration::from_millis(2500));
        assert!(waits[7] >= Duration::from_secs(60) && waits[7] < Duration::from_secs(76));
        b.reset();
        assert!(b.wait() < Duration::from_secs(2));
    }
}
