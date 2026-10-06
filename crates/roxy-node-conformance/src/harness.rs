//! The conformance checks. Each check pins one statement of the spec and
//! fails with the status, header or body it saw. Checks that need the server
//! to act on its own initiative (revoke, forget, require a feature, exhaust
//! a quota) go through a [`Hook`]; without one they are skipped and the run
//! does not pass.

use std::fmt::Write as _;
use std::io::Write;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Context, anyhow, ensure};
use http::StatusCode;
use rcgen::{KeyPair, PublicKeyData};
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;

use crate::ca::{first_cert_der, inspect_node_cert, node_csr};
use crate::protocol::{
    EnrolRequest, EnrolResponse, ErrorBody, FlowAck, FlowBatch, Lease, NodeState,
};
use crate::{
    LEASE_REFRESH_AFTER_HEADER, LEASE_VALID_FOR_HEADER, NODE_STATE_HEADER, PREFIX,
    UNSUPPORTED_FEATURE, client, schema, sha256_tag,
};

/// A way to make the server take an action against a node. `action` is one
/// of `revoke`, `forget`, `require-feature` (with the feature name as the
/// argument) or `exhaust-flow-quota`.
pub trait Hook: Send + Sync {
    fn call(
        &self,
        action: String,
        node_id: String,
        argument: Option<String>,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + '_>>;
}

/// Runs `<command> <action> <node_id> [<argument>]` and expects exit 0.
pub struct CommandHook(pub String);

impl Hook for CommandHook {
    fn call(
        &self,
        action: String,
        node_id: String,
        argument: Option<String>,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + '_>> {
        let mut cmd = tokio::process::Command::new(&self.0);
        cmd.arg(&action).arg(node_id).args(argument);
        Box::pin(async move {
            let status = cmd
                .status()
                .await
                .with_context(|| format!("run hook {}", self.0))?;
            ensure!(
                status.success(),
                "hook {} {action} exited with {status}",
                self.0
            );
            Ok(())
        })
    }
}

/// `POST`s `{"action", "node_id", "argument"}` to a URL, as the reference
/// server's admin listener accepts.
pub struct AdminUrlHook {
    url: String,
    client: reqwest::Client,
}

impl AdminUrlHook {
    pub fn new(url: &str) -> anyhow::Result<Self> {
        Ok(Self {
            url: url.to_owned(),
            client: client::build(None, None)?,
        })
    }
}

impl Hook for AdminUrlHook {
    fn call(
        &self,
        action: String,
        node_id: String,
        argument: Option<String>,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + '_>> {
        let body = json!({"action": action, "node_id": node_id, "argument": argument});
        Box::pin(async move {
            let res = self
                .client
                .post(&self.url)
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(body.to_string())
                .send()
                .await
                .context("admin request")?;
            ensure!(
                res.status().is_success(),
                "admin {action} answered {}",
                res.status()
            );
            Ok(())
        })
    }
}

#[derive(Debug, Clone)]
pub struct Options {
    pub url: String,
    pub ca_bundle_pem: Option<String>,
    pub tokens: Vec<String>,
    pub hook: Option<Arc<dyn Hook>>,
}

impl std::fmt::Debug for dyn Hook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Hook")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Passed,
    Failed(String),
    Skipped(String),
}

#[derive(Debug, Clone)]
pub struct CheckResult {
    pub name: &'static str,
    pub outcome: Outcome,
}

#[derive(Debug, Default)]
pub struct Report {
    pub results: Vec<CheckResult>,
}

impl Report {
    /// True when every check passed. A skipped check is not a pass: the
    /// server has not been shown to produce that response.
    pub fn ok(&self) -> bool {
        self.results.iter().all(|r| r.outcome == Outcome::Passed)
    }

    pub fn write(&self, mut w: impl Write) -> std::io::Result<()> {
        let (mut passed, mut failed, mut skipped) = (0, 0, 0);
        for r in &self.results {
            match &r.outcome {
                Outcome::Passed => {
                    passed += 1;
                    writeln!(w, "ok    {}", r.name)?;
                }
                Outcome::Failed(why) => {
                    failed += 1;
                    writeln!(w, "FAIL  {}: {why}", r.name)?;
                }
                Outcome::Skipped(why) => {
                    skipped += 1;
                    writeln!(w, "skip  {}: {why}", r.name)?;
                }
            }
        }
        writeln!(w, "{passed} passed, {failed} failed, {skipped} skipped")
    }

    async fn check<F>(&mut self, name: &'static str, f: F)
    where
        F: Future<Output = anyhow::Result<()>>,
    {
        let outcome = match f.await {
            Ok(()) => Outcome::Passed,
            Err(e) => Outcome::Failed(format!("{e:#}")),
        };
        self.results.push(CheckResult { name, outcome });
    }

    fn skip(&mut self, name: &'static str, why: &str) {
        self.results.push(CheckResult {
            name,
            outcome: Outcome::Skipped(why.to_owned()),
        });
    }
}

/// The features a harness node reports. [`UNSUPPORTED_FEATURE`] is never
/// among them.
const FEATURES: &[&str] = &[
    "valid_until",
    "sourceless_secrets",
    "readyz",
    "action:allow",
    "action:deny",
];
const ROXY_VERSION: &str = "0.0.0-conformance";

struct Ctx {
    opts: Options,
    anon: reqwest::Client,
}

/// An enrolled node as the harness sees it.
struct Node {
    id: String,
    chain_pem: String,
    client: reqwest::Client,
}

impl Ctx {
    fn url(&self, path: &str) -> String {
        format!("{}{PREFIX}{path}", self.opts.url.trim_end_matches('/'))
    }

    fn enrol_request(csr: String, protocol_version: u32) -> EnrolRequest {
        EnrolRequest {
            csr,
            roxy_version: ROXY_VERSION.to_owned(),
            protocol_version,
            features: FEATURES.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    async fn post_enrol(
        &self,
        token: &str,
        body: &EnrolRequest,
    ) -> anyhow::Result<reqwest::Response> {
        self.anon
            .post(self.url("/enrol"))
            .bearer_auth(token)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(body)?)
            .send()
            .await
            .context("POST /enrol")
    }

    /// Enrol a fresh node with `token`, checking everything the spec says
    /// about the response and the certificate.
    async fn enrol(&self, token: &str) -> anyhow::Result<Node> {
        let (key, csr) = node_csr()?;
        let res = self.post_enrol(token, &Self::enrol_request(csr, 1)).await?;
        let status = res.status();
        let body = res.bytes().await?;
        ensure!(
            status == StatusCode::OK,
            "enrol answered {status}: {}",
            String::from_utf8_lossy(&body)
        );
        let v: Value = serde_json::from_slice(&body).context("enrol response is not JSON")?;
        schema::validate("enrol-response", &v).map_err(|e| anyhow!(e))?;
        let res: EnrolResponse = serde_json::from_value(v)?;
        check_issued(&res, &key, None)?;
        let client = client::build(
            self.opts.ca_bundle_pem.as_deref(),
            Some((&res.certificate_chain, &key.serialize_pem())),
        )?;
        Ok(Node {
            id: res.node_id,
            chain_pem: res.certificate_chain,
            client,
        })
    }

    fn state(lease: Option<&Lease>) -> NodeState {
        NodeState {
            lease_id: lease.map(|l| l.lease_id.clone()),
            config_hash: lease.map(|l| l.config_hash.clone()),
            secrets_hash: lease.map(|l| l.secrets_hash.clone()),
            roxy_version: ROXY_VERSION.to_owned(),
            protocol_version: 1,
            features: FEATURES.iter().map(|s| (*s).to_owned()).collect(),
            uptime_seconds: 60,
            policy_state: if lease.is_some() { "loaded" } else { "none" }.to_owned(),
            spooled_bytes: 0,
        }
    }

    async fn get_lease(
        &self,
        client: &reqwest::Client,
        state: Option<&NodeState>,
        if_none_match: Option<&str>,
    ) -> anyhow::Result<reqwest::Response> {
        let mut req = client.get(self.url("/lease"));
        if let Some(s) = state {
            let v = serde_json::to_value(s)?;
            schema::validate("node-state", &v).map_err(|e| anyhow!(e))?;
            req = req.header(NODE_STATE_HEADER, v.to_string());
        }
        if let Some(etag) = if_none_match {
            req = req.header(http::header::IF_NONE_MATCH, format!("\"{etag}\""));
        }
        req.send().await.context("GET /lease")
    }

    /// Fetch a lease expecting `200`, and check it against the spec.
    async fn lease_200(&self, node: &Node, current: Option<&Lease>) -> anyhow::Result<Lease> {
        let res = self
            .get_lease(
                &node.client,
                Some(&Self::state(current)),
                current.map(|l| l.lease_id.as_str()),
            )
            .await?;
        let status = res.status();
        let etag = res
            .headers()
            .get(http::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = res.bytes().await?;
        ensure!(
            status == StatusCode::OK,
            "lease answered {status}: {}",
            String::from_utf8_lossy(&body)
        );
        let v: Value = serde_json::from_slice(&body).context("lease is not JSON")?;
        schema::validate("lease", &v).map_err(|e| anyhow!(e))?;
        let lease: Lease = serde_json::from_value(v)?;
        ensure!(
            etag.as_deref() == Some(&format!("\"{}\"", lease.lease_id)),
            "ETag {etag:?} is not the quoted lease_id {:?}",
            lease.lease_id
        );
        let expected = sha256_tag(lease.config.as_bytes());
        ensure!(
            lease.config_hash == expected,
            "config_hash {} but config hashes to {expected}",
            lease.config_hash
        );
        ensure!(
            lease.refresh_after_seconds < lease.valid_for_seconds,
            "refresh_after_seconds {} is not inside valid_for_seconds {}",
            lease.refresh_after_seconds,
            lease.valid_for_seconds
        );
        Ok(lease)
    }

    async fn post_flows(
        &self,
        node: &Node,
        batch: &FlowBatch,
        gzip: bool,
    ) -> anyhow::Result<reqwest::Response> {
        let json = serde_json::to_vec(batch)?;
        schema::validate("flow-batch", &serde_json::from_slice(&json)?).map_err(|e| anyhow!(e))?;
        let mut req = node
            .client
            .post(self.url("/flows"))
            .header(http::header::CONTENT_TYPE, "application/json");
        let body = if gzip {
            let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            enc.write_all(&json)?;
            req = req.header(http::header::CONTENT_ENCODING, "gzip");
            enc.finish()?
        } else {
            json
        };
        req.body(body).send().await.context("POST /flows")
    }

    async fn ack(&self, node: &Node, batch: &FlowBatch, gzip: bool) -> anyhow::Result<u64> {
        let res = self.post_flows(node, batch, gzip).await?;
        let status = res.status();
        let body = res.bytes().await?;
        ensure!(
            status == StatusCode::OK,
            "flows answered {status}: {}",
            String::from_utf8_lossy(&body)
        );
        let v: Value = serde_json::from_slice(&body).context("ack is not JSON")?;
        schema::validate("flow-ack", &v).map_err(|e| anyhow!(e))?;
        let ack: FlowAck = serde_json::from_value(v)?;
        Ok(ack.acked_through)
    }

    async fn hook(
        &self,
        action: &str,
        node_id: &str,
        argument: Option<&str>,
    ) -> anyhow::Result<()> {
        let hook = self.opts.hook.as_ref().ok_or_else(|| anyhow!("no hook"))?;
        hook.call(
            action.to_owned(),
            node_id.to_owned(),
            argument.map(str::to_owned),
        )
        .await
        .with_context(|| format!("hook {action} {node_id}"))
    }
}

/// Check an enrol or renew response against its key and, on renewal, the
/// node id it must keep.
fn check_issued(
    res: &EnrolResponse,
    key: &KeyPair,
    expect_node_id: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(id) = expect_node_id {
        ensure!(
            res.node_id == id,
            "node_id changed from {id} to {}",
            res.node_id
        );
    }
    let der = first_cert_der(&res.certificate_chain)?;
    let cert = inspect_node_cert(&der)?;
    ensure!(
        cert.node_id.as_deref() == Some(res.node_id.as_str()),
        "certificate SAN names {:?}, response names {}",
        cert.node_id,
        res.node_id
    );
    ensure!(
        cert.san_count == 1,
        "certificate has {} SANs; only the node URI is allowed",
        cert.san_count
    );
    ensure!(
        cert.spki_der == key.subject_public_key_info(),
        "certificate public key is not the CSR's key"
    );
    let stated = time::OffsetDateTime::parse(&res.not_after, &Rfc3339)
        .context("not_after is not RFC 3339")?;
    ensure!(
        stated.unix_timestamp() == cert.not_after.unix_timestamp(),
        "not_after {} differs from the certificate's {}",
        res.not_after,
        cert.not_after.format(&Rfc3339).unwrap_or_default()
    );
    let lifetime = (cert.not_after - time::OffsetDateTime::now_utc()).whole_seconds();
    ensure!(
        i128::from(res.renew_after_seconds) < i128::from(lifetime),
        "renew_after_seconds {} is not inside the certificate lifetime ({lifetime}s)",
        res.renew_after_seconds
    );
    Ok(())
}

/// Read an error response: the status must be `expected` and the body must
/// validate as `error.json`.
async fn expect_error(res: reqwest::Response, expected: StatusCode) -> anyhow::Result<ErrorBody> {
    let status = res.status();
    let body = res.bytes().await?;
    ensure!(
        status == expected,
        "expected {expected}, got {status}: {}",
        String::from_utf8_lossy(&body)
    );
    let v: Value = serde_json::from_slice(&body).with_context(|| {
        format!(
            "{status} body is not JSON: {}",
            String::from_utf8_lossy(&body)
        )
    })?;
    schema::validate("error", &v).map_err(|e| anyhow!(e))?;
    Ok(serde_json::from_value(v)?)
}

fn event(seq: u64, padding: usize) -> Value {
    let mut v = json!({
        "seq": seq,
        "ts": "2026-10-06T10:12:00.123Z",
        "event": "request",
        "flow": format!("conf-{seq}"),
        "decision": "deny",
        "terminal_rule": "_default",
    });
    if padding > 0 {
        v["pad"] = Value::String("x".repeat(padding));
    }
    v
}

fn batch(node: &Node, lease: &Lease, first: u64, count: u64) -> FlowBatch {
    FlowBatch {
        node_id: node.id.clone(),
        lease_id: lease.lease_id.clone(),
        seq_first: first,
        events: (first..first + count).map(|s| event(s, 0)).collect(),
    }
}

/// Run every check against `opts.url`.
#[allow(clippy::too_many_lines)]
pub async fn run(opts: Options) -> anyhow::Result<Report> {
    ensure!(
        opts.tokens.len() >= 5,
        "the harness needs five enrolment tokens, got {}",
        opts.tokens.len()
    );
    let anon = client::build(opts.ca_bundle_pem.as_deref(), None)?;
    let ctx = Ctx { opts, anon };
    let mut report = Report::default();
    let tokens = ctx.opts.tokens.clone();

    report
        .check("enrol: unknown token is 401", async {
            let (_, csr) = node_csr()?;
            let res = ctx
                .post_enrol("not-a-token", &Ctx::enrol_request(csr, 1))
                .await?;
            expect_error(res, StatusCode::UNAUTHORIZED).await?;
            Ok(())
        })
        .await;

    report
        .check("enrol: malformed CSR is 400", async {
            let req = Ctx::enrol_request(
                "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"
                    .to_owned(),
                1,
            );
            let res = ctx.post_enrol(&tokens[1], &req).await?;
            expect_error(res, StatusCode::BAD_REQUEST).await?;
            Ok(())
        })
        .await;

    report
        .check(
            "enrol: unsupported protocol_version is 426 naming it, token kept",
            async {
                let (_, csr) = node_csr()?;
                let res = ctx
                    .post_enrol(&tokens[1], &Ctx::enrol_request(csr, 2))
                    .await?;
                let err = expect_error(res, StatusCode::UPGRADE_REQUIRED).await?;
                let missing = err.missing.unwrap_or_default();
                ensure!(
                    missing.iter().any(|m| m == "protocol_version:1"),
                    "missing {missing:?} does not name protocol_version:1"
                );
                Ok(())
            },
        )
        .await;

    let mut node_a = None;
    report
        .check(
            "enrol: token exchanged for a node certificate with the node URI SAN",
            async {
                node_a = Some(ctx.enrol(&tokens[0]).await?);
                Ok(())
            },
        )
        .await;
    let Some(node_a) = node_a else {
        return Ok(report);
    };

    report
        .check("enrol: token is single-use", async {
            let (_, csr) = node_csr()?;
            let res = ctx
                .post_enrol(&tokens[0], &Ctx::enrol_request(csr, 1))
                .await?;
            expect_error(res, StatusCode::UNAUTHORIZED).await?;
            Ok(())
        })
        .await;

    report
        .check("lease: no client certificate is 401", async {
            let res = ctx
                .get_lease(&ctx.anon, Some(&Ctx::state(None)), None)
                .await?;
            expect_error(res, StatusCode::UNAUTHORIZED).await?;
            Ok(())
        })
        .await;

    report
        .check("lease: missing Roxy-Node-State is 400", async {
            let res = ctx.get_lease(&node_a.client, None, None).await?;
            expect_error(res, StatusCode::BAD_REQUEST).await?;
            Ok(())
        })
        .await;

    let mut lease_a = None;
    report
        .check(
            "lease: first fetch is 200 with ETag, config_hash and refresh inside validity",
            async {
                lease_a = Some(ctx.lease_200(&node_a, None).await?);
                Ok(())
            },
        )
        .await;
    let Some(lease_a) = lease_a else {
        return Ok(report);
    };

    report
        .check(
            "lease: matching If-None-Match is 304 with the extension headers",
            async {
                let state = Ctx::state(Some(&lease_a));
                let res = ctx
                    .get_lease(&node_a.client, Some(&state), Some(&lease_a.lease_id))
                    .await?;
                ensure!(
                    res.status() == StatusCode::NOT_MODIFIED,
                    "expected 304, got {}",
                    res.status()
                );
                for (header, expected) in [
                    (LEASE_VALID_FOR_HEADER, lease_a.valid_for_seconds),
                    (LEASE_REFRESH_AFTER_HEADER, lease_a.refresh_after_seconds),
                ] {
                    let v = res
                        .headers()
                        .get(header)
                        .and_then(|v| v.to_str().ok())
                        .ok_or_else(|| anyhow!("304 lacks {header}"))?;
                    let n: u64 = v
                        .parse()
                        .with_context(|| format!("{header}: {v:?} is not an integer"))?;
                    ensure!(n == expected, "{header} is {n}, lease said {expected}");
                }
                let body = res.bytes().await?;
                ensure!(
                    body.is_empty(),
                    "304 carried a body of {} bytes",
                    body.len()
                );
                Ok(())
            },
        )
        .await;

    report
        .check(
            "lease: stale If-None-Match is 200 with the current lease",
            async {
                let mut state = Ctx::state(Some(&lease_a));
                state.lease_id = Some("stale".to_owned());
                let res = ctx
                    .get_lease(&node_a.client, Some(&state), Some("stale"))
                    .await?;
                ensure!(
                    res.status() == StatusCode::OK,
                    "expected 200, got {}",
                    res.status()
                );
                let v: Value = serde_json::from_slice(&res.bytes().await?)?;
                ensure!(
                    v["lease_id"] == json!(lease_a.lease_id),
                    "lease_id changed to {}",
                    v["lease_id"]
                );
                Ok(())
            },
        )
        .await;

    let mut renewed = None;
    report
        .check(
            "renew: new CSR gets a new certificate for the same node id",
            async {
                let (key, csr) = node_csr()?;
                let res = node_a
                    .client
                    .post(ctx.url("/renew"))
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(serde_json::to_vec(&Ctx::enrol_request(csr, 1))?)
                    .send()
                    .await
                    .context("POST /renew")?;
                let status = res.status();
                let body = res.bytes().await?;
                ensure!(
                    status == StatusCode::OK,
                    "renew answered {status}: {}",
                    String::from_utf8_lossy(&body)
                );
                let v: Value = serde_json::from_slice(&body)?;
                schema::validate("enrol-response", &v).map_err(|e| anyhow!(e))?;
                let res: EnrolResponse = serde_json::from_value(v)?;
                check_issued(&res, &key, Some(&node_a.id))?;
                ensure!(
                    first_cert_der(&res.certificate_chain)? != first_cert_der(&node_a.chain_pem)?,
                    "renew returned the old certificate"
                );
                renewed = Some(Node {
                    id: node_a.id.clone(),
                    client: client::build(
                        ctx.opts.ca_bundle_pem.as_deref(),
                        Some((&res.certificate_chain, &key.serialize_pem())),
                    )?,
                    chain_pem: res.certificate_chain,
                });
                Ok(())
            },
        )
        .await;

    if let Some(renewed) = &renewed {
        report
            .check("renew: the new certificate fetches the lease", async {
                let state = Ctx::state(Some(&lease_a));
                let res = ctx
                    .get_lease(&renewed.client, Some(&state), Some(&lease_a.lease_id))
                    .await?;
                ensure!(
                    res.status() == StatusCode::NOT_MODIFIED || res.status() == StatusCode::OK,
                    "expected 200 or 304 with the renewed certificate, got {}",
                    res.status()
                );
                Ok(())
            })
            .await;
    }

    report
        .check("flows: batch is acked through its last seq", async {
            let acked = ctx
                .ack(&node_a, &batch(&node_a, &lease_a, 1, 3), false)
                .await?;
            ensure!(acked == 3, "acked_through {acked}, sent 1..=3");
            Ok(())
        })
        .await;

    report
        .check("flows: re-sent batch is acked idempotently", async {
            let acked = ctx
                .ack(&node_a, &batch(&node_a, &lease_a, 1, 3), false)
                .await?;
            ensure!(acked == 3, "re-send of 1..=3 acked through {acked}");
            let acked = ctx
                .ack(&node_a, &batch(&node_a, &lease_a, 4, 2), false)
                .await?;
            ensure!(acked == 5, "4..=5 acked through {acked}");
            let acked = ctx
                .ack(&node_a, &batch(&node_a, &lease_a, 1, 3), false)
                .await?;
            ensure!(
                acked == 5,
                "late re-send of 1..=3 moved acked_through to {acked}"
            );
            Ok(())
        })
        .await;

    report
        .check("flows: gzip body is accepted", async {
            let acked = ctx
                .ack(&node_a, &batch(&node_a, &lease_a, 6, 2), true)
                .await?;
            ensure!(acked == 7, "gzip 6..=7 acked through {acked}");
            Ok(())
        })
        .await;

    report
        .check(
            "flows: node_id not matching the certificate is 400",
            async {
                let mut b = batch(&node_a, &lease_a, 8, 1);
                b.node_id = String::from("someone-else");
                expect_error(
                    ctx.post_flows(&node_a, &b, false).await?,
                    StatusCode::BAD_REQUEST,
                )
                .await?;
                Ok(())
            },
        )
        .await;

    report
        .check("flows: non-consecutive seq is 400", async {
            let mut b = batch(&node_a, &lease_a, 8, 2);
            b.events[1]["seq"] = json!(10);
            expect_error(
                ctx.post_flows(&node_a, &b, false).await?,
                StatusCode::BAD_REQUEST,
            )
            .await?;
            Ok(())
        })
        .await;

    report
        .check("flows: batch over batch_max_bytes is 413", async {
            let max = usize::try_from(lease_a.flow.batch_max_bytes).unwrap_or(usize::MAX);
            ensure!(
                max <= 64 * 1024 * 1024,
                "batch_max_bytes {max} is too large to exceed in a test"
            );
            let mut b = batch(&node_a, &lease_a, 8, 1);
            b.events[0] = event(8, max);
            expect_error(
                ctx.post_flows(&node_a, &b, false).await?,
                StatusCode::PAYLOAD_TOO_LARGE,
            )
            .await?;
            Ok(())
        })
        .await;

    if ctx.opts.hook.is_none() {
        for name in [
            "revoke: lease is 410",
            "revoke: flows is 410",
            "forget: unrecognised certificate is 401",
            "features: missing feature is 426 naming it",
            "flows: exhausted quota is 507",
        ] {
            report.skip(name, "needs --hook or --admin-url");
        }
        return Ok(report);
    }

    let mut node_b = None;
    report
        .check("revoke: lease is 410", async {
            let node = ctx.enrol(&tokens[1]).await?;
            let lease = ctx.lease_200(&node, None).await?;
            ctx.hook("revoke", &node.id, None).await?;
            let res = ctx
                .get_lease(
                    &node.client,
                    Some(&Ctx::state(Some(&lease))),
                    Some(&lease.lease_id),
                )
                .await?;
            expect_error(res, StatusCode::GONE).await?;
            node_b = Some((node, lease));
            Ok(())
        })
        .await;
    if let Some((node, lease)) = &node_b {
        report
            .check("revoke: flows is 410", async {
                expect_error(
                    ctx.post_flows(node, &batch(node, lease, 1, 1), false)
                        .await?,
                    StatusCode::GONE,
                )
                .await?;
                Ok(())
            })
            .await;
    }

    report
        .check("forget: unrecognised certificate is 401", async {
            let node = ctx.enrol(&tokens[2]).await?;
            let lease = ctx.lease_200(&node, None).await?;
            ctx.hook("forget", &node.id, None).await?;
            let res = ctx
                .get_lease(
                    &node.client,
                    Some(&Ctx::state(Some(&lease))),
                    Some(&lease.lease_id),
                )
                .await?;
            expect_error(res, StatusCode::UNAUTHORIZED).await?;
            Ok(())
        })
        .await;

    report
        .check("features: missing feature is 426 naming it", async {
            let node = ctx.enrol(&tokens[3]).await?;
            let lease = ctx.lease_200(&node, None).await?;
            ctx.hook("require-feature", &node.id, Some(UNSUPPORTED_FEATURE))
                .await?;
            let res = ctx
                .get_lease(
                    &node.client,
                    Some(&Ctx::state(Some(&lease))),
                    Some(&lease.lease_id),
                )
                .await?;
            let err = expect_error(res, StatusCode::UPGRADE_REQUIRED).await?;
            let missing = err.missing.unwrap_or_default();
            ensure!(
                missing.iter().any(|m| m == UNSUPPORTED_FEATURE),
                "missing {missing:?} does not name {UNSUPPORTED_FEATURE}"
            );
            Ok(())
        })
        .await;

    report
        .check("flows: exhausted quota is 507", async {
            let node = ctx.enrol(&tokens[4]).await?;
            let lease = ctx.lease_200(&node, None).await?;
            let acked = ctx.ack(&node, &batch(&node, &lease, 1, 1), false).await?;
            ensure!(acked == 1, "acked_through {acked} before exhausting");
            ctx.hook("exhaust-flow-quota", &node.id, None).await?;
            expect_error(
                ctx.post_flows(&node, &batch(&node, &lease, 2, 1), false)
                    .await?,
                StatusCode::INSUFFICIENT_STORAGE,
            )
            .await?;
            Ok(())
        })
        .await;

    Ok(report)
}

/// A one-line summary for logs.
pub fn summary(report: &Report) -> String {
    let mut s = String::new();
    for r in &report.results {
        let _ = match &r.outcome {
            Outcome::Passed => write!(s, "ok {}; ", r.name),
            Outcome::Failed(e) => write!(s, "FAIL {}: {e}; ", r.name),
            Outcome::Skipped(e) => write!(s, "skip {}: {e}; ", r.name),
        };
    }
    s
}
