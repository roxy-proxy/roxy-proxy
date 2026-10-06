//! The harness against the reference server: every check must pass, and
//! none may be skipped, so the reference server produces every response
//! code the spec names.

use roxy_node_conformance::harness::{self, AdminUrlHook, Outcome};
use roxy_node_conformance::reference;

#[tokio::test]
async fn every_check_passes_against_the_reference_server() {
    let server = reference::Server::start(reference::Options::default())
        .await
        .unwrap();
    let report = harness::run(harness::Options {
        url: server.url().to_owned(),
        ca_bundle_pem: Some(server.ca_pem().to_owned()),
        tokens: server.tokens().to_vec(),
        hook: Some(server.hook()),
    })
    .await
    .unwrap();
    assert!(report.ok(), "{}", harness::summary(&report));
    assert!(
        report.results.len() >= 20,
        "only {} checks ran",
        report.results.len()
    );
}

#[tokio::test]
async fn admin_url_hook_drives_the_reference_server() {
    let server = reference::Server::start(reference::Options::default())
        .await
        .unwrap();
    let report = harness::run(harness::Options {
        url: server.url().to_owned(),
        ca_bundle_pem: Some(server.ca_pem().to_owned()),
        tokens: server.tokens().to_vec(),
        hook: Some(std::sync::Arc::new(
            AdminUrlHook::new(server.admin_url()).unwrap(),
        )),
    })
    .await
    .unwrap();
    assert!(report.ok(), "{}", harness::summary(&report));
}

#[tokio::test]
async fn without_a_hook_the_server_initiated_codes_are_skipped_and_the_run_fails() {
    let server = reference::Server::start(reference::Options::default())
        .await
        .unwrap();
    let report = harness::run(harness::Options {
        url: server.url().to_owned(),
        ca_bundle_pem: Some(server.ca_pem().to_owned()),
        tokens: server.tokens().to_vec(),
        hook: None,
    })
    .await
    .unwrap();
    assert!(!report.ok());
    let skipped = report
        .results
        .iter()
        .filter(|r| matches!(r.outcome, Outcome::Skipped(_)))
        .count();
    assert_eq!(skipped, 5, "{}", harness::summary(&report));
    assert!(
        report
            .results
            .iter()
            .all(|r| !matches!(r.outcome, Outcome::Failed(_))),
        "{}",
        harness::summary(&report)
    );
}
