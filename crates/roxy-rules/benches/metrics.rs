//! Metric store hot path: `get` and `record` for one keyed 1-minute metric
//! (target < 1 µs each), plus a windowed `unique` read for reference.

use std::collections::HashSet;
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

use criterion::{Criterion, criterion_group, criterion_main};
use roxy_rules::{
    DefaultDecision, Field, MapView, MetricConfig, MetricStore, Policy, PolicyInput, Sample, Value,
};

fn store(metrics_yaml: &str) -> MetricStore {
    let metrics: Vec<MetricConfig> = serde_yaml_ng::from_str(metrics_yaml).unwrap();
    let none = HashSet::new();
    let policy = Policy::compile(&PolicyInput {
        rules: &[],
        metrics: &metrics,
        secret_names: &none,
        address_lists: &none,
        default: DefaultDecision::Deny,
    })
    .unwrap();
    MetricStore::new(policy.metric_defs(), 100_000)
}

fn view(i: u32) -> MapView {
    MapView::new()
        .with(
            Field::ClientIp,
            Value::Ip(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i))),
        )
        .with_str(Field::Host, "api.example.com")
        .with_str(Field::Path, "/v1/items")
}

/// A head sample: counts `requests` and `unique`.
const HEAD: Sample = Sample {
    head: true,
    request_bytes: 0,
    response_bytes: 0,
    denied: false,
    error: false,
};

fn bench(c: &mut Criterion) {
    let s = store("- { id: per_client, count: requests, key: [client.ip], window: 1m }");
    // A populated table: 1000 clients.
    for i in 0..1000 {
        s.record(&view(i), &HEAD).unwrap();
    }
    let v = view(7);
    let sample = HEAD;
    c.bench_function("metrics/get keyed 1m", |b| {
        b.iter(|| black_box(s.get(black_box("per_client"), black_box(&v)).unwrap()));
    });
    c.bench_function("metrics/record keyed 1m", |b| {
        b.iter(|| {
            s.record(black_box(&v), black_box(&sample)).unwrap();
        });
    });

    let u = store("- { id: paths, count: unique(path), key: [client.ip], window: 1m }");
    for i in 0..20_000 {
        let v = view(7).with_str(Field::Path, &format!("/p/{i}"));
        u.record(&v, &sample).unwrap();
    }
    c.bench_function("metrics/get unique 1m (dense)", |b| {
        b.iter(|| black_box(u.get(black_box("paths"), black_box(&v)).unwrap()));
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
