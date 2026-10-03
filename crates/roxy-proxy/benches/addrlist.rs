//! Address lists (DESIGN.md §7.1): build 1M random IPv4 CIDRs + 100k IPv6
//! CIDRs, report the table size, and time lookups (hit and miss, v4 and v6,
//! and an IPv4-mapped v6 address that needs normalising).

#![allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]

use std::fmt::Write as _;
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use criterion::{Criterion, criterion_group, criterion_main};
use roxy_proxy::AddressList;

/// xorshift64*: deterministic, dependency-free.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

fn source(v4: usize, v6: usize) -> String {
    let mut r = Rng(0x9e37_79b9_7f4a_7c15);
    let mut s = String::with_capacity(v4 * 18 + v6 * 40);
    for _ in 0..v4 {
        let prefix = 24 + (r.next() % 9) as u32; // /24../32
        let a = (r.next() as u32) & (u32::MAX.checked_shl(32 - prefix).unwrap_or(0));
        writeln!(s, "{}/{prefix}", Ipv4Addr::from(a)).unwrap();
    }
    for _ in 0..v6 {
        let prefix = 32 + (r.next() % 97) as u32; // /32../128
        let a = ((u128::from(r.next()) << 64) | u128::from(r.next()))
            & (u128::MAX.checked_shl(128 - prefix).unwrap_or(0));
        writeln!(s, "{}/{prefix}", Ipv6Addr::from(a)).unwrap();
    }
    s
}

fn bench(c: &mut Criterion) {
    let text = source(1_000_000, 100_000);
    let t0 = Instant::now();
    let list = AddressList::parse("bench", &text).unwrap();
    let parse = t0.elapsed();
    eprintln!(
        "addrlist: parsed 1.1M lines ({} MiB of text) in {parse:?}: {} entries after merge, \
         ~{:.1} MiB of tables",
        text.len() / (1024 * 1024),
        list.len(),
        list.heap_bytes() as f64 / (1024.0 * 1024.0),
    );
    let nets: Vec<_> = list.iter().collect();
    let t0 = Instant::now();
    let rebuilt = AddressList::from_nets("bench", nets.iter().copied());
    eprintln!(
        "addrlist: built from {} parsed nets in {:?}",
        nets.len(),
        t0.elapsed()
    );
    assert_eq!(rebuilt.len(), list.len());

    let hit_v4 = nets.iter().find(|n| n.addr().is_ipv4()).unwrap().addr();
    let hit_v6 = nets.iter().find(|n| n.addr().is_ipv6()).unwrap().addr();
    let miss_v4: IpAddr = "0.0.0.1".parse().unwrap();
    let miss_v6: IpAddr = "::2".parse().unwrap();
    let IpAddr::V4(h4) = hit_v4 else {
        unreachable!()
    };
    let mapped = IpAddr::V6(h4.to_ipv6_mapped());
    assert!(list.contains(hit_v4) && list.contains(hit_v6) && list.contains(mapped));

    let mut g = c.benchmark_group("addrlist/lookup 1.1M");
    for (name, ip) in [
        ("v4 hit", hit_v4),
        ("v4 miss", miss_v4),
        ("v6 hit", hit_v6),
        ("v6 miss", miss_v6),
        ("v4-mapped v6 hit", mapped),
    ] {
        g.bench_function(name, |b| b.iter(|| black_box(list.lookup(black_box(ip)))));
    }
    let mut r = Rng(42);
    let randoms: Vec<IpAddr> = (0..4096)
        .map(|_| IpAddr::V4(Ipv4Addr::from(r.next() as u32)))
        .collect();
    g.bench_function("v4 random", |b| {
        let mut i = 0;
        b.iter(|| {
            i = (i + 1) & 4095;
            black_box(list.lookup(black_box(randoms[i])))
        });
    });
    g.finish();

    let mut g = c.benchmark_group("addrlist/build");
    g.sample_size(10);
    g.bench_function("parse 1M v4 + 100k v6", |b| {
        b.iter(|| black_box(AddressList::parse("bench", black_box(&text)).unwrap()));
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
