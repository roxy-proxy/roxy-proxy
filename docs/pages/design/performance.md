# Performance

On ordinary HTTP traffic roxy is on a par with Envoy. Per CPU core it
handles 1.3 to 1.5 times as many small requests, with a lower median latency,
at 64 clients and at 256. On large bodies it moves the same bytes per second
at the gateway seat but spends about a quarter more CPU to do so at 1 MiB;
the extra is on the HTTP/2 upstream leg, where roxy relays each DATA frame on
its own ([#104](https://github.com/roxy-proxy/roxy-proxy/issues/104)). At
the forward-proxy seat, where the upstream is HTTP/1.1, roxy is ahead at
every size.

Doing TLS interception on the same traffic, roxy handles about 19 times the
requests per core of mitmproxy on small requests, 8 times at 64 KiB and
under 3 times at 1 MiB, with a median latency in milliseconds rather than
hundreds of milliseconds. mitmproxy is the common choice for TLS-terminating
egress inspection; it is single-threaded Python, so its raw and per-core
figures coincide. Envoy's CONNECT seat is a TCP tunnel that does not decrypt
and is not in that table: its 16,800 requests per core at 1 KiB against
roxy's 9,100 is the cost of terminating and re-originating TLS.

A no-op addon is not free. A [WASM layer](/design/addon-model) built with
the SDK that forwards everything unchanged cost 37% to 48% of the
throughput in the table below. The cost is the number of calls the guest
makes into the host, each roughly a microsecond of component-model
bookkeeping before roxy's own code runs, and those rows were taken against
`roxy:addon@0.1.0`, whose WASI HTTP types read and write a head a field at
a time: about 60 calls for a 1 KiB exchange. `roxy:addon@0.2.0` hands each
head over as one record and each untouched body as a stream the host moves
itself, so the same no-op layer makes 3 calls per exchange (`next`, `wait`,
`respond`), a layer that answers without `next` makes 2, and one that
transforms both bodies in the guest makes about 15 for a small exchange
(`crates/roxy-wasm/tests/host_calls.rs` counts them). The no-op rows below
have not been re-taken on the new interface
([#403](https://github.com/roxy-proxy/roxy-proxy/issues/403),
[#421](https://github.com/roxy-proxy/roxy-proxy/issues/421)).

A Python [service layer](/reference/service-layers) that does the same is
bound by its own single core at about 2,400 requests per second, with roxy
at 1.2 to 1.4 cores; that is the floor for an asyncio sidecar, not the cost
of the protocol.

### roxy and Envoy

| seat | roxy req/s per core | Envoy req/s per core | roxy / Envoy | p50 ms roxy / Envoy | MB/s roxy / Envoy |
|---|---|---|---|---|---|
| gateway, 1 KiB, 64 clients | 9,726 | 7,579 | 1.28 | 1.6 / 2.2 | - |
| gateway, 1 KiB, 256 clients | 10,688 | 8,325 | 1.28 | 6.0 / 7.7 | - |
| gateway, 64 KiB, 64 clients | 3,663 | 3,795 | 0.97 | 3.9 / 4.5 | 949 / 872 |
| gateway, 1 MiB, 64 clients | 375 | 471 | 0.80 | 38.6 / 27.3 | 1,568 / 1,558 |
| forward proxy, 1 KiB, 64 clients | 9,127 | 5,928 | 1.54 | 1.8 / 2.3 | - |
| forward proxy, 1 KiB, 256 clients | 8,979 | 6,356 | 1.41 | 7.1 / 10.2 | - |
| forward proxy, 64 KiB, 64 clients | 5,650 | 4,316 | 1.31 | 2.8 / 3.7 | 1,475 / 1,131 |
| forward proxy, 1 MiB, 64 clients | 1,190 | 907 | 1.31 | 13.2 / 17.9 | 4,985 / 3,798 |

### TLS interception: roxy and mitmproxy

| requests | roxy req/s per core | mitmproxy req/s per core | roxy / mitmproxy | p50 ms roxy / mitmproxy | MB/s roxy / mitmproxy |
|---|---|---|---|---|---|
| 1 KiB, 64 clients | 9,080 | 471 | 19.3 | 1.8 / 132.4 | - |
| 1 KiB, 256 clients | 9,997 | 429 | 23.3 | 6.4 / 547.9 | - |
| 64 KiB, 64 clients | 3,007 | 378 | 8.0 | 5.2 / 165.5 | 784 / 25 |
| 1 MiB, 64 clients | 296 | 110 | 2.7 | 50.9 / 572.8 | 1,237 / 114 |
| 1 KiB, 64 clients, a new connection per request | 1,458 | 100 | 14.6 | 12.2 / 616.6 | - |

### roxy with a no-op addon

| seat | no addons req/s | no-op WASM layer req/s | no-op service layer req/s | sidecar cores |
|---|---|---|---|---|
| gateway, 1 KiB, 64 clients | 40,555 | 21,446 (-47%) | 2,402 (-94%) | 1.00 |
| gateway, 64 KiB, 64 clients | 13,936 | 8,561 (-39%) | 1,050 (-93%) | 1.00 |
| gateway, 1 MiB, 64 clients | 1,546 | 843 (-45%) | 71 (-95%) | 1.00 |
| forward proxy, 1 KiB, 64 clients | 38,043 | 21,155 (-44%) | 2,333 (-94%) | 1.00 |
| forward proxy, 64 KiB, 64 clients | 23,184 | 14,564 (-37%) | 1,195 (-95%) | 0.80 |
| forward proxy, 1 MiB, 64 clients | 4,638 | 2,392 (-48%) | 240 (-95%) | 1.00 |

roxy is at four cores in every row of this table, so the WASM column is
CPU per exchange. The service column is from the 2026-10-07 run below, and
the 1 KiB rows at 256 clients from that run (not re-taken) were 42,084 and
35,743 req/s with no addons and 2,357 and 2,169 with the service layer.

## What is not measured

No run uses [body rules](/reference/rule-language#body-rules),
[capture](/reference/flow-log#capture), body digests or a real addon. A
digest costs about one core per 400 MB/s on a CPU without SHA-NI, which is
why it is opt-in.

## Method

Measured 2026-10-07 on a 16-vCPU AWS host (Xeon Platinum 8259CL, 8 cores
with two threads each) in Docker, every component pinned: load generator on
CPUs 0-3, nginx on 4-7, the proxy on 8-11 (the hyperthread siblings of 0-3),
the service sidecar on 12-15. oha 1.16 over HTTP/1.1 with keep-alive, a 5 s
warm-up discarded and then 30 s measured; nginx serves random bytes from
memory with HTTP/2 on. "Per core" is requests per second over the proxy
container's cgroup CPU time in the measured window.

The gateway seat takes plain HTTP on :8080 and routes by host to nginx over
TLS and HTTP/2 (roxy: a `redirect` rule with `rewrite_host`; Envoy: a static
TLS cluster with h2). The forward-proxy seat takes absolute-form requests to
nginx:80 (Envoy: `dynamic_forward_proxy`). The CONNECT seat takes `CONNECT`
and then TLS to nginx:443; roxy and mitmproxy terminate it with their own CA
and open their own TLS connection upstream, Envoy tunnels the bytes.

roxy is `ghcr.io/roxy-proxy/roxy:edge` at
`sha256:703fcc651b6a01bcb16f41bb7b5308fa126cc3a2fa1e1ee5ef09f5f76ea67dc6`
(commit `8adb52f`): one rule allowing the upstream (`private_ok: true`), no
body rules, no digest, no addons unless the row says so, flow log on a tmpfs.
Envoy is v1.33 with `--concurrency 4`; mitmproxy is 12.2.3 (`mitmdump` with
`stream_large_bodies=1`). The no-addon and no-op WASM rows were re-taken on
2026-10-08 with a local release build of the same roxy (glibc, not the
image) and a no-op layer built with the SDK at that commit, in the same
harness and seats; its no-addon rows are within 6% of the image's. The host was shared with other builds: a row whose
host-wide busy time on the proxy's cores exceeded the proxy's own CPU by more
than 0.1 core was re-run; the service rows show that gap on every attempt
without it moving the result.
