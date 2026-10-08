# Performance

On ordinary HTTP traffic roxy is on a par with Envoy. As a gateway it
handles about 30% more small requests per core, moves the same bytes per
second on large bodies, and answers small requests with a lower median
latency at both light and heavy concurrency; on 1 MiB bodies its median is
higher and it spends about a quarter more CPU, on the HTTP/2 leg to the
upstream ([#104](https://github.com/roxy-proxy/roxy-proxy/issues/104)). As
an egress proxy, where the upstream is HTTP/1.1, it is ahead of Envoy at
every size, by 30% to 50% per core.

Doing TLS interception, roxy handles about 20 times the small requests per
core of mitmproxy, falling to about 3 times on 1 MiB bodies, with a median
latency in milliseconds rather than hundreds of milliseconds.

## Addons as a budget

Each addon in the path costs a share of the throughput roxy would otherwise
have, before the addon's own work. A WASM layer that forwards everything
unchanged costs about WASM_PCT; a service layer that does the same costs about
SVC_SMALL_PCT on small requests and SVC_BULK_PCT on large bodies, plus whatever
your sidecar and its network hop add. In CPU terms, roxy spends about
BASE_US µs on a 1 KiB exchange with no addons, a no-op WASM layer adds about
WASM_US µs and a no-op service layer about SVC_US µs. So a WASM layer that does
T µs of work per request makes an exchange cost roughly BASE_US + WASM_US + T µs
of roxy CPU, and four cores give about 4,000,000 / that requests per second;
a service layer the same with SVC_US in place of WASM_US, and its sidecar's
CPU on top.

A WASM layer is not free because each exchange makes a fixed number of
calls across the component boundary, each a microsecond or so of bookkeeping
before roxy's own code runs; reducing that count is the open work in
[#403](https://github.com/roxy-proxy/roxy-proxy/issues/403),
[#319](https://github.com/roxy-proxy/roxy-proxy/issues/319) and
[#421](https://github.com/roxy-proxy/roxy-proxy/issues/421). A service layer
pays for a second validated request and response and about a dozen messages
per exchange over the [service protocol](/reference/service-layers);
[#425](https://github.com/roxy-proxy/roxy-proxy/issues/425) is the open work
on that.

TABLES

## What is not measured

No run uses [body rules](/reference/rule-language#body-rules),
[capture](/reference/flow-log#capture), body digests or a real addon. A
digest costs about one core per 400 MB/s on a CPU without SHA-NI, which is
why it is opt-in.

## Method

A 16-vCPU AWS host (Xeon Platinum 8259CL, 8 cores with two threads each),
Docker, every component pinned: load generator on CPUs 0-3, nginx on 4-7,
the proxy on 8-11, the service sidecar on 12-15. 8-11 are the hyperthread
siblings of 0-3 and 12-15 of 4-7, so load on one group slows the other in a
way the CPU figures do not show. oha 1.16 over HTTP/1.1 with keep-alive, a
5 s warm-up discarded and then 30 s measured; nginx serves random bytes from
memory with HTTP/2 on. "Per core" is requests per second over the proxy
container's cgroup CPU time in the measured window.

The gateway takes plain HTTP on :8080 and routes by host to nginx over TLS
and HTTP/2 (roxy: a `redirect` rule with `rewrite_host`; Envoy: a static TLS
cluster with h2). The egress proxy takes absolute-form requests to nginx:80
(Envoy: `dynamic_forward_proxy`). TLS interception takes `CONNECT` and then
TLS to nginx:443, terminated with the proxy's own CA and re-originated
upstream. roxy's configuration is one rule allowing the upstream
(`private_ok: true`), no body rules, no digest, flow log on a tmpfs, and
no addons unless the row says so.

The Envoy and mitmproxy comparisons are from 2026-10-07 on roxy
`ghcr.io/roxy-proxy/roxy:edge` at
`sha256:703fcc651b6a01bcb16f41bb7b5308fa126cc3a2fa1e1ee5ef09f5f76ea67dc6`
(commit `8adb52f`), Envoy v1.33 with `--concurrency 4`, mitmproxy 12.2.3
(`mitmdump` with `stream_large_bodies=1`). The addon table is from
2026-10-08 on `ghcr.io/roxy-proxy/roxy:edge` at `DIGEST` (commit `REV`), the
no-op WASM layer built with the SDK at that commit, `mode: enforce`. The
service sidecar is a Rust no-op on the same host that returns every message
unchanged, so its column is the cost of the protocol in roxy, not of a
sidecar doing work.
