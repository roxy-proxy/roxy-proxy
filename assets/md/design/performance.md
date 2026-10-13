# Performance

On ordinary HTTP traffic roxy is on a par with Envoy. As a gateway it
handles about 30% more small requests per core, with a lower median latency
at both light and heavy concurrency, and moves the same bytes per second on
large bodies for about a quarter more CPU
([#104](https://github.com/roxy-proxy/roxy-proxy/issues/104)). As an egress
proxy it is ahead at every size, by a third to a half per core. Doing TLS
interception it handles about 20 times the small requests per core of
mitmproxy, falling to about 3 times on 1 MiB bodies, with a median latency
in milliseconds rather than hundreds of milliseconds.

| requests per core, roxy relative to | 1 KiB | 64 KiB | 1 MiB |
|---|---|---|---|
| Envoy, as a gateway | 1.3x | 1.0x | 0.8x |
| Envoy, as an egress proxy | 1.5x | 1.3x | 1.3x |
| mitmproxy, doing TLS interception | 19x | 8x | 2.7x |

## What an addon costs

An addon is a fixed charge on the throughput roxy would otherwise have,
before the addon's own work. A [WASM layer](/design/addon-model) that
forwards everything unchanged costs about half of the small-request
throughput and a third to a half on large bodies; a
[service layer](/reference/service-layers) doing the same costs about half
on small requests and half to two thirds on large bodies, plus whatever the
sidecar and its network hop add.

| throughput lost to a do-nothing layer, as an egress proxy | 1 KiB | 64 KiB | 1 MiB |
|---|---|---|---|
| WASM layer | about 45% | about 40% | about 50% |
| service layer (sidecar on localhost) | about 45% | about 50% | about 70% |

In CPU terms, roxy spends about 100 µs on a small exchange with no addons
and a do-nothing layer of either kind adds roughly another 100 µs: the calls
into the host for WASM, a dozen messages over a second socket for a service.
So a layer that does T µs of work per request makes an exchange cost about
200 + T µs, and four cores give roughly 4,000,000 / (200 + T) requests per
second: 20,000 with no work, 13,000 at 100 µs, 4,000 at 800 µs. A service
layer adds the sidecar's own CPU on top.

## What is not measured

No run uses [body rules](/reference/rule-language#body-rules),
[capture](/reference/flow-log#capture), body digests or a real addon. A
digest costs about one core per 400 MB/s on a CPU without SHA-NI, which is
why it is opt-in.

These figures come from one machine, measured against Envoy and mitmproxy
and with a do-nothing addon of each kind; the detail and the open work on
the fixed cost are in [#403](https://github.com/roxy-proxy/roxy-proxy/issues/403) and
[#425](https://github.com/roxy-proxy/roxy-proxy/issues/425).
