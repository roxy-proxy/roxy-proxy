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
before the addon's own work, and a charge per byte on the bodies that
stream through it. A [WASM layer](/design/addon-model) that forwards
everything unchanged costs about half of the small-request throughput and
most of it on large bodies; a [service layer](/reference/service-layers)
doing the same costs about 60% on small requests and most of it on large
bodies, plus whatever the sidecar and its network hop add. Most of the
body cost is common to both kinds and is paid even when the layer leaves
the body untouched: it is in the lane pipeline between the stages
([#558](https://github.com/roxy-proxy/roxy-proxy/pull/558)), with the
service's socket on top.

| throughput lost to a do-nothing layer, as an egress proxy | 1 KiB | 64 KiB | 1 MiB |
|---|---|---|---|
| WASM layer | about 50% | about 70% | about 85% |
| service layer (sidecar on localhost) | about 60% | about 75% | about 90% |

In CPU terms, roxy spends about 100 µs on a small exchange with no addons
and a do-nothing layer of either kind adds roughly another 100 µs: the calls
into the host for WASM, a dozen messages over a second socket for a service.
So a layer that does T µs of work per request makes an exchange cost about
200 + T µs, and four cores give roughly 4,000,000 / (200 + T) requests per
second: 20,000 with no work, 13,000 at 100 µs, 4,000 at 800 µs. A service
layer adds the sidecar's own CPU on top. A body through a layer adds about
3 µs per KiB for WASM and 4.5 µs per KiB for a service, so a 1 MiB response
through a do-nothing layer costs roxy 4 to 5 ms against about 0.6 ms with
no addons.

## What is not measured

No run uses [body rules](/reference/rule-language#body-rules),
[capture](/reference/flow-log#capture), body digests or a real addon. A
digest costs about one core per 400 MB/s on a CPU without SHA-NI, which is
why it is opt-in.

These figures come from one machine, measured against Envoy and mitmproxy
and with a do-nothing addon of each kind; the detail on the fixed cost is
in [#403](https://github.com/roxy-proxy/roxy-proxy/issues/403) and
[#425](https://github.com/roxy-proxy/roxy-proxy/issues/425). The addon
rows were re-taken after the lane pipeline
([#558](https://github.com/roxy-proxy/roxy-proxy/pull/558)); the Envoy and
mitmproxy rows were not.
