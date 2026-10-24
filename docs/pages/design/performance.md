# Performance

On ordinary HTTP traffic roxy is on a par with Envoy. Doing TLS
interception it handles 3 to 20 times the requests per core of mitmproxy,
with a median latency in milliseconds rather than hundreds of
milliseconds.

| requests per core, roxy relative to | 1 KiB | 64 KiB | 1 MiB |
|---|---|---|---|
| Envoy, as a gateway | 1.3x | 1.0x | 0.8x |
| Envoy, as an egress proxy | 1.5x | 1.3x | 1.3x |
| mitmproxy, doing TLS interception | 19x | 8x | 2.7x |

## What an addon costs

roxy spends about 100 µs of CPU on a small exchange with no addons. An
addon that does nothing adds roughly another 100 µs, whether it is a WASM
component or a service. So an addon that does T µs of work makes an
exchange cost about 200 + T µs: four cores give roughly 20,000 requests a
second with no work, 13,000 at 100 µs and 4,000 at 800 µs. A service
layer's own CPU comes on top.

Bodies cost about 3 µs per KiB through a WASM layer and 4.5 µs per KiB
through a service layer, even when the layer leaves them untouched. A
1 MiB response through a do-nothing layer costs 4 to 5 ms, against about
0.6 ms with no addons.

| throughput lost to a do-nothing layer, as an egress proxy | 1 KiB | 64 KiB | 1 MiB |
|---|---|---|---|
| WASM layer | about 50% | about 70% | about 85% |
| service layer (sidecar on localhost) | about 60% | about 75% | about 90% |

## What is not measured

These figures come from one machine. No run uses body rules, capture,
body digests or a real addon. A body digest costs about one core per
400 MB/s on a CPU without SHA extensions, which is why it is opt-in.
