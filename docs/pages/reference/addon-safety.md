# Addon safety limits

An addon's limits protect roxy and catch an addon that is broken. They do
not police how fast it is: a slow addon makes its exchanges slow, never
denied.

| limit | behaviour |
|---|---|
| `first_byte_timeout` (default 30s) | bounds the layer's own time to its response head: starting an instance, the layer's work, endpoint calls and reading the client's body count; the time `next` spends below the layer does not. Overrunning it fails closed with `budget:first_byte_timeout`. A service layer's bounds each of the service's heads the same way |
| bodies | no clock: once the head is out, a body streams for as long as it takes. The client's and the upstream's idle timeouts still apply |
| CPU | no limit. A guest yields to the async runtime on a 1 ms engine-wide tick, so a busy guest never stalls a worker thread and cancelling its exchange takes effect within a tick |
| `max_memory` | linear memory, summed over the instance's memories; table growth and the host resource table (4096 live resources) are capped too. Whatever a layer holds of a body lives here |
| `max_instances` (default 1024) | caps live instances, and so the layer's concurrent exchanges and, with `max_memory`, its memory. An exchange that finds none free waits, without a deadline. Instances start on demand |

Fixed caps on what the host holds for a guest, outside `max_memory` and not
configurable:

| cap | value | on overrun |
|---|---|---|
| a `fields` a guest builds | 128 KiB of names and values | `budget:fields`, fails the exchange |
| a flow's tags, across all its layers | 64 tags, 4 KiB together | `budget:tags`, fails the exchange |
| a `flow.log` message, or a `flow.record` kind and document together | 64 KiB | `budget:message`, fails the exchange |
| an endpoint call's request body | 16 MiB, read within the endpoint's timeout | refuses the call |
| endpoint calls in flight per exchange | 8 | refuses the call |
| a state key | 1 KiB | refuses the call |

Failure semantics:

- **Every failure is closed.** A trap, an exceeded budget, a second `next`,
  a missing capability, a host failure, an unbuildable request, an error or
  missing response, a handler that returns while still holding resources,
  or a cancelled exchange is a `LayerError`, which becomes a deny (or a cut
  exchange).
- **A client that gives up cancels the exchange.** The guest is stopped,
  its instance discarded, and the slot freed. It is logged as cancelled,
  not as a failure.
- **No clean end for a failed body.** A guest body ends with an error once
  its exchange has failed, and a response body holds its end until the
  handler returns, so a trap after the last byte still cuts it.
- **An abandoned request is cut, not failed.** A request body passed to
  `next` that the guest drops without `finish` never ends cleanly: the
  upstream sees it cut. If the guest is still waiting on `next`'s response,
  the layer has failed (`invalid_request`). If it has dropped the response
  future, or already has the response, it has abandoned the forwarded
  request and may answer itself; its answer stands.
- Layers see canonical heads and body streams, never raw wire bytes, and
  have no filesystem, sockets or environment. All their I/O is `next`,
  `endpoints` and `flow`.
