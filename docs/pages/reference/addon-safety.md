# Addon safety limits

An addon's limits catch a broken addon, not a slow one: a slow addon makes
its exchanges slow, never denied.

| limit | behaviour |
|---|---|
| `first_byte_timeout` (default 30s) | the layer's own time to its response head: starting an instance, its work, endpoint calls and reading the client's body count; time `next` spends below it does not. Overrun fails closed, `budget:first_byte_timeout`. On a service layer it bounds each of the service's heads |
| bodies | no clock: once the head is out, a body streams for as long as it takes (a WebSocket for as long as the relay's idle timeout allows). The client's and upstream's idle timeouts still apply |
| CPU | no limit. A guest yields to the runtime on a 1 ms engine-wide tick, so it never stalls a worker thread and cancellation takes effect within a tick |
| `max_memory` | linear memory, summed over the instance's memories; table growth and the host resource table (4096 live resources) are capped too. What a layer holds of a body lives here |
| `max_instances` (default 1024) | live instances, so concurrent exchanges and (with `max_memory`) the layer's memory. An enforce exchange that finds none free waits, without a deadline; an observer waits at most `first_byte_timeout`, then its copy is dropped (`observer_lagged`, `no_instance`). Instances start on demand |

Fixed caps on what the host holds for a guest, outside `max_memory`, not
configurable:

| cap | value | on overrun |
|---|---|---|
| a `fields` a guest builds | 128 KiB of names and values | `budget:fields`: fails the exchange |
| a flow's tags, across all its layers | 64 tags, 4 KiB together | `budget:tags`: fails the exchange |
| a `flow.log` message, or a `flow.record` kind and document together | 64 KiB | `budget:message`: fails the exchange |
| an endpoint call's request body | 16 MiB, read within the endpoint's timeout and charged to the [buffer budget](/reference/limits#buffer-budget) while the call runs | refuses the call |
| endpoint calls in flight per exchange | 8 (further calls wait for a permit, within the timeout) | refuses the call |
| a state key | 1 KiB | refuses the call |

Failure:

- **Every failure is closed.** A trap, an exceeded budget, a second `next`,
  a missing capability, a host failure, an unbuildable request, an error or
  missing response, a handler that returns still holding resources, or a
  cancelled exchange is a `LayerError`: a deny, or a cut exchange after the
  response head.
- **A client that gives up cancels the exchange.** The guest is stopped,
  its instance discarded, the slot freed. Logged as cancelled, not failed.
- **No clean end for a failed body.** A guest body ends with an error once
  its exchange has failed; a response body holds its end until the handler
  returns, so a trap after the last byte still cuts it.
- **An abandoned request is cut, not failed.** A request body passed to
  `next` that the guest drops without `finish` is cut at the upstream. If
  the guest is still waiting on `next`'s response, the layer has failed
  (`invalid_request`); if it has dropped the response future or already has
  the response, it may answer itself and its answer stands.
- Layers see canonical heads and body streams, never wire bytes, and have
  no filesystem, sockets or environment: all their I/O is `next`,
  `endpoints` and `flow`.
