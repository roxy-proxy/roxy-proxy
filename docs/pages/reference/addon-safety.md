# Addon safety

An addon's limits protect roxy and catch an addon that is broken. They
don't police how fast it is: a slow addon makes its exchanges slow, never
denied, and how fast it runs is its author's business. Nothing passes a
slow layer unchecked while it works, so this keeps traffic fail-closed.

- **A deadline to the response head.** `first_byte_timeout` (default 30s)
  bounds the layer's own time to set its response head. Starting an
  instance, the layer's work, endpoint calls and reading the client's body
  count. The time `next` spends below the layer does not. A layer that
  never answers is broken, not slow: it fails closed with
  `budget:first_byte_timeout`. A service layer's `first_byte_timeout`
  bounds each of the service's heads the same way.
- **No clock on bodies.** Once the head is out, a body streams for as long
  as it takes. An SSE stream or a long generation is never cut by an addon
  limit. The client's and the upstream's idle timeouts still apply.
- **No CPU limit.** A guest may compute for as long as it likes. It yields
  to the async runtime on a 1 ms engine-wide tick, so a busy guest never
  stalls a worker thread, and cancelling its exchange takes effect within
  a tick.
- **A client that gives up cancels the exchange.** The guest is stopped,
  its instance discarded, and the slot freed. It is logged as cancelled,
  not as a failure.
- **Memory per instance.** Linear memory, summed over the instance's
  memories, is capped at `max_memory`; table growth and the host resource
  table (4096 live resources) are capped too. This is what keeps one addon
  from exhausting roxy's memory, and with it every flow. Whatever a layer
  holds of a body lives here.
- **Fixed caps on what the host holds for a guest.** A `fields` a guest
  builds, the flow's tags and the payloads of `flow.log` and `flow.record`
  live in the host, outside `max_memory`, so each has a fixed cap. A
  `fields` holds at most 128 KiB of names and values (`budget:fields`). A
  flow holds at most 64 tags, and 4 KiB of them together, across all its
  layers (`budget:tags`). A `flow.log` message, or a `flow.record` kind and
  document together, is at most 64 KiB (`budget:message`). A call past a
  cap fails the exchange closed, like any other budget. An endpoint call's
  request body is at most 16 MiB, read within the endpoint's timeout, and
  an exchange has at most 8 calls in flight at once; a state key is at most
  1 KiB. Those refuse the call, not the exchange. These caps are not
  configurable.
- **Instances.** `max_instances` (default 1024) caps the live instances,
  and so the layer's concurrent exchanges and, with `max_memory`, its
  memory. An exchange that finds none free waits for one, without a
  deadline. Instances start on demand.
- **Every failure is closed.** A trap, an exceeded budget, a second `next`,
  a missing capability, a host failure, an unbuildable request, an error or
  missing response, a handler that returns while still holding resources,
  or a cancelled exchange is a `LayerError`, and the caller turns it into a
  deny (or a cut exchange).
- **No clean end for a failed body.** A guest body never ends cleanly once
  its exchange has failed: it ends with an error, and a response body holds
  its end until the handler returns, so a trap after the last byte still
  cuts it.
- **An abandoned request is cut, not failed.** A request body passed to
  `next` that the guest drops without `finish` never ends cleanly either:
  the upstream sees it cut. If the guest is still waiting on `next`'s
  response, the layer has failed (`invalid_request`). If it has dropped the
  response future, or already has the response, it has abandoned the
  forwarded request and may answer itself; its answer stands.
- Layers see canonical heads and body streams, never raw wire bytes, and
  have no filesystem, sockets or environment. All their I/O is `next`,
  `endpoints` and `flow`.
