# Addon safety

- **CPU per step.** A step is the guest's run between host calls: every
  call into the guest, and every host call returning to it, starts a new
  one. Each step gets `fuel_per_step` fuel and `step_cpu` of wall time. The
  time limit is checked on a 1 ms engine-wide epoch tick, which also yields
  to the async runtime, so a spinning guest neither stalls a worker thread
  nor escapes its clock.
- **Wall clock per exchange.** `max_exchange_time` runs from the start of
  the exchange until the guest's handler returns: waiting for an instance,
  `next`, endpoint calls and streaming both bodies. A streamed response
  longer than the limit is cut. Tunnels have no exchange clock; they live as
  long as the relay's idle timeout allows.
- **Memory per instance.** Linear memory, summed over the instance's
  memories, is capped at `max_memory`; table growth and the host resource
  table (4096 live resources) are capped too.
- **Buffered bytes.** `max_buffered_body_bytes` bounds, per direction, the
  bytes the guest has read from that direction's body minus the bytes it
  has passed on. A streaming layer stays near zero.
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
