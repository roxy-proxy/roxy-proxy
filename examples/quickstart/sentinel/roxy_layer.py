"""The service side of roxy's service layers (`roxy.layer.v7`).

roxy keeps a few WebSocket connections open to the service and carries
each exchange as a stream on one of them. Text frames are JSON control
messages with a `stream` field; binary frames are a 4-byte big-endian
stream id, a direction byte (0 for the request body, 1 for the response
body), then body bytes. Each direction of a stream is a lane each way,
shaped like an HTTP/2 stream: a head, body bytes, optional `trailers`, and
an end (or a cut: an end with `error`):

    roxy -> service   open (the exchange's metadata), then the request:
                      head, body bytes, request_end
    service -> roxy   the request to forward (head, bytes, request_end), or
                      a request_end alone: nothing forwarded
    roxy -> service   the response from upstream: head, bytes, response_end
    service -> roxy   the response for the client (head, bytes, response_end)

The two lanes of a stream are independent, each way: roxy sends its
`response` head as soon as the layer upstream answers, even while the
client is still uploading, and the service may answer before, while or
without forwarding. A stream ends after all four lanes and accepted host
calls finish. A service that forwards nothing still sends `request_end`,
and stops inputs it will not consume (this module does both). A body that fails on its way ends its lane with an
`error` on the end rather than ending the stream. The reader of a body may
`stop` it: after roxy's `stop` for a lane this side sends no more of it.
Each body is flow-controlled with `credit` messages, and either side may
abandon a stream with `reset`.

A direction the layer subscribes to as `head` is a head alone each way:
no bytes, trailers or end follow it. Here its body reads as empty and
`forward` or `respond` sends the head only. An observe stream is one way:
the service sends nothing on its lanes, `forward` and `respond` send
nothing, and the stream sends `close` once the handler returns. This module handles the streams, credit,
stops and resets, and turns each exchange into one coroutine:

    async def handle(ex: Exchange) -> None:
        response = await ex.forward(ex.request, ex.body())
        await ex.respond(response, ex.response_body())

    asyncio.run(serve(handle, "127.0.0.1", 9000))

Bodies stream: `ex.body()` yields the client's request bytes as they
arrive, and `forward` sends each one on as it is read. `forward` returns
as soon as the response head arrives, while the request body (if it is
still going) carries on in the background, so an early answer reaches the
client at once. A handler that needs a whole body reads it with
`read_body()` / `read_response_body()`.

A WebSocket is the same exchange, long-lived: roxy sends no `request_end`
before the `101`, since the request body is the client's side of the
WebSocket, and after the `101` the response body is the upstream's, each
until that side closes. The handler above carries one as it is: `forward`
returns on the `101` while the request body keeps going out. A handler
that reads the request body whole before forwarding waits for an end that
never comes, and roxy fails the exchange on its deadline.

If the handler raises, the stream is reset without an answer and roxy
fails the exchange closed (enforce mode). If roxy resets the stream (the
client went away, say) or the connection closes, the handler is cancelled,
and with it a request body still going out. Only the `websockets` package
is needed.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterable, AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from websockets.asyncio.server import ServerConnection, serve as ws_serve

SUBPROTOCOL = "roxy.layer.v7"

# The direction byte of a binary frame, and the `dir` of a credit message.
REQUEST = 0
RESPONSE = 1
_DIR_NAMES = {REQUEST: "request", RESPONSE: "response"}
_DIRS = {v: k for k, v in _DIR_NAMES.items()}
_DIR_OF_MESSAGE = {
    "request": REQUEST,
    "request_end": REQUEST,
    "response": RESPONSE,
    "response_end": RESPONSE,
}

# Each body's starting credit, each way, in bytes.
WINDOW = 256 * 1024

# Extra credit granted to each body of an observe stream as it opens. roxy
# cuts an observer that falls behind the real exchange, so it may send
# this much ahead of the handler; it is held here until read.
OBSERVE_CREDIT = 16 * 1024 * 1024

# Largest body frame sent, so streams share the connection fairly.
MAX_BODY_FRAME = 64 * 1024

log = logging.getLogger("roxy_layer")

Body = bytes | AsyncIterable[bytes]


@dataclass
class Request:
    """A request head: `url` is absolute; `headers` are end-to-end fields."""

    method: str
    url: str
    headers: list[tuple[str, str]] = field(default_factory=list)

    def header(self, name: str) -> str | None:
        """The first value of `name` (case-insensitive), if any."""
        name = name.lower()
        return next((v for n, v in self.headers if n.lower() == name), None)


@dataclass
class Response:
    """A response head."""

    status: int
    headers: list[tuple[str, str]] = field(default_factory=list)

    def header(self, name: str) -> str | None:
        """The first value of `name` (case-insensitive), if any."""
        name = name.lower()
        return next((v for n, v in self.headers if n.lower() == name), None)


class ForwardEnded(Exception):
    """The upstream response lane ended without a head, possibly with an error.

    A handler may catch this and supply its own response. Left uncaught,
    the helper ends its answer headless, without resetting the service.
    """

    def __init__(self, error: str | None) -> None:
        self.error = error
        super().__init__(error or "the forward ended without a response")


class ProtocolError(Exception):
    """roxy sent something out of order, or reset the stream."""


class BodyFailed(Exception):
    """A body from roxy ended short of complete: its lane carries the
    failure, the stream goes on. Whatever was read of it is not the whole."""


class HostError(Exception):
    """roxy refused a host-service call for what was passed (a key or
    value over its cap), or because it arrived after stream retirement."""


class _Conn:
    """One connection from roxy: its streams, and the way out."""

    def __init__(self, ws: ServerConnection, handler: Handler) -> None:
        self.ws = ws
        self.handler = handler
        self.streams: dict[int, _Stream] = {}
        # Serialises what goes out, and with it each stream's view of
        # whether its last message has gone.
        self.lock = asyncio.Lock()

    async def send(self, stream: int, msg: dict[str, Any]) -> None:
        async with self.lock:
            await self.send_unlocked(stream, msg)

    async def send_unlocked(self, stream: int, msg: dict[str, Any]) -> None:
        msg["stream"] = stream
        await self.ws.send(json.dumps(msg))

    async def send_bytes(self, stream: int, direction: int, data: bytes) -> None:
        async with self.lock:
            await self.ws.send(stream.to_bytes(4, "big") + bytes([direction]) + data)

    async def run(self) -> None:
        try:
            async for m in self.ws:
                if isinstance(m, bytes):
                    s = self.streams.get(int.from_bytes(m[:4], "big"))
                    if s is not None:
                        s.inbox(m[4]).put_nowait(m[5:])
                    continue
                msg = json.loads(m)
                self._control(msg)
        finally:
            streams = list(self.streams.values())
            for s in streams:
                s.fail_calls(ProtocolError("the connection closed"))
                s.task.cancel()
            await asyncio.gather(*(s.task for s in streams), return_exceptions=True)

    def _control(self, msg: dict[str, Any]) -> None:
        sid = msg["stream"]
        kind = msg.get("type")
        if kind == "open":
            flow = {k: v for k, v in msg.items() if k not in ("type", "stream")}
            s = _Stream(self, sid, flow)
            s.observe = flow.get("mode") == "observe"
            subscribe = flow.get("subscribe") or {}
            s.head_only = {d: subscribe.get(n) == "head" for d, n in _DIR_NAMES.items()}
            self.streams[sid] = s
            s.task = asyncio.create_task(s.run(observe=s.observe))
            return
        s = self.streams.get(sid)
        if s is None:
            # A message that crossed the stream's end.
            return
        if kind == "credit":
            lane = s.lane(_DIRS[msg["dir"]])
            lane.credit += int(msg["bytes"])
            lane.more_credit.set()
        elif kind == "result":
            fut = s.pending.pop(msg["id"], None)
            if fut is not None and not fut.done():
                fut.set_result(msg)
            s._maybe_ended()
        elif kind == "reset":
            self.streams.pop(sid, None)
            s.fail_calls(ProtocolError("roxy reset the stream"))
            s.task.cancel()
        elif kind == "stop":
            # roxy reads no more of this lane: nothing more of it is sent,
            # and its end is no longer owed.
            s.stopped(_DIRS[msg["dir"]])
        elif kind == "trailers":
            s.inbox(_DIRS[msg["dir"]]).put_nowait(msg)
        else:
            direction = _DIR_OF_MESSAGE.get(kind, REQUEST)
            s.inbox(direction).put_nowait(msg)
            if kind in ("request", "response") and s.head_only[direction]:
                # The head is the whole lane: its body reads as empty.
                s.inbox(direction).put_nowait({"type": f"{kind}_end"})
                s._ends_received[direction] = True
                s._maybe_ended()
            if kind in ("request_end", "response_end"):
                s._ends_received[direction] = True
                s._maybe_ended()


# Put after the final queued input once every lane and accepted call is
# terminal, so a receive beyond the end cannot wait forever.
_ENDED: Any = object()


class _Lane:
    """One body of a stream, each way: what roxy sent of it, and the credit
    for what this side may send."""

    def __init__(self) -> None:
        self.inbox: asyncio.Queue[dict[str, Any] | bytes] = asyncio.Queue()
        self.credit = WINDOW
        self.more_credit = asyncio.Event()
        # Bytes consumed and not yet credited back to roxy.
        self.unacked = 0
        # roxy reads no more of what this side sends on the lane.
        self.stopped = asyncio.Event()
        # Trailers roxy sent after the body's bytes, if any.
        self.trailers: list[tuple[str, str]] | None = None


class _Stream:
    def __init__(self, conn: _Conn, sid: int, flow: dict[str, Any]) -> None:
        self.conn = conn
        self.id = sid
        self.flow = flow
        self.lanes = {REQUEST: _Lane(), RESPONSE: _Lane()}
        self.task: asyncio.Task[None]
        # Host-service calls being sent or awaiting their `result`, by id.
        # Calls waiting for the connection lock do not retain the stream.
        self.pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self._next_call = 0
        self.observe = False
        # Directions subscribed as `head`: a head alone each way.
        self.head_only = {REQUEST: False, RESPONSE: False}
        # A `request` was forwarded.
        self.forwarded = False
        self._ends_sent = {REQUEST: False, RESPONSE: False}
        self._ends_received = {REQUEST: False, RESPONSE: False}
        # All four lanes and outstanding results determine retirement.
        self.ended = False
        self._settled = asyncio.Event()

    def stopped(self, direction: int) -> None:
        lane = self.lanes[direction]
        lane.stopped.set()
        lane.more_credit.set()
        self._lane_done(direction)

    def _lane_done(self, direction: int) -> None:
        self._ends_sent[direction] = True
        self._maybe_ended()

    def _maybe_ended(self) -> None:
        if (all(self._ends_sent.values()) and all(self._ends_received.values())
                and not self.pending and not self.ended):
            self.ended = True
            self._settled.set()
            for lane in self.lanes.values():
                lane.inbox.put_nowait(_ENDED)

    async def _stop_inputs(self) -> None:
        for direction in self._ends_received:
            await self._stop_input(direction)

    async def _stop_input(self, direction: int) -> None:
        if not self._ends_received[direction]:
            await self.conn.send(self.id, {"type": "stop", "dir": _DIR_NAMES[direction]})
            self._ends_received[direction] = True
        self._maybe_ended()

    def fail_calls(self, exc: Exception) -> None:
        """Unblocks every call still waiting for its `result`: the stream
        is gone, so none is coming."""
        for fut in self.pending.values():
            if not fut.done():
                fut.set_exception(exc)
        self.pending.clear()

    async def send(
        self,
        msg: dict[str, Any],
        *,
        host: asyncio.Future[dict[str, Any]] | None = None,
        forward: bool = False,
        end: int | None = None,
    ) -> None:
        """Sends `msg` on the stream, under the connection's lock, so a
        host-service call (`host` is its result future) or a forward
        (`forward`) is refused once the stream has ended locally. Register
        a call only after that check: waiting for the lock cannot keep the
        stream open. `end` is the direction whose end `msg` is."""
        async with self.conn.lock:
            if (host is not None or forward) and (
                self.ended or self.conn.streams.get(self.id) is not self
            ):
                what = "a call" if host is not None else "a forward"
                raise ProtocolError(f"the stream has ended: cannot send {what}")
            if host is not None:
                self.pending[msg["id"]] = host
            if forward:
                self.forwarded = True
            await self.conn.send_unlocked(self.id, msg)
            if end is not None:
                self._lane_done(end)

    async def call(self, msg: dict[str, Any]) -> Any:
        """Sends a host-service call and returns the value of its `result`,
        raising `HostError` on a refusal and `ProtocolError` if the stream
        has ended or ends first."""
        self._next_call += 1
        cid = self._next_call
        msg["id"] = cid
        fut: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        try:
            await self.send(msg, host=fut)
            result = await fut
        finally:
            self.pending.pop(cid, None)
            self._maybe_ended()
            # A reset can fail the registered future while the socket send
            # is suspended. Retrieve that failure even if sending also
            # raises, so asyncio does not report an unobserved exception.
            if fut.done() and not fut.cancelled():
                fut.exception()
        if result.get("error") is not None:
            raise HostError(result["error"])
        return result.get("value")

    def lane(self, direction: int) -> _Lane:
        return self.lanes[direction]

    def inbox(self, direction: int) -> asyncio.Queue[dict[str, Any] | bytes]:
        return self.lanes[direction].inbox

    async def run(self, observe: bool) -> None:
        exchange: Exchange | None = None
        try:
            if observe:
                for name in _DIR_NAMES.values():
                    await self.conn.send(
                        self.id, {"type": "credit", "dir": name, "bytes": OBSERVE_CREDIT}
                    )
            first = await self.inbox(REQUEST).get()
            if isinstance(first, bytes) or first.get("type") != "request":
                raise ProtocolError("expected the request head")
            request = Request(
                method=first["method"],
                url=first["url"],
                headers=[tuple(h) for h in first.get("headers", [])],  # type: ignore[misc]
            )
            exchange = Exchange(self, request)
            await self.conn.handler(exchange)
            # Nothing reads the response after handler return. Release it
            # before waiting for an upload that may still need input/credit.
            # Keep the request input available to that upload until it ends.
            await self._stop_input(RESPONSE)
            # The request body may still be going out after the handler
            # has answered. A handler that forwarded nothing ends the
            # request lane headless, and releases unread inputs.
            await exchange._finish_forwarding()
            await self._stop_inputs()
            await self._end_outputs()
            await self._settled.wait()
        except ForwardEnded as e:
            if exchange is not None:
                await exchange._stop_forwarding()
            await self._stop_inputs()
            for direction in (REQUEST, RESPONSE):
                if not self._ends_sent[direction] and not self.observe:
                    end: dict[str, Any] = {"type": f"{_DIR_NAMES[direction]}_end"}
                    if direction == REQUEST:
                        end["error"] = "the forward ended before the upload completed"
                    elif e.error is not None:
                        end["error"] = e.error
                    await self.send(end, end=direction)
            await self._end_outputs()
            await self._settled.wait()
        except asyncio.CancelledError:
            # roxy reset the stream, or the connection went.
            pass
        except Exception as e:
            # Resetting without an answer fails the exchange closed in roxy.
            log.exception("exchange failed")
            if exchange is not None:
                exchange._cancel_forwarding()
            try:
                await self.conn.send(self.id, {"type": "reset", "message": str(e)[:200]})
            except Exception:
                pass
        finally:
            # Nothing the exchange started outlives it: roxy sends nothing
            # more on a reset stream, so a body still going out would wait
            # for input or credit forever, and a call the handler left
            # waiting would never be answered.
            if exchange is not None:
                await exchange._stop_forwarding()
            self.fail_calls(ProtocolError("the stream has ended"))
            self.conn.streams.pop(self.id, None)

    async def _end_outputs(self) -> None:
        """Ends what is left of this side's lanes: with an end alone each,
        or on an observe stream, which has none, with `close`."""
        if self.observe:
            if not all(self._ends_sent.values()):
                await self.conn.send(self.id, {"type": "close"})
                for direction in self._ends_sent:
                    self._lane_done(direction)
            return
        for direction in (REQUEST, RESPONSE):
            if not self._ends_sent[direction]:
                await self.send({"type": f"{_DIR_NAMES[direction]}_end"}, end=direction)

    async def recv(self, direction: int) -> dict[str, Any] | bytes:
        lane = self.lanes[direction]
        m = await lane.inbox.get()
        if m is _ENDED:
            # Left for the next receive, which must not wait either.
            lane.inbox.put_nowait(_ENDED)
            raise ProtocolError("the stream has ended: nothing more arrives on it")
        if isinstance(m, bytes) and m:
            # Credit roxy for what was consumed, a quarter window at a time
            # (or whenever the inbox runs dry), not a message per frame.
            lane.unacked += len(m)
            if lane.unacked >= WINDOW // 4 or lane.inbox.empty():
                n, lane.unacked = lane.unacked, 0
                await self.conn.send(
                    self.id, {"type": "credit", "dir": _DIR_NAMES[direction], "bytes": n}
                )
        return m

    async def send_bytes(self, direction: int, data: bytes) -> None:
        lane = self.lanes[direction]
        view = memoryview(data)
        while view and not lane.stopped.is_set():
            while lane.credit <= 0 and not lane.stopped.is_set():
                lane.more_credit.clear()
                await lane.more_credit.wait()
            if lane.stopped.is_set():
                return
            n = min(len(view), lane.credit, MAX_BODY_FRAME)
            lane.credit -= n
            await self.conn.send_bytes(self.id, direction, bytes(view[:n]))
            view = view[n:]


class Exchange:
    """One exchange, from the service's side."""

    def __init__(self, stream: _Stream, request: Request) -> None:
        self._s = stream
        self.request = request
        """The client's request head, as it reached this layer."""
        self.flow: dict[str, Any] = stream.flow
        """The stream's `open` metadata: flow, conn, layer, mode (`enforce`
        or `observe`), client_ip, listener, sni, tags, capabilities and
        config. The pair (flow, layer) is unique to this exchange."""
        self._body_read = False
        self._response_read = False
        # The forwarded request body still going out, if `forward` returned
        # before it had all gone.
        self._forwarding: asyncio.Task[None] | None = None

    @property
    def observing(self) -> bool:
        """roxy sends copies and ignores the answers (`mode: observe`)."""
        return self.flow.get("mode") == "observe"

    @property
    def config(self) -> Any:
        """The layer's `config:` value from roxy's configuration."""
        return self.flow.get("config")

    @property
    def trailers(self) -> list[tuple[str, str]] | None:
        """The request body's trailers, once `body()` has been read to its
        end, if roxy sent any."""
        return self._s.lane(REQUEST).trailers

    @property
    def response_trailers(self) -> list[tuple[str, str]] | None:
        """The response body's trailers, once `response_body()` has been
        read to its end, if roxy sent any."""
        return self._s.lane(RESPONSE).trailers

    # Host services, each behind a capability granted in roxy's config
    # (`capabilities: [log, record, state, metrics]`). Each returns once
    # roxy has answered it. A call without its capability, or a failure in
    # roxy, fails the layer: roxy resets the stream, and in enforce mode
    # the exchange fails with it. `add_tag` needs no capability but is
    # refused in observe mode, like `state_put` and `quarantine`.
    #
    # A call may be made at any point, including part-way through a body.
    # Calls run beside the bodies, and roxy promises no order between a
    # call and the heads or bytes the handler sends after it: the handler
    # awaits the call before sending whatever its effect must precede
    # (`forward`, `respond`, or the rest of a body). A tag or state write
    # is seen by this exchange's admission rules only if it lands before
    # `forward`; later rule evaluations can read updated tags and state.
    # A write does not itself trigger an in-flight re-check (#509).

    async def log(self, level: str, message: str) -> None:
        """Writes to roxy's operational log (`trace` to `error`)."""
        await self._s.call({"type": "log", "level": level, "message": message})

    async def record(self, kind: str, data: Any) -> None:
        """Writes a `layer_record` event to the flow log."""
        await self._s.call({"type": "record", "kind": kind, "data": data})

    async def add_tag(self, tag: str) -> None:
        """Tags the flow for the upstream layers and the flow log. Await it
        before `forward` for the upstream layers to see the tag."""
        await self._s.call({"type": "add_tag", "tag": tag})

    async def state_get(self, key: str) -> str | None:
        """Reads the state store the rules read as `state["key"]`."""
        return await self._s.call({"type": "state_get", "key": key})

    async def state_put(self, key: str, value: str, ttl_ms: int | None = None) -> None:
        """Writes the state store; a rule matches the value as written.
        Await it before `forward` for this exchange's rules to read it."""
        msg: dict[str, Any] = {"type": "state_put", "key": key, "value": value}
        if ttl_ms is not None:
            msg["ttl_ms"] = ttl_ms
        await self._s.call(msg)

    async def metric_get(self, metric: str) -> int | None:
        """Reads a metric for this flow's own key."""
        return await self._s.call({"type": "metric_get", "metric": metric})

    async def quarantine(self) -> None:
        """Puts the whole proxy into quarantine: every exchange from here
        on, this one included, is refused until an operator or the control
        plane lifts it (capability `quarantine`, enforce mode only)."""
        await self._s.call({"type": "quarantine"})

    async def _body(self, direction: int) -> AsyncIterator[bytes]:
        end = f"{_DIR_NAMES[direction]}_end"
        while True:
            m = await self._s.recv(direction)
            if isinstance(m, bytes):
                yield m
                continue
            if m.get("type") == "trailers":
                self._s.lane(direction).trailers = [tuple(h) for h in m.get("headers", [])]  # type: ignore[misc]
                continue
            if m.get("type") != end:
                raise ProtocolError(f"expected {end}, got {m.get('type')}")
            if m.get("error") is not None:
                raise BodyFailed(str(m["error"]))
            return

    def body(self) -> AsyncIterator[bytes]:
        """The request body, as it arrives. Read it once."""
        if self._body_read:
            raise ProtocolError("the request body was already read")
        self._body_read = True
        return self._body(REQUEST)

    async def read_body(self) -> bytes:
        """The whole request body."""
        return b"".join([c async for c in self.body()])

    async def _send_body(self, direction: int, body: Body) -> None:
        if self._s.head_only[direction]:
            # The head was the whole lane.
            if isinstance(body, bytes) and body:
                raise ProtocolError(f"the {_DIR_NAMES[direction]} is subscribed head-only")
            return
        end: dict[str, Any] = {"type": f"{_DIR_NAMES[direction]}_end"}
        if isinstance(body, bytes):
            if body:
                await self._s.send_bytes(direction, body)
        else:
            lane = self._s.lane(direction)
            source = aiter(body)

            async def produce() -> None:
                async for chunk in source:
                    if lane.stopped.is_set():
                        return
                    if chunk:
                        await self._s.send_bytes(direction, chunk)

            producer = asyncio.create_task(produce())
            stopped = asyncio.create_task(lane.stopped.wait())
            try:
                # A stop must also interrupt a source waiting for its next
                # chunk, not only a sender waiting for output credit.
                await asyncio.wait({producer, stopped}, return_when=asyncio.FIRST_COMPLETED)
                if not lane.stopped.is_set():
                    producer.result()
            except BodyFailed as e:
                # A body that failed on its way in is passed on cut, where
                # it stopped, never as complete.
                end["error"] = str(e)
            finally:
                for task in (producer, stopped):
                    if not task.done():
                        task.cancel()
                await asyncio.gather(producer, stopped, return_exceptions=True)
                close = getattr(source, "aclose", None)
                if close is not None:
                    await close()
        if self._s.lane(direction).stopped.is_set():
            # roxy reads no more of this lane: its end is not owed.
            return
        await self._s.send(end, end=direction)

    async def _finish_forwarding(self) -> None:
        if self._forwarding is not None:
            await self._forwarding

    def _cancel_forwarding(self) -> None:
        if self._forwarding is not None and not self._forwarding.cancelling():
            self._forwarding.cancel()

    async def _stop_forwarding(self) -> None:
        if self._forwarding is None:
            return
        self._cancel_forwarding()
        await asyncio.wait({self._forwarding})
        if not self._forwarding.cancelled():
            # Retrieved, so a send that failed as the socket closed is not
            # logged as never retrieved; the exchange's outcome is reported.
            self._forwarding.exception()

    async def forward(self, request: Request, body: Body) -> Response:
        """Pass `request` upstream, once, and return the response
        head from upstream, as soon as there is one: the body keeps going out
        in the background if roxy answers before it has all been sent.
        roxy re-validates the request and its rules judge it; a refusal
        comes back as a response like any other. Read the response body
        with `response_body()`. If the response lane ends without a head,
        raises `ForwardEnded`; the handler may catch it and answer locally.

        Completing both outputs leaves the response input available.
        To keep the forward running, consume its response; returning from
        the handler stops any inputs it left unfinished.

        On an observe stream nothing is sent: roxy forwards the exchange
        as it is, and this returns the copy of its response head."""
        if self._s.observe:
            return _response_of(await self._s.recv(RESPONSE))
        await self._s.send(
            {
                "type": "request",
                "method": request.method,
                "url": request.url,
                "headers": request.headers,
            },
            forward=True,
            end=REQUEST if self._s.head_only[REQUEST] else None,
        )
        self._forwarding = asyncio.create_task(self._send_body(REQUEST, body))
        head = asyncio.ensure_future(self._s.recv(RESPONSE))
        try:
            done, _ = await asyncio.wait(
                {self._forwarding, head}, return_when=asyncio.FIRST_COMPLETED
            )
            if head not in done:
                # The body went first: a failure sending it is the error.
                self._forwarding.result()
                await head
            m = head.result()
        except BaseException:
            head.cancel()
            await asyncio.wait({head})
            raise
        return _response_of(m)

    def response_body(self) -> AsyncIterator[bytes]:
        """The response body from upstream, as it arrives. Read it once, after
        `forward`."""
        if self._response_read:
            raise ProtocolError("the response body was already read")
        self._response_read = True
        return self._body(RESPONSE)

    async def read_response_body(self) -> bytes:
        """The whole response body from upstream."""
        return b"".join([c async for c in self.response_body()])

    async def respond(self, response: Response, body: Body) -> None:
        """Give the client `response`, whether or not the exchange has been
        forwarded, before or after: the client's response is its own lane.
        An early answer leaves a forward to run on while this side still
        reads its response; a handler that wants nothing forwarded does not
        forward. It may finish its answer while still consuming the forward's
        response. A body that failed on its way in is
        relayed cut, with the error on its end. On an observe stream nothing
        is sent: roxy's own answer stands."""
        if self._s.observe:
            return
        await self._s.send(
            {
                "type": "response",
                "status": response.status,
                "headers": response.headers,
            },
            end=RESPONSE if self._s.head_only[RESPONSE] else None,
        )
        await self._send_body(RESPONSE, body)


def _response_of(m: dict[str, Any] | bytes) -> Response:
    """The response head the forward's response lane opened with."""
    if isinstance(m, bytes):
        raise ProtocolError("body bytes before the response head")
    if m.get("type") == "response_end":
        raise ForwardEnded(m.get("error"))
    if m.get("type") != "response":
        raise ProtocolError(f"expected response, got {m.get('type')}")
    return Response(
        status=m["status"],
        headers=[tuple(h) for h in m.get("headers", [])],  # type: ignore[misc]
    )


Handler = Callable[[Exchange], Awaitable[None]]


def serve(handler: Handler, host: str, port: int, **kwargs: Any) -> Any:
    """A server for `handler`, one call per exchange; use as
    `async with serve(...) as server: await server.serve_forever()`."""

    async def connection(ws: ServerConnection) -> None:
        await _Conn(ws, handler).run()

    return ws_serve(
        connection,
        host,
        port,
        subprotocols=[SUBPROTOCOL],  # type: ignore[list-item]
        max_size=16 * 1024 * 1024,
        **kwargs,
    )
