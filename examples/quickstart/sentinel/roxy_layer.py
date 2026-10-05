"""The service side of roxy's service layers (`roxy.layer.v3`).

roxy keeps a few WebSocket connections open to the service and carries
each exchange as a stream on one of them. Text frames are JSON control
messages with a `stream` field; binary frames are a 4-byte big-endian
stream id, a direction byte (0 for the request body, 1 for the response
body), then body bytes:

    roxy -> service   open (the exchange's metadata), then the request:
                      head, body bytes, request_end
    service -> roxy   the request to forward (head, bytes, request_end),
                      or a response of its own, or a deny
    roxy -> service   the response from below: head, bytes, response_end
    service -> roxy   the response for the client (head, bytes, response_end),
                      or a deny

The request and response bodies of a stream are independent: roxy sends
its `response` head as soon as the layer below answers, even while the
client is still uploading, and the service may do the same. Each body is
flow-controlled with `credit` messages, and either side may abandon a
stream with `reset`. This module handles the streams, credit and resets,
and turns each exchange into one coroutine:

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

SUBPROTOCOL = "roxy.layer.v3"

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


class ProtocolError(Exception):
    """roxy sent something out of order, or reset the stream."""


class _Conn:
    """One connection from roxy: its streams, and the way out."""

    def __init__(self, ws: ServerConnection, handler: Handler) -> None:
        self.ws = ws
        self.handler = handler
        self.streams: dict[int, _Stream] = {}
        self._send_lock = asyncio.Lock()

    async def send(self, stream: int, msg: dict[str, Any]) -> None:
        msg["stream"] = stream
        async with self._send_lock:
            await self.ws.send(json.dumps(msg))

    async def send_bytes(self, stream: int, direction: int, data: bytes) -> None:
        async with self._send_lock:
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
            tasks = [s.task for s in self.streams.values()]
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    def _control(self, msg: dict[str, Any]) -> None:
        sid = msg["stream"]
        kind = msg.get("type")
        if kind == "open":
            flow = {k: v for k, v in msg.items() if k not in ("type", "stream")}
            s = _Stream(self, sid, flow)
            self.streams[sid] = s
            s.task = asyncio.create_task(s.run(observe=flow.get("mode") == "observe"))
            return
        s = self.streams.get(sid)
        if s is None:
            # A message that crossed the stream's end.
            return
        if kind == "credit":
            lane = s.lane(_DIRS[msg["dir"]])
            lane.credit += int(msg["bytes"])
            lane.more_credit.set()
        elif kind == "reset":
            self.streams.pop(sid, None)
            s.task.cancel()
        else:
            s.inbox(_DIR_OF_MESSAGE.get(kind, REQUEST)).put_nowait(msg)


class _Lane:
    """One body of a stream, each way: what roxy sent of it, and the credit
    for what this side may send."""

    def __init__(self) -> None:
        self.inbox: asyncio.Queue[dict[str, Any] | bytes] = asyncio.Queue()
        self.credit = WINDOW
        self.more_credit = asyncio.Event()
        # Bytes consumed and not yet credited back to roxy.
        self.unacked = 0


class _Stream:
    def __init__(self, conn: _Conn, sid: int, flow: dict[str, Any]) -> None:
        self.conn = conn
        self.id = sid
        self.flow = flow
        self.lanes = {REQUEST: _Lane(), RESPONSE: _Lane()}
        self.task: asyncio.Task[None]

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
            # The request body may still be going out after the handler
            # has answered; the stream is roxy's to end once it has.
            await exchange._finish_forwarding()
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
            # for input or credit forever.
            if exchange is not None:
                await exchange._stop_forwarding()
            self.conn.streams.pop(self.id, None)

    async def recv(self, direction: int) -> dict[str, Any] | bytes:
        lane = self.lanes[direction]
        m = await lane.inbox.get()
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
        while view:
            while lane.credit <= 0:
                lane.more_credit.clear()
                await lane.more_credit.wait()
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
        or `observe`), client_ip, client_user, listener, sni, tags. The pair
        (flow, layer) is unique to this exchange."""
        self._body_read = False
        self._response_read = False
        # The forwarded request body still going out, if `forward` returned
        # before it had all gone.
        self._forwarding: asyncio.Task[None] | None = None

    @property
    def observing(self) -> bool:
        """roxy sends copies and ignores the answers (`mode: observe`)."""
        return self.flow.get("mode") == "observe"

    async def _body(self, direction: int) -> AsyncIterator[bytes]:
        end = f"{_DIR_NAMES[direction]}_end"
        while True:
            m = await self._s.recv(direction)
            if isinstance(m, bytes):
                yield m
                continue
            if m.get("type") != end:
                raise ProtocolError(f"expected {end}, got {m.get('type')}")
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

    async def _send(self, msg: dict[str, Any]) -> None:
        await self._s.conn.send(self._s.id, msg)

    async def _send_body(self, direction: int, body: Body) -> None:
        if isinstance(body, bytes):
            if body:
                await self._s.send_bytes(direction, body)
        else:
            async for chunk in body:
                if chunk:
                    await self._s.send_bytes(direction, chunk)
        await self._send({"type": f"{_DIR_NAMES[direction]}_end"})

    async def _finish_forwarding(self) -> None:
        if self._forwarding is not None:
            await self._forwarding

    def _cancel_forwarding(self) -> None:
        if self._forwarding is not None:
            self._forwarding.cancel()

    async def _stop_forwarding(self) -> None:
        if self._forwarding is None:
            return
        self._forwarding.cancel()
        await asyncio.wait({self._forwarding})
        if not self._forwarding.cancelled():
            # Retrieved, so a send that failed as the socket closed is not
            # logged as never retrieved; the exchange's outcome is reported.
            self._forwarding.exception()

    async def forward(self, request: Request, body: Body) -> Response:
        """Pass `request` on down the stack and return the response head
        from below, as soon as there is one: the body keeps going out in
        the background if roxy answers before it has all been sent. roxy
        re-validates the request and its rules judge it; read the response
        body with `response_body()`."""
        await self._send(
            {
                "type": "request",
                "method": request.method,
                "url": request.url,
                "headers": request.headers,
            }
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
        if isinstance(m, bytes):
            raise ProtocolError("body bytes before the response head")
        if m.get("type") != "response":
            raise ProtocolError(f"expected response, got {m.get('type')}")
        return Response(
            status=m["status"],
            headers=[tuple(h) for h in m.get("headers", [])],  # type: ignore[misc]
        )

    def response_body(self) -> AsyncIterator[bytes]:
        """The response body from below, as it arrives. Read it once, after
        `forward`."""
        if self._response_read:
            raise ProtocolError("the response body was already read")
        self._response_read = True
        return self._body(RESPONSE)

    async def read_response_body(self) -> bytes:
        """The whole response body from below."""
        return b"".join([c async for c in self.response_body()])

    async def respond(self, response: Response, body: Body) -> None:
        """Give the client `response`: after `forward`, the response the
        client gets; before it, an answer instead of forwarding. It may be
        sent while the forwarded request body is still going out."""
        await self._send(
            {
                "type": "response",
                "status": response.status,
                "headers": response.headers,
            }
        )
        await self._send_body(RESPONSE, body)

    async def deny(self, status: int = 403, message: str | None = None) -> None:
        """Refuse: before `forward` the request is never sent; after it, the
        response is replaced. `status` is 4xx or 5xx."""
        msg: dict[str, Any] = {"type": "deny", "status": status}
        if message is not None:
            msg["message"] = message
        await self._send(msg)


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
