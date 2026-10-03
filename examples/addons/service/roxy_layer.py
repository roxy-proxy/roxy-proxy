"""The service side of roxy's service layers (`roxy.layer.v1`, DESIGN.md §11.6).

roxy opens one WebSocket per exchange. Text frames are JSON control
messages and binary frames are body bytes of the message whose head came
last:

    roxy -> service   request head, body bytes, request_end
    service -> roxy   the request to forward (head, bytes, request_end),
                      or a response of its own, or a deny
    roxy -> service   the response from below: head, bytes, response_end
    service -> roxy   the response for the client (head, bytes, response_end),
                      or a deny

This module turns that into one coroutine per exchange:

    async def handle(ex: Exchange) -> None:
        response = await ex.forward(ex.request, ex.body())
        await ex.respond(response, ex.response_body())

    asyncio.run(serve(handle, "127.0.0.1", 9000))

Bodies stream: `ex.body()` yields the client's request bytes as they
arrive, and `forward` sends each one on as it is read. A handler that
needs a whole body reads it with `read_body()` / `read_response_body()`.

If the handler raises, the socket closes without an answer and roxy fails
the exchange closed (enforce mode). Only the `websockets` package is
needed.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterable, AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from websockets.asyncio.server import ServerConnection, serve as ws_serve

SUBPROTOCOL = "roxy.layer.v1"

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
    """roxy sent something out of order (or the socket closed mid-message)."""


class Exchange:
    """One exchange, from the service's side."""

    def __init__(self, ws: ServerConnection, request: Request) -> None:
        self._ws = ws
        self.request = request
        """The client's request head, as it reached this layer."""
        self.flow: dict[str, str] = {
            k.lower(): v
            for k, v in ws.request.headers.raw_items()
            if k.lower().startswith("roxy-flow-")
        }
        """`roxy-flow-*` metadata from the handshake: id, conn, layer, mode
        (`enforce` or `observe`), client-ip, client-user, listener, sni, tags."""
        self._body_read = False
        self._response_read = False

    @property
    def observing(self) -> bool:
        """roxy sends copies and ignores the answers (`mode: observe`)."""
        return self.flow.get("roxy-flow-mode") == "observe"

    async def _recv(self) -> str | bytes:
        try:
            return await self._ws.recv()
        except Exception as e:  # closed
            raise ProtocolError(f"socket closed: {e}") from e

    async def _body(self, end: str) -> AsyncIterator[bytes]:
        while True:
            m = await self._recv()
            if isinstance(m, bytes):
                yield m
                continue
            msg = json.loads(m)
            if msg.get("type") != end:
                raise ProtocolError(f"expected {end}, got {msg.get('type')}")
            return

    def body(self) -> AsyncIterator[bytes]:
        """The request body, as it arrives. Read it once."""
        if self._body_read:
            raise ProtocolError("the request body was already read")
        self._body_read = True
        return self._body("request_end")

    async def read_body(self) -> bytes:
        """The whole request body."""
        return b"".join([c async for c in self.body()])

    async def _send_body(self, body: Body, end: str) -> None:
        if isinstance(body, bytes):
            if body:
                await self._ws.send(body)
        else:
            async for chunk in body:
                if chunk:
                    await self._ws.send(chunk)
        await self._ws.send(json.dumps({"type": end}))

    async def forward(self, request: Request, body: Body) -> Response:
        """Pass `request` on down the stack and return the response head
        from below. roxy re-validates it and its rules judge it; read the
        response body with `response_body()`."""
        await self._ws.send(
            json.dumps(
                {
                    "type": "request",
                    "method": request.method,
                    "url": request.url,
                    "headers": request.headers,
                }
            )
        )
        await self._send_body(body, "request_end")
        if not self._body_read:
            # The client's body must still be consumed before roxy's
            # response arrives on the same socket.
            async for _ in self.body():
                pass
        m = await self._recv()
        if isinstance(m, bytes):
            raise ProtocolError("body bytes before the response head")
        msg = json.loads(m)
        if msg.get("type") != "response":
            raise ProtocolError(f"expected response, got {msg.get('type')}")
        return Response(
            status=msg["status"],
            headers=[tuple(h) for h in msg.get("headers", [])],  # type: ignore[misc]
        )

    def response_body(self) -> AsyncIterator[bytes]:
        """The response body from below, as it arrives. Read it once, after
        `forward`."""
        if self._response_read:
            raise ProtocolError("the response body was already read")
        self._response_read = True
        return self._body("response_end")

    async def read_response_body(self) -> bytes:
        """The whole response body from below."""
        return b"".join([c async for c in self.response_body()])

    async def respond(self, response: Response, body: Body) -> None:
        """Give the client `response`: after `forward`, the response the
        client gets; before it, an answer instead of forwarding."""
        await self._ws.send(
            json.dumps(
                {
                    "type": "response",
                    "status": response.status,
                    "headers": response.headers,
                }
            )
        )
        await self._send_body(body, "response_end")

    async def deny(self, status: int = 403, message: str | None = None) -> None:
        """Refuse: before `forward` the request is never sent; after it, the
        response is replaced. `status` is 4xx or 5xx."""
        msg: dict[str, Any] = {"type": "deny", "status": status}
        if message is not None:
            msg["message"] = message
        await self._ws.send(json.dumps(msg))


Handler = Callable[[Exchange], Awaitable[None]]


async def _session(handler: Handler, ws: ServerConnection) -> None:
    first = await ws.recv()
    if isinstance(first, bytes):
        raise ProtocolError("body bytes before the request head")
    msg = json.loads(first)
    if msg.get("type") != "request":
        raise ProtocolError(f"expected request, got {msg.get('type')}")
    request = Request(
        method=msg["method"],
        url=msg["url"],
        headers=[tuple(h) for h in msg.get("headers", [])],  # type: ignore[misc]
    )
    await handler(Exchange(ws, request))


def serve(handler: Handler, host: str, port: int, **kwargs: Any) -> Any:
    """A server for `handler`, one call per exchange; use as
    `async with serve(...) as server: await server.serve_forever()`."""

    async def session(ws: ServerConnection) -> None:
        try:
            await _session(handler, ws)
        except Exception:
            # Closing without an answer fails the exchange closed in roxy.
            log.exception("exchange failed")
            await ws.close(code=1011, reason="layer failed")

    return ws_serve(
        session,
        host,
        port,
        subprotocols=[SUBPROTOCOL],  # type: ignore[list-item]
        max_size=16 * 1024 * 1024,
        **kwargs,
    )
