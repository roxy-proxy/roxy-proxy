"""A scripted roxy: drives `roxy_layer._Conn` over an in-memory socket."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from roxy_layer import REQUEST, Handler, _Conn


class FakeSocket:
    """The service end of a layer connection. Frames put with `send_*` are
    what roxy says; what the service sends lands in `sent`."""

    def __init__(self) -> None:
        self._incoming: asyncio.Queue[str | bytes | None] = asyncio.Queue()
        self.sent: asyncio.Queue[dict[str, Any] | bytes] = asyncio.Queue()

    def __aiter__(self) -> FakeSocket:
        return self

    async def __anext__(self) -> str | bytes:
        m = await self._incoming.get()
        if m is None:
            raise StopAsyncIteration
        return m

    async def send(self, m: str | bytes) -> None:
        self.sent.put_nowait(json.loads(m) if isinstance(m, str) else m)

    def control(self, stream: int, type: str, **fields: Any) -> None:
        self._incoming.put_nowait(json.dumps({"stream": stream, "type": type, **fields}))

    def body(self, stream: int, data: bytes, direction: int = REQUEST) -> None:
        self._incoming.put_nowait(stream.to_bytes(4, "big") + bytes([direction]) + data)

    def close(self) -> None:
        self._incoming.put_nowait(None)

    async def next_sent(self, timeout: float = 2.0) -> dict[str, Any] | bytes:
        """The next frame the service sent, other than its credit."""
        while True:
            m = await asyncio.wait_for(self.sent.get(), timeout)
            if isinstance(m, bytes) or m.get("type") != "credit":
                return m


class FakeRoxy:
    def __init__(self, handler: Handler) -> None:
        self.ws = FakeSocket()
        self.conn = _Conn(self.ws, handler)  # type: ignore[arg-type]
        self.task = asyncio.create_task(self.conn.run())

    def open(self, stream: int, url: str = "https://example.test/", method: str = "POST", headers: Any = ()) -> None:
        self.ws.control(stream, "open", flow=f"flow-{stream}", layer="sentinel", mode="enforce")
        self.ws.control(stream, "request", method=method, url=url, headers=[list(h) for h in headers])

    async def until_closed(self, stream: int) -> None:
        """Waits until the stream's task has finished, and a few loop turns
        after, for anything it cancelled to finish too."""
        s = self.conn.streams.get(stream)
        if s is not None:
            await asyncio.wait({s.task}, timeout=2.0)
        for _ in range(5):
            await asyncio.sleep(0)


def stray_tasks(*expected: asyncio.Task[Any]) -> set[asyncio.Task[Any]]:
    """Tasks still alive other than the test's own and `expected`."""
    return asyncio.all_tasks() - {asyncio.current_task(), *expected}
