"""Regressions for independent input and output completion."""
import asyncio

import pytest

from fake_roxy import FakeRoxy
from roxy_layer import Exchange, Response, RESPONSE


async def test_handler_return_stops_unread_response_before_waiting_on_upload():
    returned = asyncio.Event()
    release_upload = asyncio.Event()

    async def source():
        yield b"initial"
        await release_upload.wait()
        yield b"tail"

    async def handle(ex: Exchange):
        await ex.forward(ex.request, source())
        await ex.respond(Response(200), b"done")
        returned.set()

    roxy = FakeRoxy(handle)
    try:
        roxy.open(1)
        roxy.ws.control(1, "request_end")
        assert (await roxy.ws.next_sent())["type"] == "request"
        assert (await roxy.ws.next_sent()).endswith(b"initial")
        roxy.ws.control(1, "response", status=200, headers=[])
        assert (await roxy.ws.next_sent())["type"] == "response"
        assert (await roxy.ws.next_sent()).endswith(b"done")
        assert (await roxy.ws.next_sent())["type"] == "response_end"
        await returned.wait()
        stop = await roxy.ws.next_sent(timeout=0.1)
        assert stop == {"type": "stop", "dir": "response", "stream": 1}
    finally:
        roxy.ws.close()
        await roxy.task


async def test_finished_response_preserves_a_continuing_upload():
    returned = asyncio.Event()
    release_upload = asyncio.Event()
    source_closed = asyncio.Event()

    async def source():
        try:
            yield b"initial"
            await release_upload.wait()
            yield b"tail"
        finally:
            source_closed.set()

    async def handle(ex: Exchange):
        await ex.forward(ex.request, source())
        assert b"".join([chunk async for chunk in ex.response_body()]) == b"origin"
        await ex.respond(Response(200), b"done")
        returned.set()

    roxy = FakeRoxy(handle)
    try:
        roxy.open(1)
        roxy.ws.control(1, "request_end")
        assert (await roxy.ws.next_sent())["type"] == "request"
        assert (await roxy.ws.next_sent()).endswith(b"initial")
        roxy.ws.control(1, "response", status=200, headers=[])
        roxy.ws.body(1, b"origin", RESPONSE)
        roxy.ws.control(1, "response_end")
        assert (await roxy.ws.next_sent())["type"] == "response"
        assert (await roxy.ws.next_sent()).endswith(b"done")
        assert (await roxy.ws.next_sent())["type"] == "response_end"
        await returned.wait()
        with pytest.raises(TimeoutError):
            await roxy.ws.next_sent(timeout=0.05)
        assert not source_closed.is_set()
        release_upload.set()
        assert (await roxy.ws.next_sent()).endswith(b"tail")
        assert (await roxy.ws.next_sent())["type"] == "request_end"
        await roxy.until_closed(1)
        assert source_closed.is_set()
        assert 1 not in roxy.conn.streams
    finally:
        roxy.ws.close()
        await roxy.task
