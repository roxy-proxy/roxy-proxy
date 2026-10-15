"""Regressions for independent input and output completion."""
import asyncio

import pytest

from fake_roxy import FakeRoxy
from roxy_layer import Exchange, HostError, ProtocolError, Response, RESPONSE


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


async def test_call_waiting_for_socket_lock_is_rejected_after_last_input():
    answer_done = asyncio.Event()
    call_now = asyncio.Event()
    call_started = asyncio.Event()
    refused = asyncio.Event()

    async def handle(ex: Exchange):
        await ex.forward(ex.request, b"")
        await ex.respond(Response(200), b"")
        answer_done.set()
        await call_now.wait()
        call_started.set()
        with pytest.raises(ProtocolError, match="the stream has ended"):
            await ex.record("after_answer", {})
        refused.set()

    roxy = FakeRoxy(handle)
    try:
        roxy.open(1)
        roxy.ws.control(1, "request_end")
        assert (await roxy.ws.next_sent())["type"] == "request"
        assert (await roxy.ws.next_sent())["type"] == "request_end"
        roxy.ws.control(1, "response", status=200, headers=[])
        assert (await roxy.ws.next_sent())["type"] == "response"
        assert (await roxy.ws.next_sent())["type"] == "response_end"
        await answer_done.wait()
        stream = roxy.conn.streams[1]
        async with roxy.conn.lock:
            call_now.set()
            await call_started.wait()
            # The call has reached the occupied lock. Roxy can retire now:
            # all four lanes finish without any call having gone out.
            roxy.ws.control(1, "response_end")
            await asyncio.wait_for(stream._settled.wait(), 1.0)
            assert not stream.pending
        await asyncio.wait_for(stream.task, 1.0)
        assert refused.is_set()
        assert 1 not in roxy.conn.streams
        assert roxy.ws.sent.empty()
    finally:
        roxy.ws.close()
        await roxy.task


async def test_call_waiting_for_socket_lock_is_rejected_after_reset():
    ready = asyncio.Event()
    started = asyncio.Event()

    async def handle(ex: Exchange):
        ready.set()
        await asyncio.Event().wait()

    roxy = FakeRoxy(handle)
    call = None
    try:
        roxy.open(1)
        await ready.wait()
        stream = roxy.conn.streams[1]

        async def record():
            started.set()
            await stream.call({"type": "record", "kind": "late", "data": {}})

        async with roxy.conn.lock:
            call = asyncio.create_task(record())
            await started.wait()
            roxy.ws.control(1, "reset")
            await asyncio.wait_for(stream.task, 1.0)
        with pytest.raises(ProtocolError, match="the stream has ended"):
            await asyncio.wait_for(call, 1.0)
        assert not stream.pending
        assert roxy.ws.sent.empty()
    finally:
        if call is not None and not call.done():
            call.cancel()
            await asyncio.gather(call, return_exceptions=True)
        roxy.ws.close()
        await roxy.task


async def test_call_crossing_retirement_receives_a_refusal():
    refused = asyncio.Event()

    async def handle(ex: Exchange):
        await ex.forward(ex.request, b"")
        await ex.respond(Response(200), b"")
        with pytest.raises(HostError, match="the stream has ended"):
            await ex.record("after_answer", {})
        refused.set()

    roxy = FakeRoxy(handle)
    try:
        roxy.open(1)
        roxy.ws.control(1, "request_end")
        assert (await roxy.ws.next_sent())["type"] == "request"
        assert (await roxy.ws.next_sent())["type"] == "request_end"
        roxy.ws.control(1, "response", status=200, headers=[])
        assert (await roxy.ws.next_sent())["type"] == "response"
        assert (await roxy.ws.next_sent())["type"] == "response_end"
        # Roxy ended its last input before it received the new call.
        roxy.ws.control(1, "response_end")
        record = await roxy.ws.next_sent()
        assert record["type"] == "record"
        roxy.ws.control(1, "result", id=record["id"], error="the stream has ended")
        await roxy.until_closed(1)
        assert refused.is_set()
        assert 1 not in roxy.conn.streams
        assert roxy.ws.sent.empty()
    finally:
        roxy.ws.close()
        await roxy.task
