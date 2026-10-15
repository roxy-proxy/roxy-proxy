import asyncio
from collections.abc import AsyncIterator

import pytest

from fake_roxy import FakeRoxy, stray_tasks
from roxy_layer import REQUEST, RESPONSE, WINDOW, Exchange, ProtocolError, Response


async def forward_and_answer(ex: Exchange) -> None:
    res = await ex.forward(ex.request, ex.body())
    await ex.respond(res, ex.response_body())


async def started_upload() -> FakeRoxy:
    """An exchange whose request body is going out and has no response yet."""
    roxy = FakeRoxy(forward_and_answer)
    roxy.open(1)
    roxy.ws.body(1, b"partial upload")
    assert (await roxy.ws.next_sent())["type"] == "request"
    assert await roxy.ws.next_sent() == b"\x00\x00\x00\x01\x00partial upload"
    return roxy


async def test_reset_mid_forward_leaves_no_tasks() -> None:
    roxy = await started_upload()
    roxy.ws.control(1, "reset")
    # roxy may still credit bytes back for a stream it has ended.
    roxy.ws.control(1, "credit", dir="request", bytes=14)
    await roxy.until_closed(1)
    assert stray_tasks(roxy.task) == set()


async def test_reset_with_the_window_spent_leaves_no_tasks() -> None:
    roxy = FakeRoxy(forward_and_answer)
    roxy.open(1)
    roxy.ws.body(1, b"x" * (WINDOW + 1))
    assert (await roxy.ws.next_sent())["type"] == "request"
    sent = 0
    while sent < WINDOW:
        sent += len(await roxy.ws.next_sent()) - 5
    roxy.ws.control(1, "reset")
    await roxy.until_closed(1)
    assert stray_tasks(roxy.task) == set()


async def test_connection_close_mid_forward_leaves_no_tasks() -> None:
    roxy = await started_upload()
    roxy.ws.close()
    await asyncio.wait_for(roxy.task, 2.0)
    assert stray_tasks() == set()


@pytest.mark.parametrize("direction", [REQUEST, RESPONSE])
@pytest.mark.parametrize("waiting_for_credit", [False, True])
async def test_stop_closes_a_waiting_body_source(direction: int, waiting_for_credit: bool) -> None:
    started = asyncio.Event()
    closed = asyncio.Event()

    async def source() -> AsyncIterator[bytes]:
        try:
            started.set()
            if waiting_for_credit:
                yield b"x" * (WINDOW + 1)
            await asyncio.Future()
            yield b"unreachable"
        finally:
            closed.set()

    async def handle(ex: Exchange) -> None:
        if direction == REQUEST:
            response = await ex.forward(ex.request, source())
            await ex.respond(response, b"")
        else:
            await ex.respond(Response(200, []), source())

    roxy = FakeRoxy(handle)
    roxy.open(1)
    assert (await roxy.ws.next_sent())["type"] == ("request" if direction == REQUEST else "response")
    await asyncio.wait_for(started.wait(), 2.0)
    if waiting_for_credit:
        sent = 0
        while sent < WINDOW:
            sent += len(await roxy.ws.next_sent()) - 5
    if direction == REQUEST:
        roxy.ws.control(1, "response", status=200, headers=[])
        assert (await roxy.ws.next_sent())["type"] == "response"
        assert (await roxy.ws.next_sent())["type"] == "response_end"
    roxy.ws.control(1, "stop", dir="request" if direction == REQUEST else "response")
    await asyncio.wait_for(closed.wait(), 2.0)
    if direction == RESPONSE:
        assert (await roxy.ws.next_sent())["type"] == "request_end"
    await roxy.until_closed(1)
    assert 1 not in roxy.conn.streams
    assert roxy.ws.sent.empty(), "a stopped lane sends neither bytes nor an end"
    assert stray_tasks(roxy.task) == set()


async def test_an_upgrade_streams_both_ways_with_no_request_end() -> None:
    """roxy sends no `request_end` before a `101`: the pass-through
    forwards at once, answers the `101`, and carries both directions
    while neither body has ended."""
    roxy = FakeRoxy(forward_and_answer)
    roxy.open(1, url="https://example.test/ws", method="GET")
    assert (await roxy.ws.next_sent())["type"] == "request"
    roxy.ws.control(1, "response", status=101, headers=[])
    head = await roxy.ws.next_sent()
    assert isinstance(head, dict) and head["type"] == "response" and head["status"] == 101
    client_frame = b"\x81\x85\x01\x02\x03\x04ignnn"
    roxy.ws.body(1, client_frame, REQUEST)
    assert await roxy.ws.next_sent() == b"\x00\x00\x00\x01\x00" + client_frame
    upstream_frame = b"\x81\x05hello"
    roxy.ws.body(1, upstream_frame, RESPONSE)
    assert await roxy.ws.next_sent() == b"\x00\x00\x00\x01\x01" + upstream_frame
    roxy.ws.body(1, client_frame, REQUEST)
    assert await roxy.ws.next_sent() == b"\x00\x00\x00\x01\x00" + client_frame
    roxy.ws.control(1, "response_end")
    assert (await roxy.ws.next_sent())["type"] == "response_end"
    roxy.ws.control(1, "request_end")
    assert (await roxy.ws.next_sent())["type"] == "request_end"
    await roxy.until_closed(1)
    assert stray_tasks(roxy.task) == set()


async def test_a_forward_awaited_after_the_streams_end_fails() -> None:
    """A handler that forwards and completes its answer before the head from
    below arrives has sent its last message: roxy sends nothing more, so the
    forward raises `ProtocolError` at once rather than waiting for a head
    that cannot come."""
    outcome: list[BaseException | None] = []
    forwarded = asyncio.Event()

    async def answer_while_forwarding(ex: Exchange) -> None:
        head = asyncio.ensure_future(ex.forward(ex.request, b""))
        # The forward goes out first, whole; the answer completes behind it.
        await forwarded.wait()
        await ex.respond(Response(200, []), b"")
        try:
            await head
            outcome.append(None)
        except ProtocolError as e:
            outcome.append(e)

    roxy = FakeRoxy(answer_while_forwarding)
    roxy.open(1)
    assert (await roxy.ws.next_sent())["type"] == "request"
    assert (await roxy.ws.next_sent())["type"] == "request_end"
    forwarded.set()
    assert (await roxy.ws.next_sent())["type"] == "response"
    assert (await roxy.ws.next_sent())["type"] == "response_end"
    await roxy.until_closed(1)
    assert outcome and isinstance(outcome[0], ProtocolError), outcome
    assert stray_tasks(roxy.task) == set()


async def test_a_call_awaited_after_the_answer_is_still_answered() -> None:
    """An answer is not the handler's last message: the request lane ends
    only when the handler returns without forwarding. A call awaited after
    the answer is answered by roxy as usual, and the stream ends on the
    `request_end` the module sends for the handler."""
    outcome: list[BaseException | None] = []

    async def respond_then_await(ex: Exchange) -> None:
        call = asyncio.ensure_future(ex.record("audit", {"n": 1}))
        # The call goes out before the answer does.
        await asyncio.sleep(0)
        await ex.respond(Response(200, []), b"")
        try:
            await call
            outcome.append(None)
        except ProtocolError as e:
            outcome.append(e)

    roxy = FakeRoxy(respond_then_await)
    roxy.open(1)
    record = await roxy.ws.next_sent()
    assert record["type"] == "record"
    assert (await roxy.ws.next_sent())["type"] == "response"
    assert (await roxy.ws.next_sent())["type"] == "response_end"
    roxy.ws.control(1, "result", id=record["id"], value=None)
    assert (await roxy.ws.next_sent())["type"] == "request_end"
    await roxy.until_closed(1)
    assert outcome == [None], outcome
    assert stray_tasks(roxy.task) == set()
