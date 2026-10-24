import asyncio
from collections.abc import AsyncIterator

import pytest

from fake_roxy import FakeRoxy, stray_tasks
from roxy_layer import REQUEST, RESPONSE, WINDOW, Exchange, ProtocolError, Response


async def forward_and_answer(ex: Exchange) -> None:
    res = await ex.forward(ex.request, ex.body())
    await ex.respond(res, ex.response_body())


@pytest.mark.parametrize("hold", ["request", "response"])
@pytest.mark.parametrize("decision", ["approve", "edit", "deny"])
async def test_sse_approval_keeps_the_answer_open_while_holding_an_input(hold: str, decision: str) -> None:
    approve = asyncio.Event()
    tool = b'event: tool_call\ndata: {"name":"delete_file"}\n\n'
    edited = tool.replace(b"delete_file", b"read_file")
    start = b"event: start\ndata: {}\n\n"
    keepalive = b": approval pending\n\n"
    tail = b"event: done\ndata: {}\n\n"
    denied = b"event: denied\ndata: {}\n\n"

    async def handle(ex: Exchange) -> None:
        async def output() -> AsyncIterator[bytes]:
            yield start
            incoming = ex.response_body()
            held = None
            if hold == "response":
                await ex.forward(ex.request, ex.body())
                held = await anext(incoming)
            yield keepalive
            await approve.wait()
            if decision == "deny":
                yield denied
                return
            if hold == "request":
                await ex.forward(ex.request, edited if decision == "edit" else ex.body())
            else:
                assert held == tool
                yield edited if decision == "edit" else held
            async for chunk in incoming:
                yield chunk

        await ex.respond(Response(200, [("content-type", "text/event-stream")]), output())

    roxy = FakeRoxy(handle)
    roxy.open(1)
    roxy.ws.body(1, tool)
    roxy.ws.control(1, "request_end")
    assert (await roxy.ws.next_sent())["type"] == "response"
    assert await roxy.ws.next_sent() == b"\x00\x00\x00\x01\x01" + start

    async def forwarded(expected: bytes) -> None:
        assert (await roxy.ws.next_sent())["type"] == "request"
        assert await roxy.ws.next_sent() == b"\x00\x00\x00\x01\x00" + expected
        assert (await roxy.ws.next_sent())["type"] == "request_end"
        roxy.ws.control(1, "response", status=201, headers=[])

    if hold == "response":
        await forwarded(tool)
        roxy.ws.body(1, tool, RESPONSE)
    assert await roxy.ws.next_sent() == b"\x00\x00\x00\x01\x01" + keepalive
    with pytest.raises(TimeoutError):
        await roxy.ws.next_sent(timeout=0.01)
    approve.set()
    if decision == "deny":
        assert await roxy.ws.next_sent() == b"\x00\x00\x00\x01\x01" + denied
    else:
        if hold == "request":
            await forwarded(edited if decision == "edit" else tool)
            roxy.ws.body(1, edited if decision == "edit" else tool, RESPONSE)
        expected = edited if decision == "edit" else tool
        assert await roxy.ws.next_sent() == b"\x00\x00\x00\x01\x01" + expected
        # The approved event has gone out before the next one exists.
        roxy.ws.body(1, tail, RESPONSE)
        assert await roxy.ws.next_sent() == b"\x00\x00\x00\x01\x01" + tail
        roxy.ws.control(1, "response_end")
    assert (await roxy.ws.next_sent())["type"] == "response_end"
    await roxy.until_closed(1)
    assert 1 not in roxy.conn.streams
    assert stray_tasks(roxy.task) == set()


async def expect_stops(roxy: FakeRoxy, *directions: str) -> None:
    # Independent inputs can be released in either order.
    messages = [await roxy.ws.next_sent() for _ in directions]
    assert all(m["type"] == "stop" and m["stream"] == 1 for m in messages)
    assert sorted(m["dir"] for m in messages) == sorted(directions)


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
    await expect_stops(roxy, "request", "response")
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


async def test_a_completed_answer_keeps_receiving_the_forward() -> None:
    """Finishing both outputs leaves the upstream input available."""
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
    assert not roxy.conn.streams[1].ended
    roxy.ws.control(1, "response", status=204, headers=[])
    await expect_stops(roxy, "request", "response")
    await roxy.until_closed(1)
    assert outcome == [None], outcome
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
    await expect_stops(roxy, "request", "response")
    assert (await roxy.ws.next_sent())["type"] == "request_end"
    await roxy.until_closed(1)
    assert outcome == [None], outcome
    assert stray_tasks(roxy.task) == set()


@pytest.mark.parametrize("error", [None, "upstream cancelled"])
async def test_headless_forward_ends_without_resetting_the_service(error: str | None) -> None:
    roxy = await started_upload()
    roxy.ws.control(1, "response_end", **({"error": error} if error else {}))
    await expect_stops(roxy, "request")
    request_end = await roxy.ws.next_sent()
    assert request_end["type"] == "request_end"
    assert request_end["error"]
    response_end = await roxy.ws.next_sent()
    assert response_end["type"] == "response_end"
    assert response_end.get("error") == error
    await roxy.until_closed(1)
    assert 1 not in roxy.conn.streams
    assert stray_tasks(roxy.task) == set()
    assert roxy.ws.sent.empty()


async def test_accepted_call_gets_its_result_after_the_handler_finishes() -> None:
    calls: list[asyncio.Task[object]] = []

    async def handle(ex: Exchange) -> None:
        calls.append(asyncio.create_task(ex.record("audit", {"n": 1})))
        await asyncio.sleep(0)
        await ex.respond(Response(204, []), b"")

    roxy = FakeRoxy(handle)
    roxy.open(1)
    record = await roxy.ws.next_sent()
    assert record["type"] == "record"
    assert (await roxy.ws.next_sent())["type"] == "response"
    assert (await roxy.ws.next_sent())["type"] == "response_end"
    await expect_stops(roxy, "request", "response")
    assert (await roxy.ws.next_sent())["type"] == "request_end"
    assert not roxy.conn.streams[1].ended
    roxy.ws.control(1, "result", id=record["id"], value=None)
    await roxy.until_closed(1)
    assert await calls[0] is None
    assert stray_tasks(roxy.task) == set()


async def test_a_head_only_exchange_is_heads_alone_each_way() -> None:
    roxy = FakeRoxy(forward_and_answer)
    roxy.open(1, subscribe={"request": "head", "response": "head"})
    forwarded = await roxy.ws.next_sent()
    assert isinstance(forwarded, dict) and forwarded["type"] == "request"
    roxy.ws.control(1, "response", status=204, headers=[])
    answer = await roxy.ws.next_sent()
    assert isinstance(answer, dict) and answer["type"] == "response" and answer["status"] == 204
    await roxy.until_closed(1)
    assert 1 not in roxy.conn.streams
    # No bytes, ends or stops follow either head.
    with pytest.raises(TimeoutError):
        await roxy.ws.next_sent(timeout=0.01)


async def test_an_observer_sends_nothing_on_its_lanes_then_closes() -> None:
    seen: list[bytes] = []

    async def handle(ex: Exchange) -> None:
        seen.append(await ex.read_body())
        res = await ex.forward(ex.request, b"ignored")
        seen.append(await ex.read_response_body())
        await ex.respond(res, b"ignored")

    roxy = FakeRoxy(handle)
    roxy.open(1, mode="observe")
    roxy.ws.body(1, b"up")
    roxy.ws.control(1, "request_end")
    roxy.ws.control(1, "response", status=200, headers=[])
    roxy.ws.body(1, b"down", RESPONSE)
    roxy.ws.control(1, "response_end")
    assert await roxy.ws.next_sent() == {"stream": 1, "type": "close"}
    await roxy.until_closed(1)
    assert seen == [b"up", b"down"]
    assert 1 not in roxy.conn.streams
