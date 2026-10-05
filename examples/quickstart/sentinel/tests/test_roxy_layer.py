import asyncio

from fake_roxy import FakeRoxy, stray_tasks
from roxy_layer import REQUEST, RESPONSE, WINDOW, Exchange


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
