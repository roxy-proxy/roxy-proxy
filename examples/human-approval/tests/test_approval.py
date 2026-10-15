"""The hold: the model's text streams to the agent live; its tool call waits
for the page, then goes on as the model sent it or is replaced by what the
person said."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

import pytest
from aiohttp.test_utils import TestClient, TestServer

from fake_roxy import FakeRoxy, stray_tasks
from roxy_layer import RESPONSE
import sidecar as sidecar_module
from sidecar import PING, Sidecar

from approval import build
from review import ReviewQueue, app

MESSAGES_URL = "https://api.anthropic.com/v1/messages"
FRAME = b"\x00\x00\x00\x01\x01"  # stream 1, response body
ARGUMENTS = {"command": "rm -rf build"}


def sse(event: str, data: dict[str, Any]) -> bytes:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()


def message(content: list[dict[str, Any]], stop_reason: str) -> dict[str, Any]:
    return {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": "claude-test",
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": {"input_tokens": 1, "output_tokens": 5},
    }


TOOL_USE = {"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": ARGUMENTS}

MESSAGE_START = sse(
    "message_start",
    {"type": "message_start", "message": {**message([], None), "stop_reason": None, "usage": {"input_tokens": 1, "output_tokens": 0}}},
)
# The rest of a streamed response: the model says something, then calls Bash.
TEXT = (
    sse("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}})
    + sse("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Cleaning up."}})
    + sse("content_block_stop", {"type": "content_block_stop", "index": 0})
)
TOOL_CALL = (
    sse("content_block_start", {"type": "content_block_start", "index": 1, "content_block": {**TOOL_USE, "input": {}}})
    + sse("content_block_delta", {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": json.dumps(ARGUMENTS)}})
    + sse("content_block_stop", {"type": "content_block_stop", "index": 1})
)
ENDING = sse(
    "message_delta", {"type": "message_delta", "delta": {"stop_reason": "tool_use", "stop_sequence": None}, "usage": {"output_tokens": 5}}
) + sse("message_stop", {"type": "message_stop"})


@pytest.fixture
async def demo(tmp_path: Any) -> AsyncIterator[tuple[Sidecar, ReviewQueue, TestClient]]:
    sidecar, queue = build(str(tmp_path))
    async with TestClient(TestServer(app(queue))) as ui:
        yield sidecar, queue, ui


async def model_call(roxy: FakeRoxy, *, stream: bool) -> None:
    """Drives a Messages call through to the model's response, a text block
    and a Bash tool call: streamed, up to the sidecar holding the tool call
    with the text already sent on; whole, up to the sidecar holding all of
    it."""
    body = json.dumps({"model": "claude-test", "stream": stream, "messages": [{"role": "user", "content": "clean up"}]})
    roxy.open(1, url=MESSAGES_URL, headers=[["x-claude-code-session-id", "s1"]])
    roxy.ws.body(1, body.encode())
    roxy.ws.control(1, "request_end")
    for _ in range(3):  # the forwarded request: head, body, request_end
        await roxy.ws.next_sent()
    if stream:
        roxy.ws.control(1, "response", status=200, headers=[["content-type", "text/event-stream"]])
        roxy.ws.body(1, MESSAGE_START, RESPONSE)
        assert (await roxy.ws.next_sent())["type"] == "response"
        assert await roxy.ws.next_sent() == FRAME + MESSAGE_START
        roxy.ws.body(1, TEXT + TOOL_CALL + ENDING, RESPONSE)
        assert await roxy.ws.next_sent() == FRAME + TEXT  # live, before the tool call is judged
    else:
        roxy.ws.control(1, "response", status=200, headers=[["content-type", "application/json"]])
        response = message([{"type": "text", "text": "Cleaning up."}, TOOL_USE], "tool_use")
        roxy.ws.body(1, json.dumps(response).encode(), RESPONSE)
    roxy.ws.control(1, "response_end")


async def card(ui: TestClient) -> dict[str, Any]:
    """The one tool call on the page, once it is there."""
    for _ in range(40):
        items = await (await ui.get("/pending")).json()
        if items:
            assert len(items) == 1
            return items[0]
        await asyncio.sleep(0.05)
    raise AssertionError("no tool call reached the page")


async def rest_of_stream(roxy: FakeRoxy) -> bytes:
    """Everything the sidecar sends on stream 1 up to its end, pings aside."""
    out = b""
    while True:
        m = await roxy.ws.next_sent()
        if isinstance(m, dict):
            assert m["type"] == "response_end"
            return out
        assert m[:5] == FRAME
        if m != FRAME + PING:
            out += m[5:]


async def test_a_tool_call_waits_on_the_page_and_goes_on_when_approved(demo: Any) -> None:
    sidecar, queue, ui = demo
    roxy = FakeRoxy(sidecar.handle)
    await model_call(roxy, stream=True)
    item = await card(ui)
    assert item["tool"] == "Bash"
    assert item["arguments"] == ARGUMENTS
    assert item["message"] == "Cleaning up."
    assert item["choices"] == ["approve", "reject"]
    with pytest.raises(TimeoutError):  # held: the agent has the text, not the tool call
        await roxy.ws.next_sent(timeout=0.2)
    assert (await ui.post(f"/pending/{item['id']}", json={"decision": "approve"})).status == 200
    assert await rest_of_stream(roxy) == TOOL_CALL + ENDING
    assert queue.pending() == []


async def test_a_denied_tool_call_is_replaced_by_the_reason(demo: Any) -> None:
    sidecar, _, ui = demo
    roxy = FakeRoxy(sidecar.handle)
    await model_call(roxy, stream=True)
    item = await card(ui)
    res = await ui.post(f"/pending/{item['id']}", json={"decision": "reject", "reason": "  not in this repo "})
    assert res.status == 200
    rest = (await rest_of_stream(roxy)).decode()  # the model's words have already gone
    assert "tool_use" not in rest
    assert '"index": 1, "content_block": {"type": "text"' in rest
    assert "A person reviewing this session denied the Bash tool call: not in this repo" in rest
    assert '"stop_reason": "end_turn"' in rest


async def test_a_denial_without_a_reason_still_says_who_denied_it(demo: Any) -> None:
    sidecar, _, ui = demo
    roxy = FakeRoxy(sidecar.handle)
    await model_call(roxy, stream=True)
    item = await card(ui)
    await ui.post(f"/pending/{item['id']}", json={"decision": "reject"})
    assert b"A person reviewing this session denied the Bash tool call." in await rest_of_stream(roxy)


async def test_pings_flow_while_the_person_decides(demo: Any, monkeypatch: Any) -> None:
    monkeypatch.setattr(sidecar_module, "PING_EVERY", 0.05)
    sidecar, _, ui = demo
    roxy = FakeRoxy(sidecar.handle)
    await model_call(roxy, stream=True)
    item = await card(ui)
    while not roxy.ws.sent.empty():
        roxy.ws.sent.get_nowait()
    for _ in range(3):  # three pings in a row, nothing else between them
        assert await roxy.ws.next_sent(timeout=1.0) == FRAME + PING
    await ui.post(f"/pending/{item['id']}", json={"decision": "approve"})
    assert await rest_of_stream(roxy) == TOOL_CALL + ENDING


async def test_a_whole_response_is_held_with_nothing_sent(demo: Any) -> None:
    sidecar, _, ui = demo
    roxy = FakeRoxy(sidecar.handle)
    await model_call(roxy, stream=False)
    item = await card(ui)
    with pytest.raises(TimeoutError):  # no head yet: roxy's first_byte_timeout is the bound
        await roxy.ws.next_sent(timeout=0.2)
    await ui.post(f"/pending/{item['id']}", json={"decision": "reject", "reason": "no"})
    head = await roxy.ws.next_sent()
    assert head["type"] == "response" and head["status"] == 200
    reply = json.loads((await roxy.ws.next_sent())[5:])
    assert [b["type"] for b in reply["content"]] == ["text", "text"]
    assert reply["content"][1]["text"] == "A person reviewing this session denied the Bash tool call: no"
    assert reply["stop_reason"] == "end_turn"


async def test_a_call_whose_exchange_went_away_leaves_the_page(demo: Any) -> None:
    sidecar, queue, ui = demo
    roxy = FakeRoxy(sidecar.handle)
    await model_call(roxy, stream=True)
    item = await card(ui)
    roxy.ws.control(1, "reset")
    await roxy.until_closed(1)
    assert queue.pending() == []
    assert (await ui.post(f"/pending/{item['id']}", json={"decision": "approve"})).status == 404
    ours = {t for t in stray_tasks(roxy.task) if "Sidecar" in t.get_coro().__qualname__}
    assert ours == set()


async def test_an_answer_the_person_was_not_offered_or_already_gave_is_refused(demo: Any) -> None:
    sidecar, _, ui = demo
    roxy = FakeRoxy(sidecar.handle)
    await model_call(roxy, stream=True)
    item = await card(ui)
    assert (await ui.post(f"/pending/{item['id']}", json={"decision": "terminate"})).status == 400
    assert (await ui.post(f"/pending/{item['id']}", json={"nope": 1})).status == 400
    assert len(await (await ui.get("/pending")).json()) == 1  # still waiting
    assert (await ui.post(f"/pending/{item['id']}", json={"decision": "approve"})).status == 200
    assert (await ui.post(f"/pending/{item['id']}", json={"decision": "approve"})).status == 404
    assert await rest_of_stream(roxy) == TOOL_CALL + ENDING
