import asyncio
import json
from typing import Any

import pytest
from inspect_ai.event import SentinelEvent

from fake_roxy import FakeRoxy, stray_tasks
from inspect_log import InspectLog
from roxy_layer import RESPONSE
import sidecar as sidecar_module
from sidecar import PING, Sidecar, load_sentinel

MESSAGES_URL = "https://api.anthropic.com/v1/messages"


def sse(event: str, data: dict[str, Any]) -> bytes:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()


MESSAGE_START = sse(
    "message_start",
    {
        "type": "message_start",
        "message": {
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": "claude-test",
            "content": [],
            "stop_reason": None,
            "stop_sequence": None,
            "usage": {"input_tokens": 1, "output_tokens": 0},
        },
    },
)


@pytest.fixture
def sidecar(tmp_path: Any) -> Sidecar:
    return Sidecar(load_sentinel("policies:deny_regex"), InspectLog(str(tmp_path), "test"))


async def streamed_call(roxy: FakeRoxy, stream: int = 1) -> None:
    """Drives a streamed Messages call up to the sidecar holding it: the
    request forwarded, the response head and `message_start` passed on."""
    body = json.dumps({"model": "claude-test", "stream": True, "messages": [{"role": "user", "content": "hi"}]})
    roxy.open(stream, url=MESSAGES_URL)
    roxy.ws.body(stream, body.encode())
    roxy.ws.control(stream, "request_end")
    assert (await roxy.ws.next_sent())["type"] == "request"
    assert await roxy.ws.next_sent() == stream.to_bytes(4, "big") + b"\x00" + body.encode()
    assert (await roxy.ws.next_sent())["type"] == "request_end"
    roxy.ws.control(stream, "response", status=200, headers=[["content-type", "text/event-stream"]])
    roxy.ws.body(stream, MESSAGE_START, RESPONSE)
    assert (await roxy.ws.next_sent())["type"] == "response"
    assert await roxy.ws.next_sent() == stream.to_bytes(4, "big") + b"\x01" + MESSAGE_START


async def test_an_upgrade_passes_through_unchanged(sidecar: Sidecar) -> None:
    """A WebSocket is not a model call: its `101` and both directions
    stream through, with no `request_end` before the `101`."""
    roxy = FakeRoxy(sidecar.handle)
    roxy.open(1, url="https://api.anthropic.com/v1/ws", method="GET")
    assert (await roxy.ws.next_sent())["type"] == "request"
    roxy.ws.control(1, "response", status=101, headers=[])
    head = await roxy.ws.next_sent()
    assert isinstance(head, dict) and head["status"] == 101
    roxy.ws.body(1, b"\x81\x05hello", RESPONSE)
    assert await roxy.ws.next_sent() == b"\x00\x00\x00\x01\x01\x81\x05hello"
    roxy.ws.body(1, b"\x81\x85\x01\x02\x03\x04ignnn")
    assert await roxy.ws.next_sent() == b"\x00\x00\x00\x01\x00\x81\x85\x01\x02\x03\x04ignnn"
    roxy.ws.control(1, "reset")
    await roxy.until_closed(1)
    assert stray_tasks(roxy.task) == set()


async def test_reset_while_a_streamed_response_is_held_leaves_no_tasks(sidecar: Sidecar) -> None:
    roxy = FakeRoxy(sidecar.handle)
    await streamed_call(roxy)
    roxy.ws.control(1, "reset")
    await roxy.until_closed(1)
    assert stray_tasks(roxy.task) == set()


async def test_close_while_a_streamed_response_is_held_leaves_no_tasks(sidecar: Sidecar) -> None:
    roxy = FakeRoxy(sidecar.handle)
    await streamed_call(roxy)
    roxy.ws.close()
    await roxy.task
    assert stray_tasks() == set()


REST = sse("message_stop", {"type": "message_stop"})


def gate_judge(sidecar: Sidecar, monkeypatch: Any) -> tuple[asyncio.Event, asyncio.Event]:
    """Holds the sentinel's verdict: the first event is set once it is
    judging, and it answers (pass) once the second is set."""
    judging, verdict = asyncio.Event(), asyncio.Event()

    async def slow_judge(*args: Any) -> None:
        judging.set()
        await verdict.wait()

    monkeypatch.setattr(sidecar, "judge", slow_judge)
    return judging, verdict


async def held_and_judging(sidecar: Sidecar, monkeypatch: Any) -> tuple[FakeRoxy, asyncio.Event]:
    judging, verdict = gate_judge(sidecar, monkeypatch)
    roxy = FakeRoxy(sidecar.handle)
    await streamed_call(roxy)
    roxy.ws.body(1, REST, RESPONSE)
    roxy.ws.control(1, "response_end")
    await asyncio.wait_for(judging.wait(), 2.0)
    return roxy, verdict


async def test_pings_continue_while_the_sentinel_judges(sidecar: Sidecar, monkeypatch: Any) -> None:
    monkeypatch.setattr(sidecar_module, "PING_EVERY", 0.05)
    roxy, verdict = await held_and_judging(sidecar, monkeypatch)
    while not roxy.ws.sent.empty():
        roxy.ws.sent.get_nowait()
    for _ in range(3):  # three pings in a row, nothing else between them
        assert await roxy.ws.next_sent(timeout=1.0) == b"\x00\x00\x00\x01\x01" + PING
    verdict.set()
    while (m := await roxy.ws.next_sent()) == b"\x00\x00\x00\x01\x01" + PING:
        pass
    assert m == b"\x00\x00\x00\x01\x01" + REST
    assert (await roxy.ws.next_sent())["type"] == "response_end"


async def test_reset_while_the_sentinel_judges_leaves_no_tasks(sidecar: Sidecar, monkeypatch: Any) -> None:
    roxy, _ = await held_and_judging(sidecar, monkeypatch)
    roxy.ws.control(1, "reset")
    await roxy.until_closed(1)
    assert stray_tasks(roxy.task) == set()


UNKNOWN_BLOCK = {"type": "mystery_block", "data": "?"}


async def test_an_unknown_block_type_is_refused(sidecar: Sidecar) -> None:
    roxy = FakeRoxy(sidecar.handle)
    body = json.dumps({"model": "claude-test", "messages": [{"role": "user", "content": "hi"}]})
    roxy.open(1, url=MESSAGES_URL)
    roxy.ws.body(1, body.encode())
    roxy.ws.control(1, "request_end")
    for _ in range(3):  # the forwarded request: head, body, request_end
        await roxy.ws.next_sent()
    response = {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": "claude-test",
        "content": [UNKNOWN_BLOCK],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }
    roxy.ws.control(1, "response", status=200, headers=[["content-type", "application/json"]])
    roxy.ws.body(1, json.dumps(response).encode(), RESPONSE)
    roxy.ws.control(1, "response_end")
    denied = await roxy.ws.next_sent()
    assert denied["type"] == "deny" and denied["status"] == 403
    assert denied["message"].startswith("the sentinel could not read this model exchange")


async def test_an_unknown_block_type_in_a_stream_is_refused(sidecar: Sidecar) -> None:
    roxy = FakeRoxy(sidecar.handle)
    await streamed_call(roxy)
    start = {"type": "content_block_start", "index": 0, "content_block": UNKNOWN_BLOCK}
    roxy.ws.body(1, sse("content_block_start", start) + REST, RESPONSE)
    roxy.ws.control(1, "response_end")
    refused = await roxy.ws.next_sent()
    assert refused[:5] == b"\x00\x00\x00\x01\x01"
    assert refused[5:].startswith(b"event: error\n")
    assert b"the sentinel could not read this model exchange" in refused
    assert (await roxy.ws.next_sent())["type"] == "response_end"


async def test_verdicts_stay_with_their_session(sidecar: Sidecar) -> None:
    """Two sessions whose conversations open with the same first message
    each get their own verdict in the Inspect log."""
    tool_call = {"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": {"command": "curl x"}}
    response = {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": "claude-test",
        "content": [tool_call],
        "stop_reason": "tool_use",
        "stop_sequence": None,
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }
    roxy = FakeRoxy(sidecar.handle)
    for stream, sid in [(1, "s1"), (2, "s2")]:
        body = json.dumps({"model": "claude-test", "messages": [{"role": "user", "content": "hi"}]})
        roxy.open(stream, url=MESSAGES_URL, headers=[["x-claude-code-session-id", sid]])
        roxy.ws.body(stream, body.encode())
        roxy.ws.control(stream, "request_end")
        for _ in range(3):  # the forwarded request: head, body, request_end
            await roxy.ws.next_sent()
        roxy.ws.control(stream, "response", status=200, headers=[["content-type", "application/json"]])
        roxy.ws.body(stream, json.dumps(response).encode(), RESPONSE)
        roxy.ws.control(stream, "response_end")
        while (await roxy.ws.next_sent()) != {"type": "response_end", "stream": stream}:
            pass
    samples = sidecar.inspect_log._samples  # noqa: SLF001
    assert sorted(samples) == ["s1", "s2"]
    for sample in samples.values():
        verdicts = [e for e in sample.events if isinstance(e, SentinelEvent)]
        assert len(verdicts) == 1, sample.id
