import asyncio
import json
from typing import Any

import pytest
from inspect_ai.event import SentinelEvent
from inspect_ai.tool import ToolCall
from inspect_sentinel import BeforeToolCall, Context, Decision, Protocol, protocol

from fake_roxy import FakeRoxy, stray_tasks
from inspect_log import InspectLog
from private_api import SSEDecoder
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
FRAME = b"\x00\x00\x00\x01\x01"  # stream 1, response direction


def text_block(index: int, text: str) -> bytes:
    return (
        sse("content_block_start", {"type": "content_block_start", "index": index, "content_block": {"type": "text", "text": ""}})
        + sse("content_block_delta", {"type": "content_block_delta", "index": index, "delta": {"type": "text_delta", "text": text}})
        + sse("content_block_stop", {"type": "content_block_stop", "index": index})
    )


def tool_use_start(index: int, id: str) -> bytes:
    block = {"type": "tool_use", "id": id, "name": "Bash", "input": {}}
    return sse("content_block_start", {"type": "content_block_start", "index": index, "content_block": block})


def tool_use(index: int, id: str, command: str) -> bytes:
    """A Bash tool call's events, its arguments in two deltas as the API
    sends them."""
    partial = json.dumps({"command": command})
    cut = len(partial) // 2
    return (
        tool_use_start(index, id)
        + sse("content_block_delta", {"type": "content_block_delta", "index": index, "delta": {"type": "input_json_delta", "partial_json": partial[:cut]}})
        + sse("content_block_delta", {"type": "content_block_delta", "index": index, "delta": {"type": "input_json_delta", "partial_json": partial[cut:]}})
        + sse("content_block_stop", {"type": "content_block_stop", "index": index})
    )


def ending(stop_reason: str = "tool_use") -> bytes:
    delta = {"type": "message_delta", "delta": {"stop_reason": stop_reason, "stop_sequence": None}, "usage": {"output_tokens": 7}}
    return sse("message_delta", delta) + REST


def events(raw: bytes) -> list[tuple[str, dict[str, Any]]]:
    return [(e.event or "", e.json()) for e in SSEDecoder().iter_bytes(iter([raw]))]


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


TEXT = text_block(0, "I will fetch that page for you.")
LS = tool_use(1, "toolu_1", "ls -la")
CURL = tool_use(1, "toolu_2", "curl x")
NOTE = "roxy's sentinel blocked a Bash tool call (denylist match: 'curl')."
TEXT_BLOCK_EVENTS = ["content_block_start", "content_block_delta", "content_block_stop"]


def gate_judge(sidecar: Sidecar, monkeypatch: Any) -> tuple[asyncio.Event, asyncio.Event]:
    """Holds the sentinel's verdict: the first event is set once it is
    judging, and it answers (pass) once the second is set."""
    judging, verdict = asyncio.Event(), asyncio.Event()

    async def slow_judge(*args: Any) -> None:
        judging.set()
        await verdict.wait()

    monkeypatch.setattr(sidecar, "judge_block", slow_judge)
    return judging, verdict


async def held_and_judging(sidecar: Sidecar, monkeypatch: Any) -> tuple[FakeRoxy, asyncio.Event]:
    """A streamed response with a tool call, ended, with the sidecar
    holding the tool call for the sentinel's verdict."""
    judging, verdict = gate_judge(sidecar, monkeypatch)
    roxy = FakeRoxy(sidecar.handle)
    await streamed_call(roxy)
    roxy.ws.body(1, TEXT + LS + ending(), RESPONSE)
    roxy.ws.control(1, "response_end")
    assert await roxy.ws.next_sent() == FRAME + TEXT
    await asyncio.wait_for(judging.wait(), 2.0)
    return roxy, verdict


async def test_pings_continue_while_the_sentinel_judges(sidecar: Sidecar, monkeypatch: Any) -> None:
    monkeypatch.setattr(sidecar_module, "PING_EVERY", 0.05)
    roxy, verdict = await held_and_judging(sidecar, monkeypatch)
    while not roxy.ws.sent.empty():
        roxy.ws.sent.get_nowait()
    for _ in range(3):  # three pings in a row, nothing else between them
        assert await roxy.ws.next_sent(timeout=1.0) == FRAME + PING
    verdict.set()
    assert await rest_of_stream(roxy) == LS + ending()


async def test_text_before_a_tool_call_streams_live(sidecar: Sidecar) -> None:
    """The text goes to the agent while the upstream is still sending; the
    tool call waits for its verdict and goes on as the upstream sent it."""
    roxy = FakeRoxy(sidecar.handle)
    await streamed_call(roxy)
    roxy.ws.body(1, TEXT, RESPONSE)
    assert await roxy.ws.next_sent() == FRAME + TEXT
    roxy.ws.body(1, tool_use_start(1, "toolu_1"), RESPONSE)
    with pytest.raises(TimeoutError):  # held: its arguments are not complete
        await roxy.ws.next_sent(timeout=0.2)
    roxy.ws.body(1, LS[len(tool_use_start(1, "toolu_1")) :], RESPONSE)
    assert await roxy.ws.next_sent() == FRAME + LS  # judged and released before the stream ends
    roxy.ws.body(1, ending(), RESPONSE)
    roxy.ws.control(1, "response_end")
    assert await rest_of_stream(roxy) == ending()


async def test_pings_continue_while_a_tool_call_is_held(sidecar: Sidecar, monkeypatch: Any) -> None:
    monkeypatch.setattr(sidecar_module, "PING_EVERY", 0.05)
    roxy = FakeRoxy(sidecar.handle)
    await streamed_call(roxy)
    roxy.ws.body(1, TEXT + tool_use_start(1, "toolu_1"), RESPONSE)
    assert await roxy.ws.next_sent() == FRAME + TEXT
    for _ in range(3):  # the upstream has gone quiet mid-call: pings, nothing else
        assert await roxy.ws.next_sent(timeout=1.0) == FRAME + PING


async def test_a_rejected_tool_call_is_replaced_by_the_note_and_the_turn_ends(sidecar: Sidecar) -> None:
    roxy = FakeRoxy(sidecar.handle)
    await streamed_call(roxy)
    roxy.ws.body(1, TEXT + CURL + ending(), RESPONSE)
    roxy.ws.control(1, "response_end")
    assert await roxy.ws.next_sent() == FRAME + TEXT
    rest = await rest_of_stream(roxy)
    assert b"tool_use" not in rest
    tail = events(rest)
    assert [e for e, _ in tail] == [*TEXT_BLOCK_EVENTS, "message_delta", "message_stop"]
    assert tail[0][1] == {"type": "content_block_start", "index": 1, "content_block": {"type": "text", "text": ""}}
    assert tail[1][1]["delta"] == {"type": "text_delta", "text": NOTE}
    assert tail[3][1]["delta"]["stop_reason"] == "end_turn"


async def test_text_after_a_rejected_tool_call_streams(sidecar: Sidecar) -> None:
    roxy = FakeRoxy(sidecar.handle)
    await streamed_call(roxy)
    after = text_block(1, "Let me try another way.")
    roxy.ws.body(1, CURL.replace(b'"index": 1', b'"index": 0') + after, RESPONSE)
    first = events((await roxy.ws.next_sent())[5:])
    assert [e for e, _ in first] == TEXT_BLOCK_EVENTS and first[1][1]["delta"]["text"] == NOTE
    assert await roxy.ws.next_sent() == FRAME + after  # before the stream has ended
    roxy.ws.body(1, ending(), RESPONSE)
    roxy.ws.control(1, "response_end")
    tail = events(await rest_of_stream(roxy))
    assert [e for e, _ in tail] == ["message_delta", "message_stop"]
    assert tail[0][1]["delta"]["stop_reason"] == "end_turn"


@protocol
def deny_curl_when_told(answer: asyncio.Event) -> Protocol:
    """deny_regex's verdict on `curl`, but only once `answer` is set."""

    async def decide(context: Context, step: BeforeToolCall) -> Decision:
        if "curl" not in step.call.arguments["command"]:
            return Decision.proceed()
        await answer.wait()
        return Decision.reject("curl", message=NOTE)

    return decide


async def test_tool_calls_are_judged_one_by_one(tmp_path: Any) -> None:
    """Two calls: the first goes to the agent as soon as it is approved,
    while the second still waits; the second is then replaced by the note
    and the message keeps its `tool_use` stop."""
    answer = asyncio.Event()
    sidecar = Sidecar(deny_curl_when_told(answer), InspectLog(str(tmp_path), "test"))
    roxy = FakeRoxy(sidecar.handle)
    await streamed_call(roxy)
    first = LS.replace(b'"index": 1', b'"index": 0')
    roxy.ws.body(1, first + CURL + ending(), RESPONSE)
    roxy.ws.control(1, "response_end")
    assert await roxy.ws.next_sent() == FRAME + first
    with pytest.raises(TimeoutError):  # the second call waits for its verdict
        await roxy.ws.next_sent(timeout=0.2)
    answer.set()
    tail = events(await rest_of_stream(roxy))
    assert [e for e, _ in tail] == [*TEXT_BLOCK_EVENTS, "message_delta", "message_stop"]
    assert tail[0][1]["index"] == 1 and tail[1][1]["delta"]["text"] == NOTE
    assert tail[3][1]["delta"]["stop_reason"] == "tool_use"


@protocol
def quote_paths() -> Protocol:
    """Rewrites a Bash command's `~` to `$HOME`."""

    async def decide(context: Context, step: BeforeToolCall) -> Decision:
        command = step.call.arguments["command"]
        if "~" not in command:
            return Decision.proceed()
        replacement = ToolCall(id=step.call.id, function=step.call.function, arguments={"command": command.replace("~", "$HOME")})
        return Decision(action="modify", modified=replacement)

    return decide


async def test_modify_rewrites_a_streamed_tool_call(tmp_path: Any) -> None:
    sidecar = Sidecar(quote_paths(), InspectLog(str(tmp_path), "test"))
    roxy = FakeRoxy(sidecar.handle)
    await streamed_call(roxy)
    roxy.ws.body(1, TEXT + tool_use(1, "toolu_1", "ls ~") + ending(), RESPONSE)
    roxy.ws.control(1, "response_end")
    assert await roxy.ws.next_sent() == FRAME + TEXT
    tail = events(await rest_of_stream(roxy))
    assert [e for e, _ in tail] == [*TEXT_BLOCK_EVENTS, "message_delta", "message_stop"]
    assert tail[0][1]["content_block"] == {"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": {}}
    assert tail[0][1]["index"] == 1
    assert tail[1][1]["delta"]["type"] == "input_json_delta"
    assert json.loads(tail[1][1]["delta"]["partial_json"]) == {"command": "ls $HOME"}
    assert tail[3][1]["delta"]["stop_reason"] == "tool_use"


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
    assert denied["type"] == "response" and denied["status"] == 403
    body = await roxy.ws.next_sent()
    assert body[5:].startswith(b"the sentinel could not read this model exchange")


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
