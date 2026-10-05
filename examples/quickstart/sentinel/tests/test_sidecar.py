import json
from typing import Any

import pytest

from fake_roxy import FakeRoxy, stray_tasks
from inspect_log import InspectLog
from roxy_layer import RESPONSE
from sidecar import Sidecar, load_sentinel

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
