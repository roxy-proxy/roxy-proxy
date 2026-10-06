"""A scripted stand-in for the Anthropic Messages API.

`POST /v1/messages` answers from `responses.json`, one entry per call in
order, round and round, so a run is the same every time and the quota
board's numbers can be predicted. Streamed and whole responses both carry
`usage` as the real API does: `input_tokens` is estimated from the request,
`output_tokens` is the entry's. The request must carry the `x-api-key` that
MODEL_API_KEY names; roxy injects it, so a client that bypassed roxy is
refused.

    MODEL_API_KEY     the key to require (default fake-model-key)
    STREAM_DELAY_MS   pause between streamed deltas (default 40)
"""

from __future__ import annotations

import itertools
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any

from common import JsonHandler, serve

API_KEY = os.environ.get("MODEL_API_KEY", "fake-model-key")
DELAY = int(os.environ.get("STREAM_DELAY_MS", "40")) / 1000
RESPONSES: list[dict[str, Any]] = json.loads(Path(__file__).with_name("responses.json").read_text())

_lock = threading.Lock()
_turn = itertools.cycle(range(len(RESPONSES)))
_ids = itertools.count(1)


def next_response() -> tuple[int, dict[str, Any]]:
    with _lock:
        return next(_ids), RESPONSES[next(_turn)]


def estimate_input_tokens(request: dict[str, Any]) -> int:
    """About four characters a token, plus a little per message, over the
    messages, system prompt and tool definitions."""
    text = json.dumps(request.get("messages", [])) + json.dumps(request.get("system", ""))
    text += json.dumps(request.get("tools", []))
    return len(text) // 4 + 3 * len(request.get("messages", []))


def sse(event: str, data: dict[str, Any]) -> bytes:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()


def words(text: str, per_chunk: int = 3) -> list[str]:
    parts = text.split(" ")
    return [" ".join(parts[i : i + per_chunk]) + (" " if i + per_chunk < len(parts) else "") for i in range(0, len(parts), per_chunk)]


class Handler(JsonHandler):
    log = logging.getLogger("fake-model")

    def do_POST_v1_messages(self) -> None:  # noqa: N802
        if self.headers.get("x-api-key") != API_KEY:
            self.log.info("refused: wrong or missing x-api-key")
            self.send_error_json(401, "authentication_error", "invalid x-api-key")
            return
        request = self.read_json()
        n, entry = next_response()
        message = {
            "id": f"msg_fake_{n:06d}",
            "type": "message",
            "role": "assistant",
            "model": request.get("model", "fake-model"),
            "content": entry["content"],
            "stop_reason": entry.get("stop_reason", "end_turn"),
            "stop_sequence": None,
            "usage": {
                "input_tokens": estimate_input_tokens(request),
                "output_tokens": entry["output_tokens"],
            },
        }
        self.log.info(
            "turn %d: %d content blocks, %d in / %d out tokens, %s",
            n, len(entry["content"]), message["usage"]["input_tokens"],
            entry["output_tokens"], "streamed" if request.get("stream") else "whole",
        )
        if request.get("stream"):
            self.stream(message)
        else:
            self.send_json(200, message)

    def stream(self, message: dict[str, Any]) -> None:
        self.send_response(200)
        self.send_header("content-type", "text/event-stream; charset=utf-8")
        self.send_header("cache-control", "no-cache")
        self.send_header("transfer-encoding", "chunked")
        self.end_headers()

        def emit(event: str, data: dict[str, Any]) -> None:
            chunk = sse(event, data)
            self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
            self.wfile.flush()
            time.sleep(DELAY)

        head = dict(message, content=[], stop_reason=None)
        head["usage"] = {"input_tokens": message["usage"]["input_tokens"], "output_tokens": 1}
        emit("message_start", {"type": "message_start", "message": head})
        for i, block in enumerate(message["content"]):
            if block["type"] == "text":
                emit("content_block_start", {"type": "content_block_start", "index": i, "content_block": {"type": "text", "text": ""}})
                for piece in words(block["text"]):
                    emit("content_block_delta", {"type": "content_block_delta", "index": i, "delta": {"type": "text_delta", "text": piece}})
            else:
                start = {"type": "tool_use", "id": block["id"], "name": block["name"], "input": {}}
                emit("content_block_start", {"type": "content_block_start", "index": i, "content_block": start})
                partial = json.dumps(block["input"])
                for j in range(0, len(partial), 12):
                    emit("content_block_delta", {"type": "content_block_delta", "index": i, "delta": {"type": "input_json_delta", "partial_json": partial[j : j + 12]}})
            emit("content_block_stop", {"type": "content_block_stop", "index": i})
        emit("message_delta", {
            "type": "message_delta",
            "delta": {"stop_reason": message["stop_reason"], "stop_sequence": None},
            "usage": {"output_tokens": message["usage"]["output_tokens"]},
        })
        emit("message_stop", {"type": "message_stop"})
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()


if __name__ == "__main__":
    Handler.log.info("%d scripted responses", len(RESPONSES))
    serve(Handler, 8080)
