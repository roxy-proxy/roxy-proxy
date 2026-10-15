"""The review queue: the person's side of `Host.ask_human`, and the page
they answer from.

A sentinel that asks a person hands `ask_human` the step. Here the step
becomes a card on the review page, and the call waits on a future until a
button is pressed. The answer is a `HumanAnswer`: `approve` lets the tool
call through; `reject` (the Deny button) carries the reason the agent will
read. A step whose exchange goes away while the person is deciding (the
agent gave up, roxy reset the stream) leaves the queue with no answer.

The page is one HTML file (review.html) that polls `GET /pending` and
answers with `POST /pending/{id}`. Nothing is kept after an answer: the
Inspect log the sidecar writes is the record.
"""

from __future__ import annotations

import asyncio
import dataclasses
import itertools
import pathlib
import time
from collections.abc import Sequence
from typing import Any

from aiohttp import web
from inspect_ai.model import ChatMessage, GenerateConfig, Model, ModelOutput
from inspect_ai.tool import ToolInfo
from inspect_sentinel import BeforeToolCall, HumanAnswer, Step

PAGE = pathlib.Path(__file__).with_name("review.html")


@dataclasses.dataclass
class Pending:
    """One tool call waiting for a person."""

    id: str
    conversation: str
    tool: str
    arguments: dict[str, Any]
    message: str
    choices: tuple[str, ...]
    asked: float = dataclasses.field(default_factory=time.monotonic)
    answer: asyncio.Future[HumanAnswer] = dataclasses.field(
        default_factory=lambda: asyncio.get_running_loop().create_future()
    )

    def describe(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "conversation": self.conversation,
            "tool": self.tool,
            "arguments": self.arguments,
            "message": self.message,
            "choices": list(self.choices),
            "age_seconds": round(time.monotonic() - self.asked),
        }


class ReviewQueue:
    """The host for a sentinel that asks a person: every question becomes a
    card, and stays one until it is answered or its exchange goes away."""

    def __init__(self) -> None:
        self._pending: dict[str, Pending] = {}
        self._ids = itertools.count(1)

    def pending(self) -> list[Pending]:
        return list(self._pending.values())

    async def ask_human(self, step: Step, choices: Sequence[str]) -> HumanAnswer:
        if not isinstance(step, BeforeToolCall):
            raise RuntimeError("the review page shows tool calls before they run; it cannot show this step")
        item = Pending(
            id=str(next(self._ids)),
            conversation=step.conversation,
            tool=step.call.function,
            arguments=step.call.arguments,
            message=step.message,
            choices=tuple(choices),
        )
        self._pending[item.id] = item
        try:
            return await item.answer
        finally:
            # Answered, or cancelled with the exchange it belonged to.
            self._pending.pop(item.id, None)

    def answer(self, id: str, decision: str, reason: str | None) -> None:
        """Resolves a pending call. `KeyError` if it is not waiting (already
        answered, or gone with its exchange); `ValueError` for a decision
        the person was not offered."""
        item = self._pending[id]
        if decision not in item.choices:
            raise ValueError(f"{decision!r} is not one of {list(item.choices)}")
        reason = (reason or "").strip() or None
        if decision == "reject":
            # What the agent reads in place of its tool call.
            text = f"A person reviewing this session denied the {item.tool} tool call"
            reason = f"{text}: {reason}" if reason else f"{text}."
        item.answer.set_result(HumanAnswer(decision=decision, reason=reason))

    async def generate(
        self,
        input: str | list[ChatMessage],
        *,
        model: str | Model | None = None,
        role: str | None = None,
        tools: list[ToolInfo] | None = None,
        config: GenerateConfig | None = None,
    ) -> ModelOutput:
        raise RuntimeError("this demo asks a person, not a model")


def app(queue: ReviewQueue) -> web.Application:
    """The review page and its two endpoints."""

    async def page(_: web.Request) -> web.Response:
        return web.Response(text=PAGE.read_text(), content_type="text/html")

    async def pending(_: web.Request) -> web.Response:
        return web.json_response([item.describe() for item in queue.pending()])

    async def answer(request: web.Request) -> web.Response:
        try:
            body = await request.json()
            decision, reason = body["decision"], body.get("reason")
        except (ValueError, KeyError, TypeError):
            raise web.HTTPBadRequest(text="expected JSON with a decision") from None
        try:
            queue.answer(request.match_info["id"], decision, reason)
        except KeyError:
            raise web.HTTPNotFound(text="that call is no longer waiting") from None
        except ValueError as e:
            raise web.HTTPBadRequest(text=str(e)) from None
        return web.json_response({"ok": True})

    application = web.Application()
    application.add_routes(
        [web.get("/", page), web.get("/pending", pending), web.post("/pending/{id}", answer)]
    )
    return application


async def serve_ui(queue: ReviewQueue, host: str, port: int) -> web.AppRunner:
    """Serves the page on the running loop; `await runner.cleanup()` stops it."""
    runner = web.AppRunner(app(queue))
    await runner.setup()
    await web.TCPSite(runner, host, port).start()
    return runner
