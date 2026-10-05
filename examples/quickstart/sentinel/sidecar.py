"""inspect_sentinel at the network boundary: a roxy service layer.

Every exchange streams through this sidecar (roxy.layer.v3). For an
Anthropic Messages call (`POST .../v1/messages`) it forwards the request,
reads the model's response, turns each tool call in it into an
inspect_sentinel `BeforeToolCall` step, and runs the configured sentinel on
it before the agent sees the response:

    continue   the response goes to the agent unchanged
    modify     the tool call's arguments are replaced (non-streamed responses)
    reject     the response is replaced by an assistant message that keeps
               the model's text, drops its tool calls and says what was
               blocked, so the agent's turn ends normally
    terminate  as reject; the sidecar cannot end the agent itself
    escalate   unresolved at the root: treated as reject (fail closed)

Everything else (other requests, and every non-200 answer) passes through
untouched, for roxy's rules to decide. A streamed response starts at once
(its head and `message_start`, then pings) while the rest is held and
judged, so the agent's first-byte and idle deadlines are met.

Each conversation, its model calls and the sentinel's reports are written
as an Inspect eval log for `inspect view` (inspect_log.py).

Configuration (environment):

    SENTINEL                 module:attribute of the sentinel (default policies:deny_regex)
    SENTINEL_DENY            the regex deny_regex uses (see policies.py)
    SENTINEL_MONITOR_MODEL   the model `context.host.generate` uses, for sentinels
                             that ask one (e.g. anthropic/claude-haiku-4-5)
    SENTINEL_LISTEN          host:port to listen on (default 127.0.0.1:9000)
    SENTINEL_LOG_DIR         where the Inspect log goes (default /logs)
    SENTINEL_TASK            the agent's name, for `context.task` and the log
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import importlib
import json
import logging
import os
import time
from collections import OrderedDict
from collections.abc import AsyncIterator, Sequence
from typing import Any

import httpx2
from anthropic._models import construct_type
from anthropic._streaming import SSEDecoder
from anthropic.lib.streaming._beta_messages import accumulate_event
from anthropic.types.beta import BetaMessage, BetaRawMessageStreamEvent
from inspect_ai.model import (
    ChatMessage,
    ChatMessageAssistant,
    ContentText,
    GenerateConfig,
    Model,
    ModelOutput,
    ModelUsage,
    get_model,
    messages_from_anthropic,
    model_output_from_anthropic,
)
from inspect_ai.tool import ToolCall, ToolCallView, ToolInfo
from inspect_ai.util import Store
from inspect_sentinel import BeforeToolCall, Context, Decision, HumanAnswer, Step

# The host contract inspect_ai itself uses to run a sentinel, and the
# converters its agent bridge uses to answer an agent's Messages call.
from inspect_ai.agent._bridge.anthropic_api_impl import (
    anthropic_stop_reason,
    anthropic_usage,
    assistant_message_blocks,
)
from inspect_sentinel._integration import HostContext, resolve_sentinel, run_sentinel

from inspect_log import InspectLog, InspectRecorder
from roxy_layer import Exchange, Request, Response, serve

log = logging.getLogger("sentinel-sidecar")

MAX_CONVERSATIONS = 10_000

# While a streamed response is held for judging, a ping this often keeps
# the agent's idle watchdogs from giving up on it.
PING_EVERY = 10.0
PING = b'event: ping\ndata: {"type": "ping"}\n\n'


# ----- the host side of inspect_sentinel --------------------------------------


class SidecarHost:
    """What a monitor or protocol may do to the outside world, here."""

    async def generate(
        self,
        input: str | list[ChatMessage],
        *,
        model: str | Model | None = None,
        role: str | None = None,
        tools: list[ToolInfo] | None = None,
        config: GenerateConfig | None = None,
    ) -> ModelOutput:
        # A configured monitor model wins, as a configured role does in an
        # eval. The call goes straight to the provider, never through roxy,
        # so a monitor cannot recurse through the sentinel it runs in.
        name = os.environ.get("SENTINEL_MONITOR_MODEL") or model
        if name is None:
            raise RuntimeError(
                "this sentinel calls a model: set SENTINEL_MONITOR_MODEL "
                f"(asked for role {role or 'monitor'!r})"
            )
        return await get_model(name).generate(
            input, tools=tools or [], config=config or GenerateConfig()
        )

    async def ask_human(self, step: Step, choices: Sequence[str]) -> HumanAnswer:
        # Nobody is waiting at a proxy; a review queue would go here.
        raise RuntimeError("the sidecar has no person to ask")


class Stores:
    """One store per conversation, least recently used dropped first. A
    miss is a fresh store: a monitor degrades to no history."""

    def __init__(self) -> None:
        self._stores: OrderedDict[str, Store] = OrderedDict()

    def get(self, conversation: str) -> Store:
        store = self._stores.pop(conversation, None) or Store()
        self._stores[conversation] = store
        while len(self._stores) > MAX_CONVERSATIONS:
            self._stores.popitem(last=False)
        return store


# ----- the Anthropic Messages wire format ---------------------------------------


def _system_text(system: Any) -> str | None:
    if system is None or isinstance(system, str):
        return system
    return "\n".join(b.get("text", "") for b in system if isinstance(b, dict))


# The stream events the SDK's own stream accumulates; `ping` is skipped and
# `error` raises, as the SDK's stream does.
STREAM_EVENTS = {
    "message_start",
    "message_delta",
    "message_stop",
    "content_block_start",
    "content_block_delta",
    "content_block_stop",
}


def message_from_sse(raw: bytes) -> dict[str, Any]:
    """Rebuilds a `Message` from its event stream with the Anthropic SDK's
    accumulator (beta types: Claude Code calls the beta endpoint)."""
    snapshot = None
    json_bufs: dict[int, bytes] = {}
    for sse in SSEDecoder().iter_bytes(iter([raw])):
        if sse.event == "error":
            raise ValueError(f"error in the stream: {sse.data}")
        if sse.event not in STREAM_EVENTS:
            continue
        event = construct_type(type_=BetaRawMessageStreamEvent, value=sse.json())
        snapshot = accumulate_event(
            event=event,
            current_snapshot=snapshot,
            json_bufs=json_bufs,
            request_headers=httpx2.Headers(),
        )
    if snapshot is None:
        raise ValueError("no message in the stream")
    return snapshot.model_dump(mode="json")


async def explanation(response: dict[str, Any], output: ModelOutput, note: str) -> dict[str, Any]:
    """The reply to a refused response: the model's text, without its tool
    calls or thinking, then what was blocked. Built as an inspect message and
    converted as inspect's agent bridge answers an agent; its `end_turn`
    hands the turn back to the person, as an ordinary answer would."""
    said = output.message.text
    message = ChatMessageAssistant(
        content=[*([ContentText(text=said)] if said else []), ContentText(text=note)]
    )
    reply = BetaMessage.model_construct(
        id=response.get("id"),
        type="message",
        role="assistant",
        model=response.get("model"),
        content=await assistant_message_blocks(message, beta=True),
        stop_reason=anthropic_stop_reason("stop"),
        stop_sequence=None,
        usage=anthropic_usage(output.usage or ModelUsage(), beta=True),
    )
    return reply.model_dump(mode="json")


def anthropic_to_sse(message: dict[str, Any], *, start: bool = True) -> bytes:
    """The event stream for a whole `Message` (text blocks only), without
    its `message_start` event if that was already sent."""
    events: list[tuple[str, dict[str, Any]]] = []
    if start:
        head = {**message, "content": [], "stop_reason": None, "stop_sequence": None}
        events.append(("message_start", {"type": "message_start", "message": head}))
    for i, block in enumerate(message["content"]):
        events += [
            (
                "content_block_start",
                {"type": "content_block_start", "index": i, "content_block": {"type": "text", "text": ""}},
            ),
            (
                "content_block_delta",
                {"type": "content_block_delta", "index": i, "delta": {"type": "text_delta", "text": block["text"]}},
            ),
            ("content_block_stop", {"type": "content_block_stop", "index": i}),
        ]
    events += [
        (
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": message["stop_reason"], "stop_sequence": None},
                "usage": {"output_tokens": message.get("usage", {}).get("output_tokens", 0)},
            },
        ),
        ("message_stop", {"type": "message_stop"}),
    ]
    return "".join(f"event: {e}\ndata: {json.dumps(d)}\n\n" for e, d in events).encode()


class Call:
    """One Messages exchange, as inspect_ai types."""

    def __init__(self, request: dict[str, Any], response: dict[str, Any], streamed: bool) -> None:
        self.request = request
        self.response = response
        self.streamed = streamed

    async def input(self) -> list[ChatMessage]:
        return await messages_from_anthropic(
            self.request.get("messages", []), _system_text(self.request.get("system"))
        )

    async def output(self) -> ModelOutput:
        return await model_output_from_anthropic(self.response)

    def conversation(self) -> str:
        # The conversation's stable head (system prompt, first user turn),
        # so the agent cannot rotate it.
        messages = self.request.get("messages", [])
        first_user = next((m for m in messages if m.get("role") == "user"), None)
        head = json.dumps([self.request.get("system"), first_user], sort_keys=True)
        return hashlib.sha256(head.encode()).hexdigest()[:24]

    def modify(self, call: ToolCall, replacement: ToolCall) -> None:
        """Replaces a tool call's arguments in the response."""
        for block in self.response.get("content", []):
            if block.get("type") == "tool_use" and block.get("id") == call.id:
                block["input"] = replacement.arguments


@dataclasses.dataclass
class Refusal:
    """The agent does not get this response."""

    message: str
    call: Call | None = None
    output: ModelOutput | None = None


def is_model_call(req: Request) -> bool:
    return req.method == "POST" and req.url.split("?", 1)[0].endswith("/v1/messages")


def with_length(res: Response, length: int) -> Response:
    headers = [(n, v) for n, v in res.headers if n.lower() != "content-length"]
    return Response(res.status, [*headers, ("content-length", str(length))])


# ----- the layer --------------------------------------------------------------


class Sidecar:
    def __init__(self, sentinel: Any, inspect_log: InspectLog) -> None:
        self.root = resolve_sentinel(sentinel)
        self.host = SidecarHost()
        self.stores = Stores()
        self.inspect_log = inspect_log

    async def handle(self, ex: Exchange) -> None:
        if not is_model_call(ex.request):
            # Not a model call: stream it through untouched.
            res = await ex.forward(ex.request, ex.body())
            await ex.respond(res, ex.response_body())
            return
        body = await ex.read_body()
        res = await ex.forward(ex.request, body)
        streamed = (res.header("content-type") or "").startswith("text/event-stream")
        if streamed and res.status == 200 and not ex.observing:
            head = [(n, v) for n, v in res.headers if n.lower() != "content-length"]
            await ex.respond(Response(res.status, head), self.judged_stream(ex, body, res))
            return
        raw = await ex.read_response_body()
        if res.status != 200 or ex.observing:
            await ex.respond(res, raw)
            if ex.observing and res.status == 200:
                await self.judge(ex, body, res, raw)
            return
        verdict = await self.judge(ex, body, res, raw)
        if verdict is None:
            await ex.respond(res, raw)
        elif isinstance(verdict, bytes):
            await ex.respond(with_length(res, len(verdict)), verdict)
        elif verdict.call and verdict.output:
            reply = await explanation(verdict.call.response, verdict.output, verdict.message)
            out = json.dumps(reply).encode()
            await ex.respond(with_length(res, len(out)), out)
        else:
            await ex.deny(403, verdict.message)

    async def judged_stream(self, ex: Exchange, body: bytes, res: Response) -> AsyncIterator[bytes]:
        """A streamed response, judged before the agent sees any content:
        its `message_start` passes at once, pings follow while the rest is
        held, then the rest or, if refused, the explanation."""
        chunks: list[bytes] = []

        async def read() -> None:
            async for chunk in ex.response_body():
                chunks.append(chunk)

        reader = asyncio.create_task(read())
        sent = 0
        last = time.monotonic()
        while True:
            done, _ = await asyncio.wait({reader}, timeout=0.5)
            if not sent:
                raw = b"".join(chunks)
                end = raw.find(b"\n\n")
                if end != -1:
                    if b"message_start" in raw[:end]:
                        sent = end + 2
                        yield raw[:sent]
                    else:
                        sent = -1  # not the shape we know: hold everything
            if done:
                break
            if sent > 0 and time.monotonic() - last >= PING_EVERY:
                last = time.monotonic()
                yield PING
        reader.result()
        raw = b"".join(chunks)
        sent = max(sent, 0)
        verdict = await self.judge(ex, body, res, raw)
        if verdict is None or isinstance(verdict, bytes):
            # Streamed responses are never modified (see judge).
            yield raw[sent:]
        elif verdict.call and verdict.output:
            reply = await explanation(verdict.call.response, verdict.output, verdict.message)
            yield anthropic_to_sse(reply, start=not sent)
        else:
            error = {"type": "error", "error": {"type": "api_error", "message": verdict.message}}
            yield f"event: error\ndata: {json.dumps(error)}\n\n".encode()

    async def judge(self, ex: Exchange, body: bytes, res: Response, raw: bytes) -> None | bytes | Refusal:
        """None to pass the response on, new bytes for a modified response,
        or a refusal."""
        streamed = (res.header("content-type") or "").startswith("text/event-stream")
        try:
            request = json.loads(body)
            response = message_from_sse(raw) if streamed else json.loads(raw)
        except (ValueError, KeyError, IndexError) as e:
            log.warning("unreadable model exchange: %s", e)
            return Refusal("the sentinel could not read this model exchange")
        call = Call(request, response, streamed)
        output = await call.output()
        try:
            input = await call.input()
        except Exception as e:  # noqa: BLE001
            # The history is context for the sentinel, not the thing it
            # judges: a conversation the converter cannot read still gets
            # its tool calls judged, with no history.
            log.warning("unreadable conversation history: %s", e)
            input = []
        conversation = call.conversation()
        model = f"anthropic/{response.get('model', 'unknown')}"
        self.inspect_log.model_call(conversation, ex.flow.get("flow"), model, input, output)
        tool_calls = output.message.tool_calls or []
        if not tool_calls:
            return None
        first_user = next((m for m in input if m.role == "user"), None)
        context = Context(
            task=os.environ.get("SENTINEL_TASK", "roxy"),
            task_description=None,
            sample_id=None,
            epoch=None,
            sample_description=None,
            sample_input=first_user.text if first_user else "",
            metadata={"roxy": ex.flow, "url": ex.request.url},
            path="",
            host=self.host,
        )
        host_context = HostContext(
            context=context,
            recorder=InspectRecorder(self.inspect_log),
            store=self.stores.get(conversation),
        )
        modified = False
        for tc in tool_calls:
            step = BeforeToolCall(
                conversation=conversation,
                message=output.message.text,
                call=tc,
                view=ToolCallView(),
                input=input,
                history=input,
            )
            decision: Decision | None = await run_sentinel(self.root, host_context, step)
            action = decision.action if decision else "continue"
            if action == "continue":
                continue
            if action == "modify" and decision and decision.modified and not streamed:
                call.modify(tc, decision.modified)
                modified = True
                continue
            # reject, terminate, an unresolved escalate, or a modify that
            # cannot be applied: the agent does not get this response.
            log.info("%s on %s: %s", action, tc.function, decision and decision.explanation)
            return Refusal(
                (decision and decision.message) or f"tool call {tc.function} refused ({action})",
                call,
                output,
            )
        return json.dumps(call.response).encode() if modified else None


def load_sentinel(spec: str) -> Any:
    module, _, attr = spec.partition(":")
    obj = getattr(importlib.import_module(module), attr)
    return obj() if callable(obj) else obj


async def main() -> None:
    inspect_log = InspectLog(
        os.environ.get("SENTINEL_LOG_DIR", "/logs"), os.environ.get("SENTINEL_TASK", "roxy")
    )
    sidecar = Sidecar(load_sentinel(os.environ.get("SENTINEL", "policies:deny_regex")), inspect_log)
    writer = asyncio.create_task(inspect_log.run())  # noqa: F841 (held for its lifetime)
    log.info("writing an Inspect log to %s", inspect_log.path)
    host, _, port = os.environ.get("SENTINEL_LISTEN", "127.0.0.1:9000").rpartition(":")
    async with serve(sidecar.handle, host, int(port)) as server:
        log.info("sentinel sidecar listening on %s:%s", host, port)
        await server.serve_forever()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
