"""inspect_sentinel at the network boundary: a roxy service layer.

Every exchange streams through this sidecar (roxy.layer.v6). For an
Anthropic Messages call (`POST .../v1/messages`) it forwards the request,
reads the model's response, turns each tool call in it into an
inspect_sentinel `BeforeToolCall` step, and runs the configured sentinel on
it before the agent sees the tool call:

    continue   the tool call goes to the agent unchanged
    modify     the tool call's arguments are replaced
    reject     the tool call is dropped and the agent gets a note saying
               what was blocked in its place; a non-streamed response is
               replaced whole by an assistant message that keeps the
               model's text, drops its tool calls and carries the note,
               so the agent's turn ends normally
    terminate  as reject; the sidecar cannot end the agent itself
    escalate   unresolved at the root: treated as reject (fail closed)

Everything else (other requests, and every non-200 answer) passes through
untouched, for roxy's rules to decide. A streamed response goes to the
agent as it arrives, a tool call at a time: its text and thinking stream
live, and each tool call is held from the start of its block to the end,
judged as soon as its arguments are complete, then released, rewritten or
replaced by the note. Later events wait their turn behind a held call, and
pings keep the agent's idle deadline met while it waits.

Each Claude Code session (its `X-Claude-Code-Session-Id` header), its model
calls and the sentinel's reports are written as an Inspect eval log for
`inspect view` (inspect_log.py). A call without that header is logged under
its conversation instead.

Configuration (environment):

    SENTINEL                 module:attribute of the sentinel (default policies:deny_regex)
    SENTINEL_DENY            the regex deny_regex uses (see policies.py)
    SENTINEL_MONITOR_MODEL   the model `context.host.generate` uses, for sentinels
                             that ask one (e.g. anthropic/claude-haiku-4-5)
    SENTINEL_LISTEN          host:port to listen on (default 127.0.0.1:9000)
    SENTINEL_LOG_DIR         where the Inspect log goes (default /logs)
    SENTINEL_TASK            the agent's name, for the Inspect log
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
from collections import OrderedDict, deque
from collections.abc import AsyncIterator, Sequence
from typing import Any

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
from inspect_sentinel import BeforeToolCall, Context, Decision, Host, HumanAnswer, Step

from inspect_log import InspectLog, InspectRecorder
from private_api import (
    HostContext,
    SSEDecoder,
    accumulate_event,
    anthropic_stop_reason,
    anthropic_usage,
    assistant_message_blocks,
    construct_type,
    resolve_sentinel,
    run_sentinel,
)
from roxy_layer import BodyFailed, Exchange, Request, Response, serve

log = logging.getLogger("sentinel-sidecar")

MAX_CONVERSATIONS = 10_000

# While part of a streamed response is held for judging, a ping this often
# keeps the agent's idle watchdogs from giving up on it.
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

# The blocks that go to the agent as they arrive. Any other block (a tool
# call, or one this sidecar does not know) is held until it is judged.
LIVE_BLOCKS = {"text", "thinking", "redacted_thinking"}


@dataclasses.dataclass
class HeldBlock:
    """A content block held for judging, complete."""

    index: int
    raw: bytes  # its events, as the upstream sent them
    block: dict[str, Any]
    message: dict[str, Any]  # the message so far, this block included


@dataclasses.dataclass
class MessageDelta:
    """The `message_delta` event, kept apart so its `stop_reason` can be
    rewritten once every tool call has its verdict."""

    raw: bytes
    data: dict[str, Any]


class HeldStream:
    """A streamed Messages response on its way to the agent, cut into what
    goes now and what waits for a verdict.

    Events pass through as they arrive, byte for byte, except a block
    outside LIVE_BLOCKS: its events are held from `content_block_start` to
    `content_block_stop`, then come out as one `HeldBlock` for judging. The
    message is rebuilt as it goes with the Anthropic SDK's decoder and
    accumulator (beta types: Claude Code calls the beta endpoint); an event
    the accumulator cannot take raises, and nothing after it passes."""

    def __init__(self) -> None:
        self._decoder = SSEDecoder()
        self._buf = b""
        self._event = b""
        self._snapshot: Any = None
        self._json_bufs: dict[int, bytes] = {}
        self._open: tuple[int, bytes] | None = None  # the held block being read
        self.started = False  # `message_start` has gone to the agent

    @property
    def holding(self) -> bool:
        return self._open is not None

    def feed(self, chunk: bytes) -> list[bytes | HeldBlock | MessageDelta]:
        """What the chunk completes, in order: events to pass on, blocks
        to judge and the message's `message_delta`."""
        items: list[bytes | HeldBlock | MessageDelta] = []
        self._buf += chunk
        while (nl := self._buf.find(b"\n")) != -1:
            line, self._buf = self._buf[: nl + 1], self._buf[nl + 1 :]
            self._event += line
            sse = self._decoder.decode(line.rstrip(b"\r\n").decode("utf-8", "replace"))
            if sse is None:
                continue
            event, self._event = self._event, b""
            item = self._route(event, sse)
            if isinstance(item, bytes) and items and isinstance(items[-1], bytes):
                items[-1] += item
            elif item is not None:
                items.append(item)
        return items

    def end(self) -> list[bytes | HeldBlock | MessageDelta]:
        """What is left when the stream ends: an unterminated last event."""
        if self._open is not None:
            raise ValueError(f"the stream ended inside content block {self._open[0]}")
        rest, self._buf, self._event = self._event + self._buf, b"", b""
        return [rest] if rest else []

    def _route(self, event: bytes, sse: Any) -> bytes | HeldBlock | MessageDelta | None:
        data = sse.json() if sse.event in STREAM_EVENTS else None
        if data is not None:
            typed = construct_type(type_=BetaRawMessageStreamEvent, value=data)
            self._snapshot = accumulate_event(typed, self._snapshot, self._json_bufs)
        if self._open is not None:
            index, raw = self._open
            raw += event
            if sse.event != "content_block_stop" or data["index"] != index:
                self._open = (index, raw)
                return None
            self._open = None
            message = self.message()
            return HeldBlock(index, raw, message["content"][index], message)
        if sse.event == "message_start":
            self.started = True
        elif sse.event == "content_block_start" and data["content_block"]["type"] not in LIVE_BLOCKS:
            self._open = (data["index"], event)
            return None
        elif sse.event == "message_delta":
            return MessageDelta(event, data)
        return event

    def message(self) -> dict[str, Any]:
        """The `Message` the stream has carried so far."""
        if self._snapshot is None:
            raise ValueError("no message in the stream")
        return self._snapshot.model_dump(mode="json")


def message_from_sse(raw: bytes) -> dict[str, Any]:
    """Rebuilds a `Message` from a whole event stream."""
    stream = HeldStream()
    stream.feed(raw)
    stream.end()
    return stream.message()


async def explanation(response: dict[str, Any], output: ModelOutput, note: str) -> dict[str, Any]:
    """The reply to a refused non-streamed response: the model's text,
    without its tool calls or thinking, then what was blocked. Built as an
    inspect message and converted as inspect's agent bridge answers an
    agent; its `end_turn` hands the turn back to the person, as an ordinary
    answer would."""
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


def sse_bytes(event: str, data: dict[str, Any]) -> bytes:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()


def block_to_sse(index: int, block: dict[str, Any]) -> bytes:
    """The events for one content block. A tool call's arguments go as one
    delta."""
    delta: dict[str, Any] | None
    if block["type"] == "text":
        opening = {"type": "text", "text": ""}
        delta = {"type": "text_delta", "text": block["text"]}
    elif block["type"] == "tool_use":
        opening = {"type": "tool_use", "id": block["id"], "name": block["name"], "input": {}}
        delta = {"type": "input_json_delta", "partial_json": json.dumps(block["input"])}
    else:
        # The accumulator's dump of a block names every field it knows,
        # unset ones as null; the API leaves those out.
        opening, delta = {k: v for k, v in block.items() if v is not None}, None
    out = sse_bytes("content_block_start", {"type": "content_block_start", "index": index, "content_block": opening})
    if delta is not None:
        out += sse_bytes("content_block_delta", {"type": "content_block_delta", "index": index, "delta": delta})
    return out + sse_bytes("content_block_stop", {"type": "content_block_stop", "index": index})


def error_event(message: str) -> bytes:
    return sse_bytes("error", {"type": "error", "error": {"type": "api_error", "message": message}})


class Call:
    """One Messages exchange, as inspect_ai types."""

    def __init__(self, request: dict[str, Any], response: dict[str, Any]) -> None:
        self.request = request
        self.response = response
        self.modified = False

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
                self.modified = True


def session(req: Request) -> str | None:
    """The Claude Code session a request belongs to, if it says. Every call a
    session makes carries it, the main agent's and its subagents' alike."""
    return req.header("x-claude-code-session-id") or None


def is_subagent(req: Request) -> bool:
    """Claude Code marks a subagent's calls with its agent id; the main
    agent's calls have none."""
    return req.header("x-claude-code-agent-id") is not None


@dataclasses.dataclass
class Refusal:
    """The agent does not get this response."""

    message: str
    call: Call | None = None
    output: ModelOutput | None = None


@dataclasses.dataclass
class Judging:
    """The sentinel's view of one exchange, shared by every tool call
    judged in it."""

    conversation: str
    input: list[ChatMessage]
    host_context: HostContext


def unreadable(e: Exception) -> Refusal:
    """A shape the SDK or inspect's converter does not know (a new block
    type, say) cannot be judged, so it is refused."""
    first_line = str(e).partition("\n")[0][:200]
    error = f"{type(e).__name__}: {first_line}"
    log.warning("unreadable model exchange: %s", error)
    return Refusal(f"the sentinel could not read this model exchange ({error})")


def refused_note(decision: Decision | None, action: str, function: str) -> str:
    """What the agent reads in a refused tool call's place."""
    log.info("%s on %s: %s", action, function, decision and decision.explanation)
    return (decision and decision.message) or f"tool call {function} refused ({action})"


def is_model_call(req: Request) -> bool:
    return req.method == "POST" and req.url.split("?", 1)[0].endswith("/v1/messages")


def refusal(message: str) -> tuple[Response, bytes]:
    """A 403 carrying `message` as plain text."""
    body = f"{message}\n".encode()
    return with_length(Response(403, [("content-type", "text/plain; charset=utf-8")]), len(body)), body


def with_length(res: Response, length: int) -> Response:
    headers = [(n, v) for n, v in res.headers if n.lower() != "content-length"]
    return Response(res.status, [*headers, ("content-length", str(length))])


# ----- the layer --------------------------------------------------------------


@dataclasses.dataclass
class Held:
    """A held block in the queue to the agent, with its verdict on the way."""

    block: HeldBlock
    verdict: asyncio.Task[Decision | None]


class Sidecar:
    def __init__(self, sentinel: Any, inspect_log: InspectLog, host: Host | None = None) -> None:
        self.root = resolve_sentinel(sentinel)
        # The host is what the sentinel may do to the world: by default a
        # monitor model and nobody to ask. A caller with a person to ask
        # (a review queue, say) passes its own.
        self.host = host or SidecarHost()
        self.stores = Stores()
        self.inspect_log = inspect_log

    async def handle(self, ex: Exchange) -> None:
        if not is_model_call(ex.request):
            # Not a model call: stream it through untouched.
            res = await ex.forward(ex.request, ex.body())
            await ex.respond(res, ex.response_body())
            return
        try:
            body = await ex.read_body()
        except BodyFailed as e:
            await ex.respond(
                Response(400, [("content-type", "text/plain")]),
                f"request body failed: {e}\n".encode(),
            )
            return
        res = await ex.forward(ex.request, body)
        if res.status == 101:
            # An upgrade's response body is the WebSocket: it has no end to
            # read to, so it streams through.
            await ex.respond(res, ex.response_body())
            return
        streamed = (res.header("content-type") or "").startswith("text/event-stream")
        if streamed and res.status == 200 and not ex.observing:
            head = [(n, v) for n, v in res.headers if n.lower() != "content-length"]
            await ex.respond(Response(res.status, head), self.judged_stream(ex, body))
            return
        try:
            raw = await ex.read_response_body()
        except BodyFailed as e:
            await ex.respond(
                Response(502, [("content-type", "text/plain")]),
                f"upstream body failed: {e}\n".encode(),
            )
            return
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
            await ex.respond(*refusal(verdict.message))

    async def judged_stream(self, ex: Exchange, body: bytes) -> AsyncIterator[bytes]:
        """A streamed response, judged a tool call at a time. Everything else
        goes to the agent as it arrives. A tool call is held from the start
        of its block to the end, judged as soon as its arguments are
        complete, then released unchanged, emitted with its new arguments,
        or replaced by a text block carrying the note. Events behind a held
        call wait their turn, so the agent reads the message in order, and
        a ping goes whenever it has waited PING_EVERY on a held call. An
        exchange the sidecar cannot read ends in an `error` event."""
        chunks: asyncio.Queue[bytes | None] = asyncio.Queue()

        async def read() -> None:
            try:
                async for chunk in ex.response_body():
                    chunks.put_nowait(chunk)
            finally:
                chunks.put_nowait(None)

        reader = asyncio.create_task(read())
        getter: asyncio.Task[bytes | None] | None = None
        stream = HeldStream()
        queue: deque[bytes | Held | MessageDelta] = deque()
        verdicts: list[asyncio.Task[Decision | None]] = []
        tool_calls = dropped = 0
        ended = False
        try:
            try:
                request = json.loads(body)
                judging = await self.judging(ex, request)
            except Exception as e:  # noqa: BLE001
                yield error_event(unreadable(e).message)
                return
            last = time.monotonic()
            while True:
                # Release what has its turn: passed events, judged blocks,
                # and the message's end once every call has a verdict.
                while queue:
                    head = queue[0]
                    if isinstance(head, bytes):
                        out = head
                    elif isinstance(head, MessageDelta):
                        out = head.raw
                        if tool_calls and dropped == tool_calls:
                            data = {**head.data, "delta": {**head.data["delta"], "stop_reason": "end_turn"}}
                            out = sse_bytes("message_delta", data)
                    elif head.verdict.done():
                        try:
                            decision = head.verdict.result()
                        except Exception as e:  # noqa: BLE001
                            yield error_event(unreadable(e).message)
                            return
                        out, was_dropped = self.released(head.block, decision)
                        if decision is not None or head.block.block["type"] == "tool_use":
                            tool_calls += 1
                        dropped += was_dropped
                    else:
                        break
                    queue.popleft()
                    if out:
                        yield out
                        last = time.monotonic()
                if ended and not queue:
                    break
                waits: set[asyncio.Task[Any]] = set()
                if not ended:
                    getter = getter or asyncio.create_task(chunks.get())
                    waits.add(getter)
                if queue and isinstance(queue[0], Held):
                    waits.add(queue[0].verdict)
                held = stream.holding or bool(queue)
                timeout = max(PING_EVERY - (time.monotonic() - last), 0) if held and stream.started else None
                done, _ = await asyncio.wait(waits, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
                if getter is not None and getter in done:
                    chunk = getter.result()
                    getter = None
                    message = None
                    try:
                        if chunk is None:
                            ended = True
                            reader.result()
                            items = stream.end()
                            message = stream.message()
                        else:
                            items = stream.feed(chunk)
                    except BodyFailed:
                        raise
                    except Exception as e:  # noqa: BLE001
                        yield error_event(unreadable(e).message)
                        return
                    for item in items:
                        if isinstance(item, HeldBlock):
                            verdict = asyncio.create_task(self.judge_block(judging, item))
                            verdicts.append(verdict)
                            queue.append(Held(item, verdict))
                        else:
                            queue.append(item)
                    if message is not None:
                        await self.log_stream(ex, judging, Call(request, message))
                elif not done:
                    yield PING
                    last = time.monotonic()
        finally:
            # The handler is cancelled here when roxy resets the stream:
            # the reader would otherwise wait on the response for ever, and
            # the sentinel's verdicts are no longer wanted.
            tasks = {reader, *verdicts, *([getter] if getter else [])}
            for t in tasks:
                t.cancel()
            await asyncio.wait(tasks)

    def released(self, block: HeldBlock, decision: Decision | None) -> tuple[bytes, bool]:
        """What goes to the agent for a judged block, and whether the block
        was dropped."""
        action = decision.action if decision else "continue"
        if action == "continue":
            return block.raw, False
        if action == "modify" and decision and decision.modified:
            return block_to_sse(block.index, {**block.block, "input": decision.modified.arguments}), False
        # reject, terminate, an unresolved escalate, or a modify that
        # cannot be applied: the agent gets the note in the call's place.
        note = refused_note(decision, action, block.block.get("name", block.block["type"]))
        return block_to_sse(block.index, {"type": "text", "text": note}), True

    async def judge_block(self, judging: Judging, block: HeldBlock) -> Decision | None:
        """The verdict on a held block, with the message so far as its
        context. A block that is not a tool call has nothing to judge, as
        long as inspect can read it."""
        output = await model_output_from_anthropic(block.message)
        tc = next((t for t in output.message.tool_calls or [] if t.id == block.block.get("id")), None)
        if tc is None:
            if block.block["type"] == "tool_use":
                raise ValueError(f"tool call {block.block.get('id')} not read")
            return None
        return await self.decide(judging, tc, output.message.text)

    async def log_stream(self, ex: Exchange, judging: Judging, call: Call) -> None:
        """The Inspect log entry for a streamed call, once it is whole."""
        try:
            output = await call.output()
        except Exception as e:  # noqa: BLE001
            log.warning("unreadable model response, not logged: %s", e)
            return
        self.log_call(ex, judging, call, output)

    async def judge(self, ex: Exchange, body: bytes, res: Response, raw: bytes) -> None | bytes | Refusal:
        """A whole response: None to pass it on, new bytes for a modified
        response, or a refusal."""
        streamed = (res.header("content-type") or "").startswith("text/event-stream")
        try:
            call = Call(json.loads(body), message_from_sse(raw) if streamed else json.loads(raw))
        except Exception as e:  # noqa: BLE001
            return unreadable(e)
        refused = await self.judge_call(ex, call)
        if refused is not None:
            return refused
        return json.dumps(call.response).encode() if call.modified else None

    async def judge_call(self, ex: Exchange, call: Call) -> Refusal | None:
        """Runs the sentinel on each tool call in a whole response. A
        modified call's arguments are replaced in `call.response`."""
        try:
            output = await call.output()
        except Exception as e:  # noqa: BLE001
            return unreadable(e)
        judging = await self.judging(ex, call.request)
        self.log_call(ex, judging, call, output)
        for tc in output.message.tool_calls or []:
            decision = await self.decide(judging, tc, output.message.text)
            action = decision.action if decision else "continue"
            if action == "continue":
                continue
            if action == "modify" and decision and decision.modified:
                call.modify(tc, decision.modified)
                continue
            # reject, terminate, an unresolved escalate, or a modify that
            # cannot be applied: the agent does not get this response.
            return Refusal(refused_note(decision, action, tc.function), call, output)
        return None

    async def judging(self, ex: Exchange, request: dict[str, Any]) -> Judging:
        call = Call(request, {})
        try:
            input = await call.input()
        except Exception as e:  # noqa: BLE001
            # The history is context for the sentinel, not the thing it
            # judges: a conversation the converter cannot read still gets
            # its tool calls judged, with no history.
            log.warning("unreadable conversation history: %s", e)
            input = []
        conversation = call.conversation()
        if sid := session(ex.request):
            # Two sessions can open with the same first message; the
            # session keeps their conversations, and their verdicts, apart.
            conversation = hashlib.sha256(f"{sid}:{conversation}".encode()).hexdigest()[:24]
        # No eval: a proxy has no task, sample or epoch to give a sentinel.
        context = Context(path="", host=self.host, eval=None)
        host_context = HostContext(
            context=context,
            recorder=InspectRecorder(self.inspect_log),
            store=self.stores.get(conversation),
        )
        return Judging(conversation, input, host_context)

    async def decide(self, judging: Judging, tc: ToolCall, message: str) -> Decision | None:
        step = BeforeToolCall(
            conversation=judging.conversation,
            message=message,
            call=tc,
            view=ToolCallView(),
            input=judging.input,
            history=judging.input,
        )
        return await run_sentinel(self.root, judging.host_context, step)

    def log_call(self, ex: Exchange, judging: Judging, call: Call, output: ModelOutput) -> None:
        self.inspect_log.model_call(
            session(ex.request) or judging.conversation,
            judging.conversation,
            ex.flow.get("flow"),
            f"anthropic/{call.response.get('model', 'unknown')}",
            judging.input,
            output,
            main=not is_subagent(ex.request),
        )


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
