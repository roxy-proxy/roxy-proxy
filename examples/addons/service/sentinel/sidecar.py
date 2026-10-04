"""inspect_sentinel at the network boundary: a roxy service layer.

Every exchange streams through this sidecar (roxy.layer.v1).
For a model API call (Anthropic Messages or OpenAI Chat
Completions) it forwards the request, reads the model's response, turns
each tool call in it into an inspect_sentinel `BeforeToolCall` step, and
runs the configured sentinel on it before the agent sees the response:

    continue   the response goes to the agent unchanged
    modify     the tool call's arguments are replaced (JSON responses)
    reject     the agent gets a 403 carrying the decision's message
    terminate  the agent gets a 403; the sidecar cannot end the agent itself
    escalate   unresolved at the root: treated as reject (fail closed)

Everything else (and every non-200 answer) passes through untouched.

The sidecar implements inspect_sentinel's host side: a `Host` whose
`generate` calls the monitor model directly (not through roxy), a
`Recorder` that writes every report as a JSON line on stdout, and a store
per conversation, keyed by a fingerprint of the conversation's stable head
(system prompt and first user turn) so an agent cannot rotate it.

Configuration (environment):

    SENTINEL                 module:attribute of the sentinel (default policies:no_network)
    SENTINEL_MONITOR_MODEL   the model `context.host.generate` uses (e.g. anthropic/claude-haiku-4-5)
    SENTINEL_LISTEN          host:port to listen on (default 127.0.0.1:9000)
    SENTINEL_TASK            the deployed agent's name, for `context.task`

Known gaps, as inspect_sentinel's deployment design describes them: a
proxy sees `AfterToolCall` only in the next request (not projected here);
`reject` here is an error the agent's SDK raises, not the
append-and-regenerate replay an eval does; and streamed responses are held
until judged, which costs time to first token.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import importlib
import json
import logging
import os
import sys
from collections import OrderedDict
from collections.abc import Sequence
from typing import Any

from inspect_ai.model import (
    ChatMessage,
    GenerateConfig,
    Model,
    ModelOutput,
    get_model,
    messages_from_anthropic,
    messages_from_openai,
    model_output_from_anthropic,
    model_output_from_openai,
)
from inspect_ai.tool import ToolCall, ToolCallView, ToolInfo
from inspect_ai.util import Store
from inspect_sentinel import BeforeToolCall, Context, Decision, HumanAnswer, Step

# The host contract inspect_ai itself uses to run a sentinel.
from inspect_sentinel._integration import HostContext, resolve_sentinel, run_sentinel

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from roxy_layer import Exchange, Request, Response, serve  # noqa: E402

log = logging.getLogger("sentinel-sidecar")

MAX_CONVERSATIONS = 10_000


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


def _jsonable(v: Any) -> Any:
    if hasattr(v, "model_dump"):
        return v.model_dump(mode="json", exclude_none=True)
    if dataclasses.is_dataclass(v) and not isinstance(v, type):
        return {f.name: _jsonable(getattr(v, f.name)) for f in dataclasses.fields(v)}
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    if isinstance(v, dict):
        return {k: _jsonable(x) for k, x in v.items()}
    return v if isinstance(v, (str, int, float, bool, type(None))) else str(v)


class JsonlRecorder:
    """Every report, failure and cancellation, one JSON line each, tagged
    with roxy's flow id so it joins roxy's flow log."""

    def __init__(self, flow: str | None) -> None:
        self.flow = flow

    def _emit(self, kind: str, context: Context, factory: str, step: Step, **data: Any) -> None:
        call = getattr(step, "call", None)
        line = {
            "event": f"sentinel_{kind}",
            "flow": self.flow,
            "conversation": step.conversation,
            "path": context.path,
            "factory": factory,
            "tool": call.function if call else None,
            **{k: _jsonable(v) for k, v in data.items()},
        }
        print(json.dumps(line), flush=True)

    def record(self, context: Context, factory: str, step: Step, reported: Any) -> None:
        self._emit("report", context, factory, step, reported=reported)

    def failed(self, context: Context, factory: str, step: Step, failed: Any) -> None:
        self._emit("failed", context, factory, step, failed=failed)

    def cancelled(self, context: Context, factory: str, step: Step, name: str) -> None:
        self._emit("cancelled", context, factory, step, name=name)

    def bypassed(self, context: Context, factory: str, step: Step, name: str) -> None:
        self._emit("bypassed", context, factory, step, name=name)

    def superseded(self, context: Context, factory: str, step: Step, reported: Any) -> None:
        self._emit("superseded", context, factory, step, reported=reported)


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


# ----- model API wire formats -------------------------------------------------


def _system_text(system: Any) -> str | None:
    if system is None or isinstance(system, str):
        return system
    return "\n".join(b.get("text", "") for b in system if isinstance(b, dict))


def _fingerprint(*parts: Any) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()[:24]


def anthropic_from_sse(raw: bytes) -> dict[str, Any]:
    """Rebuilds an Anthropic `Message` from its event stream."""
    message: dict[str, Any] = {}
    partial: dict[int, str] = {}
    for event in raw.decode().split("\n\n"):
        data = next(
            (line[5:].strip() for line in event.splitlines() if line.startswith("data:")), None
        )
        if not data:
            continue
        e = json.loads(data)
        t = e.get("type")
        if t == "message_start":
            message = e["message"]
            message["content"] = []
        elif t == "content_block_start":
            message["content"].append(e["content_block"])
        elif t == "content_block_delta":
            block, d = message["content"][e["index"]], e["delta"]
            if d["type"] == "text_delta":
                block["text"] = block.get("text", "") + d["text"]
            elif d["type"] == "input_json_delta":
                partial[e["index"]] = partial.get(e["index"], "") + d["partial_json"]
            elif d["type"] == "thinking_delta":
                block["thinking"] = block.get("thinking", "") + d["thinking"]
        elif t == "content_block_stop":
            if e["index"] in partial:
                message["content"][e["index"]]["input"] = json.loads(partial[e["index"]] or "{}")
        elif t == "message_delta":
            message.update(e.get("delta", {}))
            message.setdefault("usage", {}).update(e.get("usage", {}))
    return message


class Call:
    """One model API exchange, as inspect_ai types."""

    def __init__(
        self,
        api: str,
        request: dict[str, Any],
        response: dict[str, Any],
        streamed: bool,
    ) -> None:
        self.api = api
        self.request = request
        self.response = response
        self.streamed = streamed

    async def input(self) -> list[ChatMessage]:
        if self.api == "anthropic":
            return await messages_from_anthropic(
                self.request.get("messages", []), _system_text(self.request.get("system"))
            )
        return await messages_from_openai(self.request.get("messages", []))

    async def output(self) -> ModelOutput:
        if self.api == "anthropic":
            return await model_output_from_anthropic(self.response)
        return await model_output_from_openai(self.response)

    def conversation(self) -> str:
        messages = self.request.get("messages", [])
        first_user = next((m for m in messages if m.get("role") == "user"), None)
        return _fingerprint(self.api, self.request.get("system"), first_user)

    def modify(self, call: ToolCall, replacement: ToolCall) -> None:
        """Replaces a tool call's arguments in the response."""
        if self.api == "anthropic":
            for block in self.response.get("content", []):
                if block.get("type") == "tool_use" and block.get("id") == call.id:
                    block["input"] = replacement.arguments
        else:
            for choice in self.response.get("choices", []):
                for tc in choice.get("message", {}).get("tool_calls") or []:
                    if tc.get("id") == call.id:
                        tc["function"]["arguments"] = json.dumps(replacement.arguments)


def classify(req: Request) -> str | None:
    path = req.url.split("?", 1)[0]
    if path.endswith("/v1/messages"):
        return "anthropic"
    if path.endswith("/chat/completions"):
        return "openai"
    return None


# ----- the layer --------------------------------------------------------------


class Sidecar:
    def __init__(self, sentinel: Any) -> None:
        self.root = resolve_sentinel(sentinel)
        self.host = SidecarHost()
        self.stores = Stores()

    async def handle(self, ex: Exchange) -> None:
        api = classify(ex.request)
        if api is None or ex.request.method != "POST":
            # Not a model call: stream it through untouched.
            res = await ex.forward(ex.request, ex.body())
            await ex.respond(res, ex.response_body())
            return
        body = await ex.read_body()
        res = await ex.forward(ex.request, body)
        raw = await ex.read_response_body()
        if res.status != 200 or ex.observing:
            await ex.respond(res, raw)
            if ex.observing and res.status == 200:
                await self.judge(ex, api, body, res, raw)
            return
        verdict = await self.judge(ex, api, body, res, raw)
        if verdict is None:
            await ex.respond(res, raw)
        elif isinstance(verdict, bytes):
            headers = [(n, v) for n, v in res.headers if n.lower() != "content-length"]
            headers.append(("content-length", str(len(verdict))))
            await ex.respond(Response(res.status, headers), verdict)
        else:
            await ex.deny(403, verdict)

    async def judge(
        self, ex: Exchange, api: str, body: bytes, res: Response, raw: bytes
    ) -> None | bytes | str:
        """None to pass the response on, new bytes for a modified response,
        or the message for a refusal."""
        streamed = (res.header("content-type") or "").startswith("text/event-stream")
        try:
            request = json.loads(body)
            if streamed and api == "anthropic":
                response = anthropic_from_sse(raw)
            elif streamed:
                return "the sentinel cannot read this streamed response (use stream: false)"
            else:
                response = json.loads(raw)
        except (ValueError, KeyError, IndexError) as e:
            log.warning("unreadable %s exchange: %s", api, e)
            return "the sentinel could not read this model exchange"
        call = Call(api, request, response, streamed)
        output = await call.output()
        tool_calls = output.message.tool_calls or []
        if not tool_calls:
            return None
        input = await call.input()
        conversation = call.conversation()
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
            recorder=JsonlRecorder(ex.flow.get("roxy-flow-id")),
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
            return (decision and decision.message) or f"tool call {tc.function} refused ({action})"
        return json.dumps(call.response).encode() if modified else None


def load_sentinel(spec: str) -> Any:
    module, _, attr = spec.partition(":")
    sys.path.insert(0, os.path.dirname(__file__))
    obj = getattr(importlib.import_module(module), attr)
    return obj() if callable(obj) else obj


async def main() -> None:
    sidecar = Sidecar(load_sentinel(os.environ.get("SENTINEL", "policies:no_network")))
    host, _, port = os.environ.get("SENTINEL_LISTEN", "127.0.0.1:9000").rpartition(":")
    async with serve(sidecar.handle, host, int(port)) as server:
        log.info("sentinel sidecar listening on %s:%s", host, port)
        await server.serve_forever()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    asyncio.run(main())
