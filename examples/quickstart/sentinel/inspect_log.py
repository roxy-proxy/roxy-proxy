"""What the sidecar sees, as an Inspect eval log for `inspect view`.

Each Claude Code session is a sample. Every model call the sidecar judged
is a model event (the messages new since the last call on the same
conversation, and the model's output), followed by a sentinel event for each
report the sentinel made about it, as an Inspect eval records them. A
session's subagents share its sample: each is its own conversation, so its
calls are logged alongside the main agent's without garbling either; the
sample's transcript follows the main agent. The log is rewritten at
most every `WRITE_EVERY` seconds while anything changed; its status stays
`started`, since the proxy never finishes.

    inspect view --log-dir $SENTINEL_LOG_DIR
"""

from __future__ import annotations

import asyncio
import datetime
import logging
import os
import uuid
from typing import Any

from inspect_ai.event import ModelEvent, SentinelEvent
from inspect_ai.log import EvalConfig, EvalDataset, EvalLog, EvalSample, EvalSpec, write_eval_log
from inspect_ai.model import ChatMessage, GenerateConfig, ModelOutput
from inspect_sentinel import Context, Step

from private_api import factory_kind

log = logging.getLogger("sentinel-sidecar")

WRITE_EVERY = 2.0


def _kind(factory: str) -> str:
    try:
        return factory_kind(factory)
    except Exception:  # noqa: BLE001
        return "decision"


class InspectLog:
    def __init__(self, log_dir: str, task: str) -> None:
        now = datetime.datetime.now(datetime.timezone.utc)
        self.path = os.path.join(
            log_dir, f"{now:%Y-%m-%dT%H-%M-%S%z}_{task}_{uuid.uuid4().hex[:8]}.eval"
        )
        self.log = EvalLog(
            eval=EvalSpec(
                created=now.isoformat(),
                task=task,
                dataset=EvalDataset(name="roxy"),
                model="roxy/proxy",
                config=EvalConfig(),
            ),
            status="started",
            samples=[],
        )
        self._samples: dict[str, EvalSample] = {}
        self._sample_of: dict[str, str] = {}  # conversation -> sample id
        self._logged: dict[str, int] = {}  # conversation -> messages logged
        self._dirty = False

    def _sample(self, sample_id: str) -> EvalSample:
        sample = self._samples.get(sample_id)
        if sample is None:
            sample = EvalSample(
                id=sample_id,
                epoch=1,
                input="",
                target="",
                messages=[],
                events=[],
                metadata={"roxy_flows": []},
            )
            self._samples[sample_id] = sample
            assert self.log.samples is not None
            self.log.samples.append(sample)
        return sample

    def model_call(
        self,
        sample_id: str,
        conversation: str,
        flow: str | None,
        model: str,
        input: list[ChatMessage],
        output: ModelOutput,
        *,
        main: bool = True,
    ) -> None:
        """Logs a model call on `conversation` to sample `sample_id`. The
        sample's transcript is updated only by a `main` call: a subagent's
        calls are logged as events without replacing it."""
        sample = self._sample(sample_id)
        if main and not sample.input:
            first_user = next((m for m in input if m.role == "user"), None)
            sample.input = first_user.text if first_user else ""
        self._sample_of[conversation] = sample_id
        logged = self._logged.get(conversation, 0)
        # Each call resends the whole conversation: log only what is new
        # since the last one (all of it if the agent compacted its history).
        new = input[logged:] if logged <= len(input) else input
        sample.events.append(
            ModelEvent(
                model=model,
                input=new,
                tools=[],
                tool_choice="auto",
                config=GenerateConfig(),
                output=output,
            )
        )
        if main:
            sample.messages = [*input, output.message]
        sample.metadata["roxy_flows"].append(flow)
        self._logged[conversation] = len(input) + 1
        self._dirty = True

    def sentinel(self, event: SentinelEvent) -> None:
        sample = self._samples.get(self._sample_of.get(event.conversation, ""))
        if sample is not None:
            sample.events.append(event)
            self._dirty = True

    async def run(self) -> None:
        """Writes the log whenever it changed, at most every WRITE_EVERY s."""
        while True:
            await asyncio.sleep(WRITE_EVERY)
            if not self._dirty:
                continue
            self._dirty = False
            snapshot = self.log.model_copy(
                update={"samples": [s.model_copy(deep=True) for s in self._samples.values()]}
            )
            try:
                await asyncio.to_thread(write_eval_log, snapshot, self.path)
            except Exception as e:  # noqa: BLE001
                log.warning("could not write %s: %s", self.path, e)


class InspectRecorder:
    """A sentinel `Recorder` that adds each report to the log as the
    `SentinelEvent` an Inspect eval would record."""

    def __init__(self, log: InspectLog) -> None:
        self.inspect_log = log

    def _emit(self, context: Context, factory: str, step: Step, kind: str, status: str, **fields: Any) -> None:
        call = getattr(step, "call", None)
        try:
            event = SentinelEvent(
                factory=factory,
                path=context.path,
                step_id=call.id if call else "",
                conversation=step.conversation,
                stage="tool_call",
                kind=kind,
                status=status,
                **fields,
            )
        except ValueError as e:
            log.warning("unrecordable sentinel report from %s: %s", factory, e)
            return
        self.inspect_log.sentinel(event)

    def _report(self, context: Context, factory: str, step: Step, status: str, reported: Any) -> None:
        report = reported.report
        if hasattr(report, "suspicion"):
            self._emit(
                context, factory, step, "observation", status,
                function=reported.function,
                suspicion=report.suspicion,
                explanation=report.explanation,
                references=report.references,
                metadata=report.metadata,
            )
        else:
            self._emit(
                context, factory, step, "decision", status,
                function=reported.function,
                action=report.action,
                audit=report.audit,
                message=report.message,
                explanation=report.explanation,
                references=report.references,
                metadata=report.metadata,
                modified=report.modified,
            )

    def record(self, context: Context, factory: str, step: Step, reported: Any) -> None:
        self._report(context, factory, step, "reported", reported)

    def superseded(self, context: Context, factory: str, step: Step, reported: Any) -> None:
        self._report(context, factory, step, "superseded", reported)

    def failed(self, context: Context, factory: str, step: Step, failed: Any) -> None:
        self._emit(
            context, factory, step, "observation", "error",
            function=failed.function,
            error=f"{type(failed.error).__name__}: {failed.error}",
        )

    def cancelled(self, context: Context, factory: str, step: Step, name: str) -> None:
        self._emit(context, factory, step, _kind(factory), "cancelled")

    def bypassed(self, context: Context, factory: str, step: Step, name: str) -> None:
        self._emit(context, factory, step, _kind(factory), "bypassed")
