"""The private anthropic, inspect_ai and inspect_sentinel APIs the sidecar
uses, all in one place. requirements.txt pins the versions they are known
to work with; an upgrade that moves one fails here, at import."""

from __future__ import annotations

from typing import Any

import httpx2

# The SDK's stream parsing, so a held stream is read exactly as the SDK reads one.
from anthropic._streaming import SSEDecoder

# Builds a stream event from its JSON as the SDK's stream does (no public constructor).
from anthropic._models import construct_type

# The SDK's message accumulator: only reachable through a live HTTP stream otherwise.
from anthropic.lib.streaming._beta_messages import accumulate_event as _accumulate_event

# The converters inspect's agent bridge uses to answer an agent in the Messages format.
from inspect_ai.agent._bridge.anthropic_api_impl import (
    anthropic_stop_reason,
    anthropic_usage,
    assistant_message_blocks,
)

# Whether a registered factory is a monitor or a protocol: only the registry knows.
from inspect_ai._sentinel._dispatch import _factory_kind as factory_kind

# The host contract inspect_ai itself uses to run a sentinel.
from inspect_sentinel._integration import HostContext, resolve_sentinel, run_sentinel

__all__ = [
    "HostContext",
    "SSEDecoder",
    "accumulate_event",
    "anthropic_stop_reason",
    "anthropic_usage",
    "assistant_message_blocks",
    "construct_type",
    "factory_kind",
    "resolve_sentinel",
    "run_sentinel",
]


def accumulate_event(event: Any, snapshot: Any, json_bufs: dict[int, bytes]) -> Any:
    """Adds a stream event to the message so far. The request headers only
    matter for structured output, which a held stream never asks for."""
    return _accumulate_event(
        event=event, current_snapshot=snapshot, json_bufs=json_bufs, request_headers=httpx2.Headers()
    )
