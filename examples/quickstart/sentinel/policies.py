"""The quickstart's sentinel. `SENTINEL=policies:deny_regex` (the default).

An ordinary inspect_sentinel protocol: the same code runs inside an Inspect
eval. Any other inspect_sentinel monitor or protocol works in its place.
"""

import json
import os
import re

from inspect_sentinel import BeforeToolCall, Context, Decision, Protocol, protocol

DEFAULT_DENY = r"\b(curl|wget|nc|ncat|ssh|scp|rsync)\b|rm\s+-rf"


@protocol
def deny_regex() -> Protocol:
    """Reject any tool call whose name or arguments match `SENTINEL_DENY`.

    The pattern is a Python regular expression, searched (not fully
    matched) against `<tool name> <arguments as JSON>`, so it sees the
    command a shell tool would run whatever the agent calls the tool.
    """
    pattern = re.compile(os.environ.get("SENTINEL_DENY") or DEFAULT_DENY)

    async def decide(context: Context, step: BeforeToolCall) -> Decision | None:
        subject = f"{step.call.function} {json.dumps(step.call.arguments)}"
        found = pattern.search(subject)
        if found:
            return Decision.reject(
                f"{step.call.function} matches the denylist: {found.group(0)!r}",
                message=f"roxy's sentinel blocked a {step.call.function} tool call "
                f"(denylist match: {found.group(0)!r}).",
            )
        return Decision.proceed()

    return decide
