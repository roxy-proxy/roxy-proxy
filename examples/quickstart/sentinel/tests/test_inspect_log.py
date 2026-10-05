from typing import Any

from inspect_ai.model import ChatMessageUser, ModelOutput

from inspect_log import InspectLog


def call(log: InspectLog, text: str) -> None:
    log.model_call(
        "session", "conversation", "flow", "anthropic/claude-test",
        [ChatMessageUser(content=text)], ModelOutput.from_content("anthropic/claude-test", "ok"),
    )


def test_a_snapshot_does_not_change_as_more_is_logged(tmp_path: Any) -> None:
    log = InspectLog(str(tmp_path), "test")
    call(log, "first")
    snapshot = log.snapshot()
    call(log, "second")
    assert snapshot.samples is not None
    [sample] = snapshot.samples
    assert len(sample.events) == 1
    assert sample.metadata["roxy_flows"] == ["flow"]
    assert [m.text for m in sample.messages] == ["first", "ok"]
