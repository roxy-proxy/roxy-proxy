"""Every tool call waits for a person.

A roxy service layer for the Anthropic Messages API. Each tool call the
model returns is shown on a page in the browser, and the response is held
until someone clicks Approve or Deny there. Approved, the response goes to
the agent as the model sent it. Denied, the agent gets an assistant message
in its place: the model's text, no tool calls, and the reason the person
gave. The sentinel is inspect_sentinel's own `human()` protocol; the
person's side of it is the review queue in review.py.

The stream parsing, the hold (a streamed response's head and
`message_start` go to the agent at once, then a ping every few seconds
until the verdict) and the roxy.layer.v6 protocol are the quickstart
sentinel's, imported from ../quickstart/sentinel.

    python approval.py [--listen 127.0.0.1:9000] [--ui 127.0.0.1:8585] [--log-dir DIR]
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import pathlib
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "quickstart" / "sentinel"))

from inspect_sentinel import human  # noqa: E402

from inspect_log import InspectLog  # noqa: E402
from review import ReviewQueue, serve_ui  # noqa: E402
from roxy_layer import serve  # noqa: E402
from sidecar import Sidecar  # noqa: E402

log = logging.getLogger("human-approval")


def build(log_dir: str) -> tuple[Sidecar, ReviewQueue]:
    """The sidecar and the queue its sentinel asks: one `human()` at the
    root, asking about every tool call, offering approve and reject."""
    queue = ReviewQueue()
    sentinel = human(stages=["tool_call"], choices=["approve", "reject"])
    return Sidecar(sentinel, InspectLog(log_dir, "human-approval"), host=queue), queue


def hostport(value: str) -> tuple[str, int]:
    host, _, port = value.rpartition(":")
    return host, int(port)


async def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--listen", default="127.0.0.1:9000", help="where roxy connects (the layer's endpoint)")
    parser.add_argument("--ui", default="127.0.0.1:8585", help="where the review page is served")
    parser.add_argument(
        "--log-dir",
        default=str(pathlib.Path(tempfile.gettempdir()) / "roxy-human-approval"),
        help="where the Inspect log of what was asked and answered goes",
    )
    args = parser.parse_args()
    pathlib.Path(args.log_dir).mkdir(parents=True, exist_ok=True)
    sidecar, queue = build(args.log_dir)
    writer = asyncio.create_task(sidecar.inspect_log.run())  # noqa: F841 (held for its lifetime)
    log.info("writing an Inspect log to %s", sidecar.inspect_log.path)
    ui = await serve_ui(queue, *hostport(args.ui))
    log.info("review page at http://%s/", args.ui)
    try:
        async with serve(sidecar.handle, *hostport(args.listen)) as server:
            log.info("layer listening on %s", args.listen)
            await server.serve_forever()
    finally:
        await ui.cleanup()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
