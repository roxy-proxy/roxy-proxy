"""Trickles model calls through roxy for several users, for ever, so the
quota board and Inspect View have something to show from `compose up`.

Each user calls on their own cadence, in their own thread. At the default
quota (a bucket of 600 tokens refilling 5 a second) alice's cadence drains
hers inside the first minute, bob's holds, and mallory's credential is
unknown. One line per
thing that came back, prefixed with the user and call number.

    TRAFFIC_SCHEDULE   user=secret@seconds, comma-separated
                       (default alice=alice-secret@6,bob=bob-secret@20,mallory=wrong@30)
"""

from __future__ import annotations

import itertools
import os
import pathlib
import threading
import time

from chat import call, make_client

DEFAULT = "alice=alice-secret@6,bob=bob-secret@20,mallory=wrong@30"
PROMPTS = ["What can you do?", "List the files here.", "Fetch https://example.com for me.", "Tell me more."]


def parse(schedule: str) -> list[tuple[str, str, float]]:
    out = []
    for item in schedule.split(","):
        user, rest = item.strip().split("=", 1)
        secret, every = rest.rsplit("@", 1)
        out.append((user, secret, float(every)))
    return out


def drive(user: str, secret: str, every: float) -> None:
    client = make_client(user, secret)
    prompts = itertools.cycle(PROMPTS)
    for n in itertools.count(1):
        call(client, f"[{user} #{n}]", next(prompts), echo=False)
        time.sleep(every)


def main() -> None:
    schedule = parse(os.environ.get("TRAFFIC_SCHEDULE", DEFAULT))
    for user, secret, every in schedule:
        print(f"[traffic] {user}: a call every {every:g}s", flush=True)
    threads = [threading.Thread(target=drive, args=s, daemon=True, name=s[0]) for s in schedule]
    for i, t in enumerate(threads):
        time.sleep(1.5 * i)  # stagger the first calls so the log reads in order
        t.start()
    pathlib.Path("/tmp/traffic-started").touch()  # the healthcheck looks for it
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
