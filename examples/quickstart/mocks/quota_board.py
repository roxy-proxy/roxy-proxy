"""A mock quota service for the token-quota addon, with a live board.

Each user has a token bucket: QUOTA_CAPACITY tokens, refilling at
QUOTA_REFILL_PER_SEC. A call is allowed while the bucket holds anything;
the tokens it then used are taken out, so a bucket can go into debt, and
the user waits for it to refill past zero.

    POST /check  {"user"}                                   -> an allowance (below)
    POST /report {"user", "input_tokens", "output_tokens"}  -> the allowance after taking them
    POST /reset                                             -> every bucket full again
    GET  /usage                                             -> every user, as JSON, with HISTORY_SECS of bucket levels
    GET  /events                                            -> the same, as SSE, on every change and every second
    GET  /                                                  -> the board

An allowance: {"allowed", "available", "capacity", "refill_per_sec",
"retry_in" (seconds until the bucket is positive again), "requests",
"refused", "used_total"}.
"""

from __future__ import annotations

import json
import logging
import math
from collections import deque
import os
import threading
import time
from pathlib import Path
from typing import Any

from common import JsonHandler, serve

CAPACITY = float(os.environ.get("QUOTA_CAPACITY", "600"))
REFILL = float(os.environ.get("QUOTA_REFILL_PER_SEC", "5"))
HISTORY_SECS = int(os.environ.get("HISTORY_SECS", "300"))
PAGE = Path(__file__).with_name("quota_board.html").read_bytes()


class Bucket:
    def __init__(self, now: float) -> None:
        self.available = CAPACITY
        self.updated = now
        self.requests = 0
        self.refused = 0
        self.used_total = 0

    def refill(self, now: float) -> None:
        self.available = min(CAPACITY, self.available + (now - self.updated) * REFILL)
        self.updated = now

    def view(self, user: str) -> dict[str, Any]:
        return {
            "user": user,
            "allowed": self.available > 0,
            "available": math.floor(self.available),
            "capacity": int(CAPACITY),
            "refill_per_sec": REFILL,
            "retry_in": 0 if self.available > 0 else math.ceil(-self.available / REFILL),
            "requests": self.requests,
            "refused": self.refused,
            "used_total": self.used_total,
        }


class Ledger:
    def __init__(self) -> None:
        self.lock = threading.Condition()
        self.buckets: dict[str, Bucket] = {}
        self.version = 0
        # One sample a second of every bucket's level: [t, {user: available}].
        self.history: deque[tuple[float, dict[str, int]]] = deque(maxlen=HISTORY_SECS)

    def _bucket(self, user: str, now: float) -> Bucket:
        b = self.buckets.get(user)
        if b is None:
            b = self.buckets[user] = Bucket(now)
        b.refill(now)
        return b

    def check(self, user: str) -> dict[str, Any]:
        with self.lock:
            b = self._bucket(user, time.time())
            if b.available > 0:
                b.requests += 1
            else:
                b.refused += 1
            self._changed()
            return b.view(user)

    def report(self, user: str, tokens: int) -> dict[str, Any]:
        with self.lock:
            b = self._bucket(user, time.time())
            b.available -= tokens
            b.used_total += tokens
            self._changed()
            return b.view(user)

    def reset(self) -> None:
        with self.lock:
            self.buckets.clear()
            self.history.clear()
            self._changed()

    def sample(self) -> None:
        with self.lock:
            now = time.time()
            levels = {u: math.floor(self._bucket(u, now).available) for u in sorted(self.buckets)}
            self.history.append((now, levels))

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            now = time.time()
            rows = [self._bucket(u, now).view(u) for u in sorted(self.buckets)]
            return {
                "capacity": int(CAPACITY),
                "refill_per_sec": REFILL,
                "users": rows,
                "history": [{"t": t, "levels": levels} for t, levels in self.history],
                "version": self.version,
            }

    def wait(self, version: int, timeout: float) -> None:
        with self.lock:
            self.lock.wait_for(lambda: self.version != version, timeout)

    def _changed(self) -> None:
        self.version += 1
        self.lock.notify_all()


LEDGER = Ledger()


class Handler(JsonHandler):
    log = logging.getLogger("quota-board")

    def do_POST_check(self) -> None:  # noqa: N802
        user = str(self.read_json().get("user", ""))
        view = LEDGER.check(user)
        self.log.info("%s: %s, %d tokens available", user, "allowed" if view["allowed"] else "REFUSED", view["available"])
        self.send_json(200, view)

    def do_POST_report(self) -> None:  # noqa: N802
        body = self.read_json()
        user = str(body.get("user", ""))
        tokens = int(body.get("input_tokens", 0)) + int(body.get("output_tokens", 0))
        view = LEDGER.report(user, tokens)
        self.log.info("%s: -%d tokens, %d available", user, tokens, view["available"])
        self.send_json(200, view)

    def do_POST_reset(self) -> None:  # noqa: N802
        LEDGER.reset()
        self.send_json(200, {"ok": True})

    def do_GET_usage(self) -> None:  # noqa: N802
        self.send_json(200, LEDGER.snapshot())

    def do_GET_index(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("content-length", str(len(PAGE)))
        self.end_headers()
        self.wfile.write(PAGE)

    def do_GET_events(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-cache")
        self.send_header("transfer-encoding", "chunked")
        self.end_headers()
        try:
            while True:
                snap = LEDGER.snapshot()
                data = f"data: {json.dumps(snap)}\n\n".encode()
                self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
                self.wfile.flush()
                LEDGER.wait(snap["version"], timeout=1.0)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        if not self.path.startswith(("/events", "/usage")):
            super().log_message(format, *args)


def sampler() -> None:
    while True:
        time.sleep(1)
        LEDGER.sample()


if __name__ == "__main__":
    Handler.log.info("buckets of %d tokens, refilling %g a second", CAPACITY, REFILL)
    threading.Thread(target=sampler, daemon=True).start()
    serve(Handler, 8090)
