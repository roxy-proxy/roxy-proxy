"""A mock quota service for the token-quota addon, with a live board.

Each user gets QUOTA_TOKENS tokens per QUOTA_WINDOW_SECS window; the window
starts at a user's first call and resets when it ends. Nothing is durable:
restart it and every user starts fresh.

    POST /check  {"user"}                              -> {"allowed", "used", "limit", "resets_in"}
    POST /report {"user", "input_tokens", "output_tokens"}  -> the same, after adding them
    POST /reset                                        -> forgets everyone
    GET  /usage                                        -> every user, as JSON
    GET  /events                                       -> the same, as SSE, on every change and every second
    GET  /                                             -> the board
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any

from common import JsonHandler, serve

LIMIT = int(os.environ.get("QUOTA_TOKENS", "600"))
WINDOW = int(os.environ.get("QUOTA_WINDOW_SECS", "60"))
PAGE = Path(__file__).with_name("quota_board.html").read_bytes()


class Ledger:
    def __init__(self) -> None:
        self.lock = threading.Condition()
        self.users: dict[str, dict[str, Any]] = {}
        self.version = 0

    def _entry(self, user: str, now: float) -> dict[str, Any]:
        e = self.users.get(user)
        if e is None or now - e["window_start"] >= WINDOW:
            e = {"used": 0, "requests": 0, "refused": 0, "window_start": now}
            self.users[user] = e
        return e

    def check(self, user: str) -> dict[str, Any]:
        with self.lock:
            now = time.time()
            e = self._entry(user, now)
            allowed = e["used"] < LIMIT
            e["requests" if allowed else "refused"] += 1
            self._changed()
            return self._view(user, e, now, allowed)

    def report(self, user: str, tokens: int) -> dict[str, Any]:
        with self.lock:
            now = time.time()
            e = self._entry(user, now)
            e["used"] += tokens
            self._changed()
            return self._view(user, e, now, e["used"] < LIMIT)

    def reset(self) -> None:
        with self.lock:
            self.users.clear()
            self._changed()

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            now = time.time()
            rows = [self._view(u, e, now, e["used"] < LIMIT) for u, e in sorted(self.users.items())
                    if now - e["window_start"] < WINDOW]
            return {"limit": LIMIT, "window": WINDOW, "users": rows, "version": self.version}

    def wait(self, version: int, timeout: float) -> None:
        with self.lock:
            self.lock.wait_for(lambda: self.version != version, timeout)

    def _changed(self) -> None:
        self.version += 1
        self.lock.notify_all()

    def _view(self, user: str, e: dict[str, Any], now: float, allowed: bool) -> dict[str, Any]:
        return {
            "user": user,
            "allowed": allowed,
            "used": e["used"],
            "limit": LIMIT,
            "requests": e["requests"],
            "refused": e["refused"],
            "resets_in": max(0, int(e["window_start"] + WINDOW - now)),
        }


LEDGER = Ledger()


class Handler(JsonHandler):
    log = logging.getLogger("quota-board")

    def do_POST_check(self) -> None:  # noqa: N802
        user = str(self.read_json().get("user", ""))
        view = LEDGER.check(user)
        self.log.info("%s: %s, %d/%d used", user, "allowed" if view["allowed"] else "REFUSED", view["used"], LIMIT)
        self.send_json(200, view)

    def do_POST_report(self) -> None:  # noqa: N802
        body = self.read_json()
        user = str(body.get("user", ""))
        tokens = int(body.get("input_tokens", 0)) + int(body.get("output_tokens", 0))
        view = LEDGER.report(user, tokens)
        self.log.info("%s: +%d tokens, %d/%d used", user, tokens, view["used"], LIMIT)
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
        version = -1
        try:
            while True:
                snap = LEDGER.snapshot()
                version = snap["version"]
                data = f"data: {json.dumps(snap)}\n\n".encode()
                self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
                self.wfile.flush()
                LEDGER.wait(version, timeout=1.0)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        if not self.path.startswith(("/events", "/usage")):
            super().log_message(format, *args)


if __name__ == "__main__":
    Handler.log.info("%d tokens per user per %ds window", LIMIT, WINDOW)
    serve(Handler, 8090)
