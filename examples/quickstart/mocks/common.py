"""What the mock servers share: a threaded JSON HTTP server with a health
endpoint, and Anthropic-shaped error bodies."""

from __future__ import annotations

import json
import logging
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")


class JsonHandler(BaseHTTPRequestHandler):
    """Dispatches to `do_<METHOD>_<route>` methods; see the subclasses."""

    protocol_version = "HTTP/1.1"
    server_version = "mock/0"
    log = logging.getLogger("mock")

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        self.log.info("%s %s", self.address_string(), format % args)

    def read_body(self) -> bytes:
        """The request body, with or without a known length: a body that
        passed through a roxy addon arrives chunked."""
        if "chunked" in (self.headers.get("transfer-encoding") or "").lower():
            body = b""
            while True:
                size = int(self.rfile.readline().split(b";", 1)[0].strip() or b"0", 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass  # trailers
                    return body
                body += self.rfile.read(size)
                self.rfile.readline()  # the CRLF after the chunk
        length = int(self.headers.get("content-length") or 0)
        return self.rfile.read(length) if length else b""

    def read_json(self) -> Any:
        raw = self.read_body()
        return json.loads(raw) if raw else {}

    def send_json(self, status: int, body: Any, extra: dict[str, str] | None = None) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def send_error_json(self, status: int, kind: str, message: str) -> None:
        self.send_json(status, {"type": "error", "error": {"type": kind, "message": message}})

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        if self.path == "/healthz":
            self.send_json(200, {"ok": True})
        else:
            self.route("GET")

    def do_POST(self) -> None:  # noqa: N802
        self.route("POST")

    def route(self, method: str) -> None:
        name = f"do_{method}_{self.path.split('?', 1)[0].strip('/').replace('/', '_') or 'index'}"
        handler = getattr(self, name, None)
        if handler is None:
            self.send_error_json(404, "not_found_error", f"no route for {method} {self.path}")
        else:
            handler()


def serve(handler: type[JsonHandler], default_port: int) -> None:
    port = int(os.environ.get("PORT", default_port))
    server = ThreadingHTTPServer(("0.0.0.0", port), handler)
    handler.log.info("listening on :%d", port)
    server.serve_forever()
