"""A mock central auth service for the auth-gate addon.

`POST /introspect {"token": ...}` answers `200 {"user": ...}` for a known
credential and `401` for any other. The credentials come from AUTH_TOKENS,
`token=user` pairs separated by commas. A real service would validate a
signed token (an OIDC JWT, an STS web identity token) here; the addon is
the same either way.
"""

from __future__ import annotations

import logging
import os

from common import JsonHandler, serve

DEFAULT_TOKENS = "alice-secret=alice,bob-secret=bob"


def parse_tokens(spec: str) -> dict[str, str]:
    pairs = (p.split("=", 1) for p in spec.split(",") if p.strip())
    return {token.strip(): user.strip() for token, user in pairs}


TOKENS = parse_tokens(os.environ.get("AUTH_TOKENS", DEFAULT_TOKENS))


class Handler(JsonHandler):
    log = logging.getLogger("auth-service")

    def do_POST_introspect(self) -> None:  # noqa: N802
        token = self.read_json().get("token")
        user = TOKENS.get(token) if isinstance(token, str) else None
        if user is None:
            self.log.info("refused a credential")
            self.send_json(401, {"error": "unknown credential"})
        else:
            self.log.info("credential of %s accepted", user)
            self.send_json(200, {"user": user})


if __name__ == "__main__":
    Handler.log.info("users: %s", ", ".join(sorted(TOKENS.values())))
    serve(Handler, 9100)
