"""A minimal client: talk to the model through roxy, as a named user.

    python chat.py --user alice --repeat 6

Each call is one `POST /v1/messages`, streamed, with the user's credential
in `x-roxy-auth` (the header the auth-gate addon reads) and a Bash tool on
offer so the scripted model's tool calls have something to call. The API
key is a placeholder: roxy puts the real one on the request. The proxy is
taken from HTTP_PROXY / HTTPS_PROXY, as any HTTP client would.

    ANTHROPIC_BASE_URL   the model API (default http://fake-model:8080)

traffic.py drives this same code on a schedule for several users.
"""

from __future__ import annotations

import argparse
import os
import sys
import uuid

import anthropic

USERS = {"alice": "alice-secret", "bob": "bob-secret"}

BASH_TOOL = {
    "name": "Bash",
    "description": "Run a shell command",
    "input_schema": {
        "type": "object",
        "properties": {"command": {"type": "string"}},
        "required": ["command"],
    },
}


def make_client(user: str, secret: str) -> anthropic.Anthropic:
    return anthropic.Anthropic(
        base_url=os.environ.get("ANTHROPIC_BASE_URL", "http://fake-model:8080"),
        api_key="placeholder-roxy-injects-the-real-key",
        default_headers={
            "x-roxy-auth": secret,
            # Groups this client's calls into one sample in Inspect View.
            "x-claude-code-session-id": f"{user}-{uuid.uuid4().hex[:8]}",
        },
        max_retries=0,  # show a 429 rather than quietly retrying it
    )


def call(client: anthropic.Anthropic, tag: str, prompt: str, *, whole: bool = False, echo: bool = True) -> bool:
    """One model call. Prints what came back, one line per thing, and
    returns whether it succeeded."""
    try:
        if whole:
            msg = client.messages.create(model="fake-model", max_tokens=512, tools=[BASH_TOOL],
                                         messages=[{"role": "user", "content": prompt}])
        else:
            with client.messages.stream(model="fake-model", max_tokens=512, tools=[BASH_TOOL],
                                        messages=[{"role": "user", "content": prompt}]) as stream:
                if echo:
                    print(f"{tag} ", end="", flush=True)
                    for text in stream.text_stream:
                        print(text, end="", flush=True)
                    print()
                else:
                    stream.until_done()
                msg = stream.get_final_message()
    except anthropic.APIStatusError as e:
        print(f"{tag} {e.status_code} {type(e).__name__}: {detail(e)}", flush=True)
        return False
    except anthropic.APIConnectionError as e:
        print(f"{tag} connection error: {e}", flush=True)
        return False
    if not echo:
        text = " ".join(b.text for b in msg.content if b.type == "text")
        print(f"{tag} {text[:160]}{'…' if len(text) > 160 else ''}", flush=True)
    for block in msg.content:
        if block.type == "tool_use":
            print(f"{tag} tool call: {block.name} {block.input}", flush=True)
    print(f"{tag} 200 stop={msg.stop_reason} in={msg.usage.input_tokens} out={msg.usage.output_tokens}", flush=True)
    return True


def detail(e: anthropic.APIStatusError) -> str:
    """The message in an error body: Anthropic's `error.message`, or roxy's `error`."""
    error = e.body.get("error") if isinstance(e.body, dict) else None
    if isinstance(error, dict):
        return str(error.get("message", ""))
    return str(error) if error else e.message


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--user", default="alice", help="alice or bob (default alice), or any name with --secret")
    ap.add_argument("--secret", help="the credential to send (default: the user's)")
    ap.add_argument("--repeat", type=int, default=1, help="how many calls to make")
    ap.add_argument("--prompt", default="What can you do?")
    ap.add_argument("--whole", action="store_true", help="ask for a whole response instead of a stream")
    args = ap.parse_args()

    secret = args.secret or USERS.get(args.user)
    if secret is None:
        ap.error(f"no credential for {args.user!r}; pass --secret")
    client = make_client(args.user, secret)
    ok = [call(client, f"[{args.user} #{i}]", args.prompt, whole=args.whole) for i in range(1, args.repeat + 1)]
    return 0 if all(ok) else 1


if __name__ == "__main__":
    sys.exit(main())
