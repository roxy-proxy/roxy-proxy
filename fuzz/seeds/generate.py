#!/usr/bin/env python3
"""Regenerates the seed corpora in fuzz/seeds/<target>/ from the project's
own test vectors. Run from the repository root:

    python3 fuzz/seeds/generate.py

Sources:
- h1_request, h1_chunked: the smuggling corpus, crates/roxy-http/tests/corpus
  (each case's role and flags are encoded in the leading config byte, see
  fuzz/src/lib.rs `flags` / `role`);
- url: request targets from that corpus plus a few path / query shapes;
- client_hello: real ClientHellos from Python's ssl module (with and
  without SNI / ALPN, TLS 1.2 and 1.3);
- rule_compile: every `when:` expression in examples/ and crates/roxy-rules;
- h2map, rule_eval: structured inputs, seeded with a few byte patterns
  (libFuzzer finds the structure quickly).
"""

import hashlib
import pathlib
import re
import ssl

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "fuzz" / "seeds"


def unescape(s: str) -> bytes:
    out = bytearray()
    i = 0
    b = s.encode()
    while i < len(b):
        if b[i] != ord("\\"):
            out.append(b[i])
            i += 1
            continue
        c = chr(b[i + 1])
        i += 2
        if c in "rnts0\\":
            out += {"r": b"\r", "n": b"\n", "t": b"\t", "s": b" ", "0": b"\0", "\\": b"\\"}[c]
        elif c == "x":
            out.append(int(b[i : i + 2], 16))
            i += 2
        elif c == "{":
            end = b.index(b"}", i)
            n, text = b[i:end].split(b":", 1)
            out += text * int(n)
            i = end + 1
        else:
            raise ValueError(f"unknown escape \\{c}")
    return bytes(out)


FLAG_BITS = {
    "allow_http10": 1,
    "allow_trailers": 2,
    "allow_chunk_extensions": 4,
    "allow_obs_text": 8,
    "allow_body_on_get": 16,
}


def corpus_cases():
    for path in sorted((ROOT / "crates/roxy-http/tests/corpus").glob("*.txt")):
        for block in re.split(r"^=== ", path.read_text(), flags=re.M)[1:]:
            name, rest = block.split("\n", 1)
            meta, raw = rest.split("\n---\n", 1)
            cfg = 0
            for line in meta.splitlines():
                key, _, value = line.partition(":")
                if key == "flags":
                    for f in value.split():
                        cfg |= FLAG_BITS[f]
                elif key == "role" and value.split()[0] == "tunnel":
                    # roxy_fuzz::role: 2 = https tunnel, 3 = http tunnel
                    cfg |= (2 if value.split()[1] == "https" else 3) << 5
            data = unescape("".join(raw.splitlines()))
            yield f"{path.stem}_{name.strip()}", cfg, data


def write(target: str, name: str, data: bytes):
    d = OUT / target
    d.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:60]
    (d / f"{safe}-{hashlib.sha1(data).hexdigest()[:8]}").write_bytes(data)


def client_hellos():
    for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
        for sni in (None, "example.com", "api.github.com"):
            for alpn in (None, ["h2", "http/1.1"]):
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.maximum_version = version
                if alpn:
                    ctx.set_alpn_protocols(alpn)
                incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
                conn = ctx.wrap_bio(incoming, outgoing, server_hostname=sni)
                try:
                    conn.do_handshake()
                except ssl.SSLWantReadError:
                    pass
                yield f"{version.name}_{sni}_{bool(alpn)}", outgoing.read()


def when_expressions():
    files = list((ROOT / "examples").rglob("*.yaml")) + list(
        (ROOT / "crates/roxy-rules").rglob("*.rs")
    )
    seen = set()
    for f in files:
        for m in re.finditer(r"when: (.+)", f.read_text()):
            expr = m.group(1).strip().rstrip("\\n\"").strip()
            if expr and expr not in seen:
                seen.add(expr)
                yield expr


def main():
    for target in ("h1_request", "h1_chunked", "url", "client_hello", "rule_compile", "h2map", "rule_eval"):
        for old in (OUT / target).glob("*"):
            old.unlink()
    n = 0
    for name, cfg, data in corpus_cases():
        write("h1_request", name, bytes([cfg]) + data)
        head, sep, body = data.partition(b"\r\n\r\n")
        if sep and b"chunked" in head.lower():
            write("h1_chunked", name, bytes([cfg & 3]) + body)
        target = head.split(b"\r\n", 1)[0].split(b" ")
        if len(target) >= 2:
            write("url", name, target[1])
        n += 1
    for t in [b"/", b"/a/./b/../c", b"/%2e%2E/x", b"/a%2Fb?x=1&y", b"http://Example.COM:80/a?b",
              b"https://[::1]:8443/p", b"example.com:443", b"xn--bcher-kva.example"]:
        write("url", "shape", t)
    for name, hello in client_hellos():
        write("client_hello", name, hello)
        write("client_hello", name + "_trailing", hello + b"GET / HTTP/1.1\r\n")
    for i, expr in enumerate(when_expressions()):
        write("rule_compile", f"when{i}", expr.encode())
    for i, pat in enumerate([b"", b"\x00" * 64, b"\x01" * 64, bytes(range(256))]):
        write("h2map", f"pattern{i}", pat)
        write("rule_eval", f"pattern{i}", pat)
    print(f"{n} corpus cases")


if __name__ == "__main__":
    main()
