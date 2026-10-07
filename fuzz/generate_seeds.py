#!/usr/bin/env python3
"""Generates the seed corpora in fuzz/seeds/<target>/ (git-ignored) from
the project's own test vectors, so the seeds never go stale. Run before
fuzzing; the Fuzz workflow does. From anywhere:

    python3 fuzz/generate_seeds.py

Sources:
- h1_request, h1_chunked: the smuggling corpus, crates/roxy-http/tests/corpus
  (each case's role and flags are encoded in the leading config byte, see
  fuzz/src/lib.rs `flags` / `role`);
- url: request targets from that corpus plus a few path / query shapes;
- client_hello, client_hello_rustls: real ClientHellos from Python's ssl
  module (with and without SNI / ALPN, TLS 1.2 and 1.3);
- rule_compile: every `when:` expression in examples/, the roxy config test
  fixtures and crates/roxy-rules;
- h2map, rule_eval: structured inputs, seeded with a few byte patterns
  (libFuzzer finds the structure quickly);
- content_coding: a small stream in each coding, a stacked pair, and gzip
  with every optional header field.
- ws_frame: the RFC 6455 example frames and a fragmented, masked message
  with a ping in the middle.
"""

import gzip
import hashlib
import pathlib
import re
import ssl
import zlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
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
                elif key == "role" and value.split()[0] == "origin":
                    # roxy_fuzz::role: 1 = an http listener
                    cfg |= 1 << 5
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
    files = (
        list((ROOT / "examples").rglob("*.yaml"))
        + list((ROOT / "crates/roxy/tests/fixtures").rglob("*.yaml"))
        + list((ROOT / "crates/roxy-rules").rglob("*.rs"))
    )
    seen = set()
    for f in files:
        for m in re.finditer(r"when: (.+)", f.read_text()):
            expr = m.group(1).strip().rstrip("\\n\"").strip()
            if expr and expr not in seen:
                seen.add(expr)
                yield expr


# Small valid streams for the codings Python's standard library lacks
# (made with the `brotli` and `ruzstd` crates).
BR_SEED = bytes.fromhex(
    "1b3a00889c09762c643a88a7982b23547aca2dcd35489e8ec22aca6ab2b2373ce09003e6b725916739540e5a23302da8ea184a3c2b97e8632027e9c800"
)
ZSTD_SEED = bytes.fromhex(
    "28b52ffd0438d90100726f787920636f6e74656e7420636f64696e6720736565643a20424547494e2050524956415445204b455920726f787920726f787920726f78790a0b204ccb"
)


def coding_seeds():
    """(name, config byte, encoded body) for content_coding: one stream per
    coding, a stacked pair, and gzip with every optional header field."""
    text = b"roxy content coding seed: BEGIN PRIVATE KEY roxy roxy roxy\n"
    gz = gzip.compress(text)
    yield "gzip", 0, gz
    yield "gzip_two_members", 0, gz + gzip.compress(b"second member")
    yield "deflate", 1, zlib.compress(text)
    yield "br", 2, BR_SEED
    yield "zstd", 3, ZSTD_SEED
    # deflate, then gzip on top: codings [deflate, gzip] = 1 | 4 | (0 << 3).
    yield "deflate_then_gzip", 1 | 4, gzip.compress(zlib.compress(text))
    # FTEXT | FHCRC | FEXTRA | FNAME | FCOMMENT, header CRC16 included.
    head = bytes([0x1F, 0x8B, 8, 0x1F, 0, 0, 0, 0, 0, 255]) + b"\x02\x00ab" + b"name\x00" + b"note\x00"
    head += (zlib.crc32(head) & 0xFFFF).to_bytes(2, "little")
    yield "gzip_all_fields", 0, head + gz[10:]
    yield "empty", 0, b""



def ws_frame(fin, opcode, payload, mask=None):
    b = bytes([(0x80 if fin else 0) | opcode])
    m = 0x80 if mask else 0
    n = len(payload)
    if n < 126:
        b += bytes([m | n])
    elif n < 1 << 16:
        b += bytes([m | 126]) + n.to_bytes(2, "big")
    else:
        b += bytes([m | 127]) + n.to_bytes(8, "big")
    if mask:
        b += mask + bytes(p ^ mask[i % 4] for i, p in enumerate(payload))
    else:
        b += payload
    return b


def ws_frames():
    """(name, config byte, frames): bit 0 of the config byte set = server
    frames; bits 4-5 = 3 picks the largest message limit."""
    key = b"\x37\xfa\x21\x3d"
    yield "hello_server", 0x31, ws_frame(True, 1, b"Hello")
    yield "hello_client", 0x30, ws_frame(True, 1, b"Hello", key)
    yield "fragmented_ping", 0x32, (ws_frame(False, 1, b"Hel", key) + ws_frame(True, 9, b"p", key)
                                    + ws_frame(True, 0, b"lo", key))
    yield "binary_256", 0x31, ws_frame(True, 2, bytes(range(256)))
    yield "close", 0x31, ws_frame(True, 8, b"\x03\xe8bye")


def main():
    for target in ("h1_request", "h1_chunked", "url", "client_hello", "client_hello_rustls", "rule_compile",
                   "h2map", "rule_eval", "ws_frame", "content_coding"):
        for old in (OUT / target).glob("*") if (OUT / target).is_dir() else []:
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
        for target in ("client_hello", "client_hello_rustls"):
            write(target, name, hello)
            write(target, name + "_trailing", hello + b"GET / HTTP/1.1\r\n")
    for i, expr in enumerate(when_expressions()):
        write("rule_compile", f"when{i}", expr.encode())
    for i, pat in enumerate([b"", b"\x00" * 64, b"\x01" * 64, bytes(range(256))]):
        write("h2map", f"pattern{i}", pat)
        write("rule_eval", f"pattern{i}", pat)
    for name, cfg, body in coding_seeds():
        for piece in (0, 7):
            write("content_coding", f"{name}_{piece}", bytes([cfg | piece << 5]) + body)
    for name, cfg, frames in ws_frames():
        write("ws_frame", name, bytes([cfg]) + frames)
    print(f"{n} corpus cases")


if __name__ == "__main__":
    main()
