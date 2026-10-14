"""A minimal roxy control plane: the server side of the node protocol
(spec/node-protocol/v1/openapi.yaml), enough to run the quickstart's roxy
in node mode.

It enrols a node against the fixed token read from the file named by
ENROL_TOKEN_FILE, issuing it a node token it keeps hashed in DATA_DIR, and
serves the lease: the quickstart's roxy.yaml with its `env` secrets turned
into `lease: true` entries and the values taken from this process's
environment. Flow batches are printed to stdout, one event per line. A node
id listed in DATA_DIR/revoked gets 410.

It is not a reference for everything a server should check: the enrolment
token is reusable and a flow batch's `lease_id` is accepted whatever it
says.
"""

import datetime as dt
import hashlib
import hmac
import json
import os
import secrets
import ssl
import sys
import threading
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

PROTOCOL_VERSION = 1
# A request body, on the wire and once inflated. The lease sets
# batch_max_bytes well below this; the rest of the protocol's bodies are small.
MAX_BODY = 1024 * 1024


class ApiError(Exception):
    """A non-2xx answer: status plus the `Error` body."""

    def __init__(self, status, code, message, missing=None):
        super().__init__(message)
        self.status = status
        self.body = {"error": code, "message": message}
        if missing:
            self.body["missing"] = missing


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def rfc3339(when):
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def write_private(path, data):
    """Writes secret material readable by its owner alone, from creation on,
    whatever the umask or the mode of a file already there. The write goes
    through a temporary file in the same directory and a rename, so a crash
    leaves the old file or the new one, never a partial one."""
    path = Path(path)
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    with open(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def server_certificate(path, hostnames):
    """The server's self-signed certificate and key as one PEM file at
    `path`, created on first use and kept so a restart presents the same
    certificate roxy was told to trust. Returns the certificate's PEM."""
    if path.exists():
        os.chmod(path, 0o600)
        return x509.load_pem_x509_certificate(path.read_bytes()).public_bytes(serialization.Encoding.PEM)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0])])
    now = utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(h) for h in hostnames]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    write_private(path, pem + key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    ))
    return pem


class Tokens:
    """The node tokens issued, by SHA-256, each to its node id and expiry,
    in DATA_DIR/tokens.json so a restart recognises the nodes it enrolled.
    A renewed token sits beside the one it replaces until that expires."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.issued = json.loads(path.read_text()) if path.exists() else {}

    @staticmethod
    def digest(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def issue(self, node_id, lifetime):
        token = "nt1-" + secrets.token_hex(32)
        not_after = utcnow() + lifetime
        with self.lock:
            self.issued = {d: t for d, t in self.issued.items()
                           if dt.datetime.fromisoformat(t["not_after"]) > utcnow()}
            self.issued[self.digest(token)] = {"node_id": node_id, "not_after": rfc3339(not_after)}
            write_private(self.path, json.dumps(self.issued, indent=1).encode())
        return token, not_after

    def node_id(self, token):
        """The node a token names, or None for one never issued or expired."""
        if token is None:
            return None
        with self.lock:
            entry = self.issued.get(self.digest(token))
        if entry is None or dt.datetime.fromisoformat(entry["not_after"]) <= utcnow():
            return None
        return entry["node_id"]


class ControlPlane:
    """The protocol's state and decisions, independent of the HTTP layer."""

    def __init__(self, data_dir, config_path, environ):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.config_path = Path(config_path)
        self.environ = environ
        # The token comes from a file (a compose secret), never the environment.
        self.token = Path(environ["ENROL_TOKEN_FILE"]).read_text().strip()
        self.lease_valid = int(environ["LEASE_VALID_SECONDS"])
        self.token_lifetime = dt.timedelta(seconds=int(environ["NODE_TOKEN_SECONDS"]))
        self.tokens = Tokens(self.data_dir / "tokens.json")
        self.lock = threading.Lock()
        self.seen = {}  # node id -> set of flow seqs stored
        self.acked = {}  # node id -> highest seq with no gap below it since the first batch

    # -- enrolment and renewal --

    def enrol(self, token, body):
        # The token is reusable: roxy's state dir is tmpfs, so every `compose up`
        # re-enrols. Reuse policy is the control plane's; single-use is the
        # usual choice.
        if token is None or not hmac.compare_digest(token.encode(), self.token.encode()):
            raise ApiError(401, "invalid_token", "enrolment token not recognised")
        node_id = "node-" + os.urandom(3).hex()
        print(f"enrolled {node_id}", flush=True)
        return self.issue(node_id, body)

    def renew(self, node_id, body):
        self.check_revoked(node_id)
        return self.issue(node_id, body)

    def issue(self, node_id, body):
        self.check_version(body)
        token, not_after = self.tokens.issue(node_id, self.token_lifetime)
        return {
            "node_id": node_id,
            "token": token,
            "not_after": rfc3339(not_after),
            "renew_after_seconds": max(1, int(self.token_lifetime.total_seconds()) // 2),
        }

    def check_version(self, body):
        if body.get("protocol_version") != PROTOCOL_VERSION:
            raise ApiError(426, "unsupported", "this server speaks protocol version 1 only",
                           missing=[f"protocol_version:{PROTOCOL_VERSION}"])
        if not isinstance(body.get("roxy_version"), str) or not body["roxy_version"]:
            raise ApiError(400, "bad_request", "roxy_version must be a non-empty string")

    # -- the lease --

    def check_revoked(self, node_id):
        revoked = self.data_dir / "revoked"
        if revoked.exists() and node_id in revoked.read_text().split():
            raise ApiError(410, "revoked", f"{node_id} is revoked")

    def lease(self, node_id, body):
        self.check_revoked(node_id)
        self.check_version(body)
        if body.get("policy_state") not in ("none", "loaded", "expired"):
            raise ApiError(400, "bad_request", "policy_state must be none, loaded or expired")
        for field in ("lease_id", "uptime_seconds", "spooled_bytes"):
            if field not in body:
                raise ApiError(400, "bad_request", f"{field} is required")
        # Absent from nodes that predate the field.
        if not isinstance(body.get("seq_unreserved", False), bool):
            raise ApiError(400, "bad_request", "seq_unreserved must be a boolean")
        if body.get("seq_unreserved"):
            print(f"{node_id} is using flow seq values it has not persisted; a restart may reuse them",
                  file=sys.stderr, flush=True)
        config, secrets_ = self.policy()
        digest = hashlib.sha256(config.encode() + json.dumps(secrets_, sort_keys=True).encode()).hexdigest()
        return {
            "lease_id": "lease-" + digest[:16],
            "valid_for_seconds": self.lease_valid,
            "refresh_after_seconds": max(1, self.lease_valid // 4),
            "config": config,
            "secrets": secrets_,
            "state_epoch": "quickstart",
            "flow": {
                "ship": True,
                "batch_max_bytes": 65536,
                "flush_interval_seconds": 5,
                "spool_high_water_bytes": 8 * 1024 * 1024,
                "on_high_water": "spool",
            },
        }

    def policy(self):
        """roxy.yaml as the lease carries it: every `env` secret becomes a
        `lease: true` entry, with its value taken from this environment."""
        doc = yaml.safe_load(self.config_path.read_text())
        values = {}
        for name, source in (doc.get("secrets") or {}).items():
            if isinstance(source, dict) and "env" in source:
                values[name] = self.environ[source["env"]]
                doc["secrets"][name] = {"lease": True}
        return yaml.safe_dump(doc, sort_keys=False), values

    # -- flows --

    def flows(self, node_id, batch):
        self.check_revoked(node_id)
        if batch.get("node_id") != node_id:
            raise ApiError(400, "node_mismatch", "node_id does not match the token's")
        events = batch.get("events")
        if not isinstance(events, list) or not events:
            raise ApiError(400, "bad_request", "events must be a non-empty list")
        seqs = [e.get("seq") if isinstance(e, dict) else None for e in events]
        if seqs != list(range(batch.get("seq_first", -1), batch.get("seq_first", -1) + len(events))):
            raise ApiError(400, "bad_request", "events are not consecutive from seq_first")
        with self.lock:
            seen = self.seen.setdefault(node_id, set())
            for event in events:
                if event["seq"] not in seen:
                    seen.add(event["seq"])
                    print(f"{node_id} {json.dumps(event, separators=(',', ':'))}", flush=True)
            # A batch that arrives ahead of a missing one is kept but not
            # acknowledged, so the node re-sends from the gap. The server
            # does not know where a node's numbering began, so the first
            # batch it sees from a node sets the baseline.
            acked = self.acked.get(node_id, batch["seq_first"] - 1)
            while acked + 1 in seen:
                acked += 1
            self.acked[node_id] = acked
            return {"acked_through": acked}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "roxy-quickstart-controlplane"
    timeout = 30  # a connection that stops sending is dropped rather than held

    def setup(self):
        super().setup()
        self.request.do_handshake()

    def log_message(self, fmt, *args):  # one line per request on stderr is noise next to the flow lines
        pass

    def do_POST(self):
        cp = self.server.cp
        try:
            body = self.read_json()
            if self.path == "/roxy/v1/enrol":
                answer = cp.enrol(self.bearer(), body)
            elif self.path == "/roxy/v1/renew":
                answer = cp.renew(self.node_id(), body)
            elif self.path == "/roxy/v1/lease":
                answer = cp.lease(self.node_id(), body)
            elif self.path == "/roxy/v1/flows":
                answer = cp.flows(self.node_id(), body)
            else:
                raise ApiError(404, "not_found", f"no such operation: {self.path}")
            self.reply(200, answer)
        except ApiError as e:
            self.reply(e.status, e.body)
        except Exception as e:  # noqa: BLE001 - the node sees a 500 and retries
            print(f"error handling {self.path}: {e!r}", file=sys.stderr, flush=True)
            self.reply(500, {"error": "internal", "message": repr(e)})

    def bearer(self):
        auth = self.headers.get("authorization", "")
        return auth[len("Bearer "):] if auth.startswith("Bearer ") else None

    def node_id(self):
        node_id = self.server.cp.tokens.node_id(self.bearer())
        if node_id is None:
            raise ApiError(401, "unrecognised", "node token not recognised")
        return node_id

    def read_json(self):
        length = int(self.headers.get("content-length") or 0)
        if length > MAX_BODY:
            raise ApiError(413, "too_large", f"body exceeds {MAX_BODY} bytes")
        raw = self.rfile.read(length)
        if self.headers.get("content-encoding") == "gzip":
            inflate = zlib.decompressobj(zlib.MAX_WBITS | 16)
            raw = inflate.decompress(raw, MAX_BODY + 1)
            if len(raw) > MAX_BODY or inflate.unconsumed_tail:
                raise ApiError(413, "too_large", f"body inflates past {MAX_BODY} bytes")
        try:
            body = json.loads(raw)
        except ValueError as e:
            raise ApiError(400, "bad_request", f"body is not JSON: {e}") from None
        if not isinstance(body, dict):
            raise ApiError(400, "bad_request", "body must be a JSON object")
        return body

    def reply(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, cp, hostnames):
        super().__init__(address, Handler)
        self.cp = cp
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls.minimum_version = ssl.TLSVersion.TLSv1_3
        self.certificate_pem = server_certificate(cp.data_dir / "server.pem", hostnames)
        self.tls.load_cert_chain(cp.data_dir / "server.pem")

    def get_request(self):
        sock, addr = super().get_request()
        return self.tls.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        # A bare TCP connect (the compose healthcheck) ends in EOF mid-handshake.
        if not isinstance(exc, (ssl.SSLEOFError, ConnectionError)):
            print(f"{client_address[0]}: {exc!r}", file=sys.stderr, flush=True)


def main():
    cp = ControlPlane(os.environ.get("DATA_DIR", "/data"), os.environ["ROXY_CONFIG"], os.environ)
    hostnames = os.environ.get("HOSTNAMES", "controlplane,localhost").split(",")
    port = int(os.environ.get("PORT", "8443"))
    server = Server(("0.0.0.0", port), cp, hostnames)
    # What roxy pins with --control-plane-ca: this server's own certificate.
    Path(os.environ["CA_OUT"]).write_bytes(server.certificate_pem)
    print(f"listening on :{port}; lease valid {cp.lease_valid}s; revoke with: echo <node_id> >> {cp.data_dir}/revoked", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
