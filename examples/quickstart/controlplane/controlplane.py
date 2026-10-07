"""A minimal roxy control plane: the server side of the node protocol
(spec/node-protocol/v1/openapi.yaml), enough to run the quickstart's roxy
in node mode.

It enrols a node against the fixed token in ENROL_TOKEN, signing the node's
CSR with a CA it keeps in DATA_DIR, and serves the lease: the quickstart's
roxy.yaml with its `env` secrets turned into `lease: true` entries and the
values taken from this process's environment. Flow batches are printed to
stdout, one event per line. A node id listed in DATA_DIR/revoked gets 410.

It is not a reference for everything a server should check: the token is
reusable, a flow batch's `lease_id` is accepted whatever it says, and the
gunzipped request body is not bounded.
"""

import datetime as dt
import hashlib
import hmac
import json
import os
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

NODE_URI_PREFIX = "urn:roxy:node:"
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


class Ca:
    """One CA for the server certificate and every node certificate, kept
    in `data_dir` so a restart recognises the nodes it enrolled."""

    def __init__(self, data_dir):
        key_path, cert_path = data_dir / "ca.key", data_dir / "ca.pem"
        if key_path.exists():
            self.key = serialization.load_pem_private_key(key_path.read_bytes(), None)
            self.cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            return
        self.key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "roxy quickstart control plane CA")])
        now = utcnow()
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ), critical=True)
            .sign(self.key, hashes.SHA256())
        )
        key_path.write_bytes(self.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
        ))
        key_path.chmod(0o600)
        cert_path.write_bytes(self.pem)

    @property
    def pem(self):
        return self.cert.public_bytes(serialization.Encoding.PEM)

    def _issue(self, public_key, subject, san, eku, lifetime):
        now = utcnow()
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + lifetime)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
            .sign(self.key, hashes.SHA256())
        )

    def server_certificate(self, hostnames):
        """A fresh server key and certificate for `hostnames`, as PEM."""
        key = ec.generate_private_key(ec.SECP256R1())
        cert = self._issue(
            key.public_key(),
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0])]),
            [x509.DNSName(h) for h in hostnames],
            ExtendedKeyUsageOID.SERVER_AUTH,
            dt.timedelta(days=365),
        )
        return (
            cert.public_bytes(serialization.Encoding.PEM)
            + key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
            )
        )

    def node_certificate(self, csr_pem, node_id, lifetime):
        """Signs the key in `csr_pem` as `node_id`. The CSR's subject and
        extensions are ignored; its signature must verify."""
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode())
        except (ValueError, TypeError) as e:
            raise ApiError(400, "bad_csr", f"csr does not parse: {e}") from None
        if not csr.is_signature_valid:
            raise ApiError(400, "bad_csr", "csr signature does not verify")
        return self._issue(
            csr.public_key(),
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id)]),
            [x509.UniformResourceIdentifier(NODE_URI_PREFIX + node_id)],
            ExtendedKeyUsageOID.CLIENT_AUTH,
            lifetime,
        )


def node_id_from(cert_der):
    """The node id named by a client certificate's URI SAN, or None."""
    cert = x509.load_der_x509_certificate(cert_der)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return None
    for uri in san.get_values_for_type(x509.UniformResourceIdentifier):
        if uri.startswith(NODE_URI_PREFIX):
            return uri[len(NODE_URI_PREFIX):]
    return None


class ControlPlane:
    """The protocol's state and decisions, independent of the HTTP layer."""

    def __init__(self, data_dir, config_path, environ):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.config_path = Path(config_path)
        self.environ = environ
        # The token: a file (a compose secret) or the environment.
        token_file = environ.get("ENROL_TOKEN_FILE")
        self.token = Path(token_file).read_text().strip() if token_file else environ["ENROL_TOKEN"]
        self.lease_valid = int(environ["LEASE_VALID_SECONDS"])
        self.cert_lifetime = dt.timedelta(seconds=int(environ["NODE_CERT_SECONDS"]))
        self.ca = Ca(self.data_dir)
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
        csr = body.get("csr")
        if not isinstance(csr, str):
            raise ApiError(400, "bad_request", "csr must be a PEM string")
        cert = self.ca.node_certificate(csr, node_id, self.cert_lifetime)
        return {
            "node_id": node_id,
            "certificate_chain": cert.public_bytes(serialization.Encoding.PEM).decode(),
            "not_after": cert.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "renew_after_seconds": max(1, int(self.cert_lifetime.total_seconds()) // 2),
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
        config, secrets = self.policy()
        digest = hashlib.sha256(config.encode() + json.dumps(secrets, sort_keys=True).encode()).hexdigest()
        return {
            "lease_id": "lease-" + digest[:16],
            "valid_for_seconds": self.lease_valid,
            "refresh_after_seconds": max(1, self.lease_valid // 4),
            "config": config,
            "secrets": secrets,
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
        secrets = {}
        for name, source in (doc.get("secrets") or {}).items():
            if isinstance(source, dict) and "env" in source:
                secrets[name] = self.environ[source["env"]]
                doc["secrets"][name] = {"lease": True}
        return yaml.safe_dump(doc, sort_keys=False), secrets

    # -- flows --

    def flows(self, node_id, batch):
        self.check_revoked(node_id)
        if batch.get("node_id") != node_id:
            raise ApiError(400, "node_mismatch", "node_id does not match the certificate")
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
                auth = self.headers.get("authorization", "")
                token = auth[len("Bearer "):] if auth.startswith("Bearer ") else None
                answer = cp.enrol(token, body)
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

    def node_id(self):
        der = self.request.getpeercert(binary_form=True)
        node_id = node_id_from(der) if der else None
        if node_id is None:
            raise ApiError(401, "unrecognised", "no node certificate presented")
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
        chain = cp.data_dir / "server.pem"
        chain.write_bytes(cp.ca.server_certificate(hostnames))
        self.tls.load_cert_chain(chain)
        # Enrolment arrives without a certificate, so one is asked for, not
        # required; the handlers answer 401 where one is needed. A presented
        # certificate must chain to the CA or the handshake fails.
        self.tls.load_verify_locations(cadata=cp.ca.pem.decode())
        self.tls.verify_mode = ssl.CERT_OPTIONAL

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
    Path(os.environ["CA_OUT"]).write_bytes(cp.ca.pem)
    hostnames = os.environ.get("HOSTNAMES", "controlplane,localhost").split(",")
    port = int(os.environ.get("PORT", "8443"))
    server = Server(("0.0.0.0", port), cp, hostnames)
    print(f"listening on :{port}; lease valid {cp.lease_valid}s; revoke with: echo <node_id> >> {cp.data_dir}/revoked", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
