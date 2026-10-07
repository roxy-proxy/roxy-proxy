"""The control plane's answers match the node protocol's schemas and the
decisions the quickstart relies on: enrolment issues a certificate naming
the node, the lease carries roxy.yaml with its secrets moved into the map,
a revoked node gets 410, and flow batches are deduplicated."""

import http.client
import json
import ssl
import sys
import threading
from pathlib import Path

import jsonschema
import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from controlplane import ApiError, ControlPlane, Server  # noqa: E402

REPO = Path(__file__).resolve().parents[4]
OPENAPI = yaml.safe_load((REPO / "spec/node-protocol/v1/openapi.yaml").read_text())

ROXY_YAML = """\
version: 1
listeners:
  - name: proxy
    bind: 0.0.0.0:3128
secrets:
  model_key: { env: MODEL_API_KEY }
rules: []
"""


def valid(schema, body):
    """Asserts `body` validates against `#/components/schemas/<schema>`."""
    root = {"$ref": f"#/components/schemas/{schema}", "components": OPENAPI["components"]}
    jsonschema.Draft202012Validator(root).validate(body)


def csr_pem(key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "roxy")]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode(), key


def enrol_body(csr, protocol_version=1):
    return {"csr": csr, "roxy_version": "0.0.0-test", "protocol_version": protocol_version}


@pytest.fixture
def cp(tmp_path):
    config = tmp_path / "roxy.yaml"
    config.write_text(ROXY_YAML)
    env = {"ENROL_TOKEN": "tok", "MODEL_API_KEY": "k1", "LEASE_VALID_SECONDS": "20", "NODE_CERT_SECONDS": "600"}
    return ControlPlane(tmp_path / "data", config, env)


def expect(status, code, fn):
    with pytest.raises(ApiError) as e:
        fn()
    assert (e.value.status, e.value.body["error"]) == (status, code)
    valid("Error", e.value.body)


def test_enrol_issues_a_certificate_naming_the_node(cp):
    csr, key = csr_pem()
    res = cp.enrol("tok", enrol_body(csr))
    valid("EnrolResponse", res)
    cert = x509.load_pem_x509_certificate(res["certificate_chain"].encode())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.UniformResourceIdentifier) == [f"urn:roxy:node:{res['node_id']}"]
    assert cert.public_key() == key.public_key()
    assert res["renew_after_seconds"] < 600


def test_enrol_refuses_a_wrong_token_a_forged_csr_and_an_unknown_protocol(cp):
    csr, _ = csr_pem()
    expect(401, "invalid_token", lambda: cp.enrol("nope", enrol_body(csr)))
    expect(401, "invalid_token", lambda: cp.enrol(None, enrol_body(csr)))
    # A CSR whose key was swapped after signing no longer proves possession.
    forged = csr.replace("REQUEST-----\n", "REQUEST-----\nA", 1)
    expect(400, "bad_csr", lambda: cp.enrol("tok", enrol_body(forged)))
    expect(426, "unsupported", lambda: cp.enrol("tok", enrol_body(csr, protocol_version=2)))


def test_renew_keeps_the_node_id(cp):
    csr, _ = csr_pem()
    first = cp.enrol("tok", enrol_body(csr))
    again = cp.renew(first["node_id"], enrol_body(csr_pem()[0]))
    valid("EnrolResponse", again)
    assert again["node_id"] == first["node_id"]
    assert again["certificate_chain"] != first["certificate_chain"]


STATE = {"lease_id": None, "roxy_version": "0.0.0", "protocol_version": 1,
         "uptime_seconds": 0, "policy_state": "none", "spooled_bytes": 0}


def test_lease_carries_the_config_with_secrets_moved_into_the_map(cp):
    valid("NodeState", STATE)
    lease = cp.lease("node-1", STATE)
    valid("Lease", lease)
    doc = yaml.safe_load(lease["config"])
    assert doc["secrets"] == {"model_key": {"lease": True}}
    assert doc["listeners"] == [{"name": "proxy", "bind": "0.0.0.0:3128"}]
    assert lease["secrets"] == {"model_key": "k1"}
    assert lease["valid_for_seconds"] == 20
    assert lease["refresh_after_seconds"] < lease["valid_for_seconds"]
    assert "interception_ca" not in lease


def test_lease_id_changes_only_when_config_or_secrets_do(cp):
    state = STATE
    a = cp.lease("node-1", state)["lease_id"]
    assert cp.lease("node-1", state)["lease_id"] == a
    cp.environ["MODEL_API_KEY"] = "k2"
    b = cp.lease("node-1", state)["lease_id"]
    assert b != a
    cp.config_path.write_text(ROXY_YAML.replace("3128", "3129"))
    assert cp.lease("node-1", state)["lease_id"] not in (a, b)


def test_a_revoked_node_gets_410_everywhere(cp):
    state = STATE
    cp.lease("node-1", state)
    (cp.data_dir / "revoked").write_text("node-0\nnode-1\n")
    expect(410, "revoked", lambda: cp.lease("node-1", state))
    expect(410, "revoked", lambda: cp.renew("node-1", enrol_body(csr_pem()[0])))
    expect(410, "revoked", lambda: cp.flows("node-1", batch("node-1", 1, 1)))
    cp.lease("node-2", state)


def test_a_malformed_node_state_is_400(cp):
    expect(400, "bad_request", lambda: cp.lease("node-1", {**STATE, "policy_state": "gone"}))
    expect(400, "bad_request", lambda: cp.lease("node-1", {k: v for k, v in STATE.items() if k != "lease_id"}))
    expect(426, "unsupported", lambda: cp.lease("node-1", {**STATE, "protocol_version": 2}))


def batch(node_id, first, count, lease_id="lease-x"):
    events = [{"seq": s, "ts": "2026-10-06T10:00:00Z", "event": "request"} for s in range(first, first + count)]
    b = {"node_id": node_id, "lease_id": lease_id, "seq_first": first, "events": events}
    valid("FlowBatch", b)
    return b


def test_flows_are_deduplicated_and_acked_through_the_highest_contiguous_seq(cp, capsys):
    ack = cp.flows("node-1", batch("node-1", 10, 3))
    valid("FlowAck", ack)
    assert ack == {"acked_through": 12}
    assert cp.flows("node-1", batch("node-1", 10, 3)) == {"acked_through": 12}
    assert cp.flows("node-1", batch("node-1", 12, 2)) == {"acked_through": 13}
    # A batch past a gap is stored but the ack stays below the gap until it is filled.
    assert cp.flows("node-1", batch("node-1", 20, 2)) == {"acked_through": 13}
    assert cp.flows("node-1", batch("node-1", 14, 6)) == {"acked_through": 21}
    lines = [l for l in capsys.readouterr().out.splitlines() if l.startswith("node-1 ")]
    assert [json.loads(l.split(" ", 1)[1])["seq"] for l in lines] == [10, 11, 12, 13, 20, 21, *range(14, 20)]
    expect(400, "node_mismatch", lambda: cp.flows("node-1", batch("node-2", 1, 1)))
    gap = batch("node-1", 20, 2)
    gap["events"][1]["seq"] = 22
    expect(400, "bad_request", lambda: cp.flows("node-1", gap))


def test_over_tls_the_client_certificate_names_the_node(cp, tmp_path):
    server = Server(("127.0.0.1", 0), cp, ["localhost"])
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    trust = ssl.create_default_context(cadata=cp.ca.pem.decode())

    def post(path, body, ctx):
        conn = http.client.HTTPSConnection("localhost", port, context=ctx, timeout=5)
        conn.request("POST", path, json.dumps(body), {"content-type": "application/json"})
        res = conn.getresponse()
        return res.status, json.loads(res.read())

    state = STATE
    status, err = post("/roxy/v1/lease", state, trust)
    assert (status, err["error"]) == (401, "unrecognised")
    valid("Error", err)

    csr, key = csr_pem()
    status, enrolled = post("/roxy/v1/enrol", enrol_body(csr), trust)
    assert status == 401, "no bearer token"
    conn = http.client.HTTPSConnection("localhost", port, context=trust)
    conn.request("POST", "/roxy/v1/enrol", json.dumps(enrol_body(csr)), {"authorization": "Bearer tok"})
    res = conn.getresponse()
    assert res.status == 200
    enrolled = json.loads(res.read())

    (tmp_path / "node.pem").write_text(enrolled["certificate_chain"] + key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    ).decode())
    with_cert = ssl.create_default_context(cadata=cp.ca.pem.decode())
    with_cert.load_cert_chain(tmp_path / "node.pem")
    status, lease = post("/roxy/v1/lease", state, with_cert)
    assert status == 200
    valid("Lease", lease)
    status, ack = post("/roxy/v1/flows", batch(enrolled["node_id"], 1, 1, lease["lease_id"]), with_cert)
    assert (status, ack) == (200, {"acked_through": 1})
    server.shutdown()
