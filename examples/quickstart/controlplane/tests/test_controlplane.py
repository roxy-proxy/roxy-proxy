"""The control plane's answers match the node protocol's schemas and the
decisions the quickstart relies on: enrolment issues a node token, the
token authenticates every later request, the lease carries roxy.yaml with
its secrets moved into the map, a revoked node gets 410, and flow batches
are deduplicated."""

import http.client
import json
import ssl
import sys
import threading
from pathlib import Path

import jsonschema
import pytest
import yaml

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

ENROL_BODY = {"roxy_version": "0.0.0-test", "protocol_version": 1}


def valid(schema, body):
    """Asserts `body` validates against `#/components/schemas/<schema>`."""
    root = {"$ref": f"#/components/schemas/{schema}", "components": OPENAPI["components"]}
    jsonschema.Draft202012Validator(root).validate(body)


@pytest.fixture
def cp(tmp_path):
    config = tmp_path / "roxy.yaml"
    config.write_text(ROXY_YAML)
    token_file = tmp_path / "enrol-token"
    token_file.write_text("tok\n")
    env = {
        "ENROL_TOKEN_FILE": str(token_file),
        "MODEL_API_KEY": "k1",
        "LEASE_VALID_SECONDS": "20",
        "NODE_TOKEN_SECONDS": "600",
    }
    return ControlPlane(tmp_path / "data", config, env)


def expect(status, code, fn):
    with pytest.raises(ApiError) as e:
        fn()
    assert (e.value.status, e.value.body["error"]) == (status, code)
    valid("Error", e.value.body)


def test_enrol_issues_a_token_that_names_the_node(cp):
    valid("EnrolRequest", ENROL_BODY)
    res = cp.enrol("tok", ENROL_BODY)
    valid("EnrolResponse", res)
    assert cp.tokens.node_id(res["token"]) == res["node_id"]
    assert res["renew_after_seconds"] < 600
    assert cp.tokens.node_id("nt1_" + "0" * 64) is None
    assert cp.tokens.node_id(None) is None


def test_enrol_refuses_a_wrong_token_and_an_unknown_protocol(cp):
    expect(401, "invalid_token", lambda: cp.enrol("nope", ENROL_BODY))
    expect(401, "invalid_token", lambda: cp.enrol(None, ENROL_BODY))
    expect(426, "unsupported", lambda: cp.enrol("tok", {**ENROL_BODY, "protocol_version": 2}))
    expect(400, "bad_request", lambda: cp.enrol("tok", {"protocol_version": 1}))


def test_renew_keeps_the_node_id_and_the_old_token_until_it_expires(cp):
    first = cp.enrol("tok", ENROL_BODY)
    again = cp.renew(first["node_id"], ENROL_BODY)
    valid("EnrolResponse", again)
    assert again["node_id"] == first["node_id"]
    assert again["token"] != first["token"]
    assert cp.tokens.node_id(first["token"]) == first["node_id"]
    assert cp.tokens.node_id(again["token"]) == first["node_id"]


def test_tokens_are_kept_hashed_and_survive_a_restart(cp, tmp_path):
    res = cp.enrol("tok", ENROL_BODY)
    stored = (cp.data_dir / "tokens.json").read_text()
    assert res["token"] not in stored
    assert res["node_id"] in stored
    assert (cp.data_dir / "tokens.json").stat().st_mode & 0o777 == 0o600
    restarted = ControlPlane(cp.data_dir, cp.config_path, cp.environ)
    assert restarted.tokens.node_id(res["token"]) == res["node_id"]


def test_an_expired_token_is_not_recognised(cp):
    short = ControlPlane(cp.data_dir, cp.config_path, {**cp.environ, "NODE_TOKEN_SECONDS": "-1"})
    res = short.enrol("tok", ENROL_BODY)
    assert short.tokens.node_id(res["token"]) is None


STATE = {"lease_id": None, "roxy_version": "0.0.0", "protocol_version": 1,
         "uptime_seconds": 0, "policy_state": "none", "spooled_bytes": 0,
         "seq_unreserved": False}


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
    expect(410, "revoked", lambda: cp.renew("node-1", ENROL_BODY))
    expect(410, "revoked", lambda: cp.flows("node-1", batch("node-1", 1, 1)))
    cp.lease("node-2", state)


def test_a_malformed_node_state_is_400(cp):
    expect(400, "bad_request", lambda: cp.lease("node-1", {**STATE, "policy_state": "gone"}))
    expect(400, "bad_request", lambda: cp.lease("node-1", {k: v for k, v in STATE.items() if k != "lease_id"}))
    expect(400, "bad_request", lambda: cp.lease("node-1", {**STATE, "seq_unreserved": "yes"}))
    expect(426, "unsupported", lambda: cp.lease("node-1", {**STATE, "protocol_version": 2}))


def test_an_unreserved_seq_is_warned_about_and_an_older_node_may_omit_it(cp, capsys):
    valid("Lease", cp.lease("node-1", {**STATE, "seq_unreserved": True}))
    assert "node-1 is using flow seq values" in capsys.readouterr().err
    valid("Lease", cp.lease("node-2", {k: v for k, v in STATE.items() if k != "seq_unreserved"}))
    assert capsys.readouterr().err == ""


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


def test_the_server_key_is_readable_by_the_owner_alone_and_kept_across_restarts(cp):
    """The key is rewritten over a file something else left world-readable;
    a second server in the same data dir presents the same certificate."""
    chain = cp.data_dir / "server.pem"
    chain.write_bytes(b"stale")
    chain.chmod(0o644)
    chain.unlink()
    first = Server(("127.0.0.1", 0), cp, ["localhost"])
    first.server_close()
    assert chain.stat().st_mode & 0o777 == 0o600
    second = Server(("127.0.0.1", 0), cp, ["localhost"])
    second.server_close()
    assert second.certificate_pem == first.certificate_pem


def test_over_tls_the_bearer_token_names_the_node(cp):
    server = Server(("127.0.0.1", 0), cp, ["localhost"])
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    trust = ssl.create_default_context(cadata=server.certificate_pem.decode())

    def post(path, body, token=None):
        headers = {"content-type": "application/json"}
        if token is not None:
            headers["authorization"] = f"Bearer {token}"
        conn = http.client.HTTPSConnection("localhost", port, context=trust, timeout=5)
        conn.request("POST", path, json.dumps(body), headers)
        res = conn.getresponse()
        return res.status, json.loads(res.read())

    state = STATE
    status, err = post("/roxy/v1/lease", state)
    assert (status, err["error"]) == (401, "unrecognised")
    valid("Error", err)
    status, err = post("/roxy/v1/lease", state, token="nt1_" + "0" * 64)
    assert (status, err["error"]) == (401, "unrecognised")

    status, err = post("/roxy/v1/enrol", ENROL_BODY)
    assert (status, err["error"]) == (401, "invalid_token"), "no bearer token"
    status, enrolled = post("/roxy/v1/enrol", ENROL_BODY, token="tok")
    assert status == 200
    valid("EnrolResponse", enrolled)

    status, lease = post("/roxy/v1/lease", state, token=enrolled["token"])
    assert status == 200
    valid("Lease", lease)
    status, ack = post("/roxy/v1/flows", batch(enrolled["node_id"], 1, 1, lease["lease_id"]), token=enrolled["token"])
    assert (status, ack) == (200, {"acked_through": 1})
    status, renewed = post("/roxy/v1/renew", ENROL_BODY, token=enrolled["token"])
    assert status == 200
    assert renewed["node_id"] == enrolled["node_id"]
    status, _ = post("/roxy/v1/lease", state, token=renewed["token"])
    assert status == 200
    status, _ = post("/roxy/v1/lease", state, token=enrolled["token"])
    assert status == 200, "the old token serves until its own expiry"
    server.shutdown()
