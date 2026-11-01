"""Probe orchestration against a mocked transport (no real servers)."""

import json

import httpx
import jwt

from mcp_audprobe.checks import Context
from mcp_audprobe.cli import main
from mcp_audprobe.probe import run_probe

CTX = Context(issuer="http://iss", audience="http://me/mcp", other_audience="http://other/mcp")


def make_client(km, *, check_aud: bool, check_iss=True, check_exp=True, reject_all=False, boom=False):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        if boom:
            raise httpx.ConnectError("down")
        token = req.headers["authorization"].removeprefix("Bearer ")
        assert req.headers["accept"].startswith("application/json")
        assert json.loads(req.content)["method"] == "initialize"
        seen.append(token)
        if reject_all:
            return httpx.Response(401)
        opts = {"verify_aud": check_aud, "verify_iss": check_iss, "verify_exp": check_exp}
        try:
            jwt.decode(
                token,
                km.private_key.public_key(),
                algorithms=["RS256"],
                audience=CTX.audience,
                issuer=CTX.issuer if check_iss else None,
                options=opts,
            )
        except jwt.PyJWTError:
            return httpx.Response(401)
        return httpx.Response(200, json={"result": {}})

    return httpx.Client(transport=httpx.MockTransport(handler)), seen


def verdicts(res):
    return {c["id"]: c["verdict"] for c in res["checks"]}


def test_hardened_passes(km):
    client, seen = make_client(km, check_aud=True)
    res = run_probe("http://127.0.0.1:1/mcp", km, CTX, client=client)
    assert res["result"] == "PASS" and res["exit_code"] == 0
    assert set(verdicts(res).values()) == {"PASS"} and len(seen) == 5
    assert res["control"]["accepted"] is True


def test_no_aud_check_fails_aud_checks_only(km):
    client, _ = make_client(km, check_aud=False)
    res = run_probe("http://127.0.0.1:1/mcp", km, CTX, client=client)
    assert verdicts(res) == {"AUD-OTHER": "FAIL", "AUD-MISSING": "FAIL", "ISS-WRONG": "PASS", "EXP-EXPIRED": "PASS"}
    assert res["result"] == "FAIL" and res["exit_code"] == 1
    assert res["summary"] == {"passed": 2, "failed": 2, "errors": 0, "skipped": 0}


def test_no_exp_check_fails_expired(km):
    client, _ = make_client(km, check_aud=True, check_exp=False)
    assert verdicts(run_probe("http://127.0.0.1:1/mcp", km, CTX, client=client))["EXP-EXPIRED"] == "FAIL"


def test_control_rejected_is_inconclusive_and_attacks_skipped(km):
    client, seen = make_client(km, check_aud=True, reject_all=True)
    res = run_probe("http://127.0.0.1:1/mcp", km, CTX, client=client)
    assert res["result"] == "INCONCLUSIVE" and res["exit_code"] == 2
    assert set(verdicts(res).values()) == {"SKIPPED"} and len(seen) == 1


def test_network_error_is_inconclusive(km):
    client, _ = make_client(km, check_aud=True, boom=True)
    res = run_probe("http://127.0.0.1:1/mcp", km, CTX, client=client)
    assert res["result"] == "INCONCLUSIVE" and "ConnectError" in res["control"]["error"]


def test_json_schema_keys(km):
    client, _ = make_client(km, check_aud=True)
    res = run_probe("http://127.0.0.1:1/mcp", km, CTX, client=client)
    assert list(res) == [
        "schema_version",
        "tool",
        "tool_version",
        "target",
        "expected_audience",
        "other_audience",
        "issuer",
        "request",
        "control",
        "checks",
        "summary",
        "result",
        "exit_code",
    ]
    assert list(res["checks"][0]) == [
        "id",
        "name",
        "description",
        "token_claims",
        "aud_present",
        "http_status",
        "outcome",
        "verdict",
        "error",
    ]


def test_cli_refuses_remote_target(km, tmp_path, capsys):
    key = tmp_path / "k.pem"
    km.save(key)
    rc = main(["probe", "https://example.com/mcp", "--audience", "x", "--key-file", str(key)])
    assert rc == 3 and "refusing to probe non-loopback" in capsys.readouterr().err
