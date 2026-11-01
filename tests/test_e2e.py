"""End-to-end: real fake auth server + real MCP Python SDK demo servers on 127.0.0.1."""

import json
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from mcp_audprobe.cli import main
from mcp_audprobe.tokens import KeyMaterial

ROOT = Path(__file__).resolve().parents[1]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait(url, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        try:
            httpx.get(url, timeout=1)
            return
        except httpx.HTTPError:
            time.sleep(0.2)
    raise TimeoutError(url)


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    d = tmp_path_factory.mktemp("e2e")
    key = d / "key.pem"
    KeyMaterial.generate().save(key)
    as_port, v_port, h_port = free_port(), free_port(), free_port()
    issuer = f"http://127.0.0.1:{as_port}"
    procs = [
        subprocess.Popen(
            [
                sys.executable,
                "-m",
                "mcp_audprobe",
                "auth-server",
                "--port",
                str(as_port),
                "--issuer",
                issuer,
                "--key-file",
                str(key),
            ]
        ),
        subprocess.Popen(
            [
                sys.executable,
                str(ROOT / "demo/demo_server.py"),
                "--mode",
                "vulnerable",
                "--port",
                str(v_port),
                "--issuer",
                issuer,
            ]
        ),
        subprocess.Popen(
            [
                sys.executable,
                str(ROOT / "demo/demo_server.py"),
                "--mode",
                "hardened",
                "--port",
                str(h_port),
                "--issuer",
                issuer,
            ]
        ),
    ]
    try:
        wait(f"{issuer}/health")
        wait(f"http://127.0.0.1:{v_port}/mcp")
        wait(f"http://127.0.0.1:{h_port}/mcp")
        yield dict(key=key, issuer=issuer, v=v_port, h=h_port, dir=d)
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            p.wait(timeout=10)


def probe(env, port, capsys):
    url = f"http://127.0.0.1:{port}/mcp"
    out = env["dir"] / f"{port}.json"
    rc = main(
        [
            "probe",
            url,
            "--audience",
            url,
            "--issuer",
            env["issuer"],
            "--auth-server",
            env["issuer"],
            "--key-file",
            str(env["key"]),
            "--json-out",
            str(out),
            "--no-color",
        ]
    )
    return rc, json.loads(out.read_text()), capsys.readouterr().out


def test_unauthenticated_request_is_401(env):
    r = httpx.post(f"http://127.0.0.1:{env['h']}/mcp", json={})
    assert r.status_code == 401


def test_vulnerable_server_fails(env, capsys):
    rc, res, out = probe(env, env["v"], capsys)
    assert rc == 1 and res["result"] == "FAIL"
    assert {c["id"]: c["verdict"] for c in res["checks"]} == {
        "AUD-OTHER": "FAIL",
        "AUD-MISSING": "FAIL",
        "ISS-WRONG": "PASS",
        "EXP-EXPIRED": "PASS",
    }
    assert "FAIL" in out and "accepted" in out


def test_hardened_server_passes(env, capsys):
    rc, res, out = probe(env, env["h"], capsys)
    assert rc == 0 and res["result"] == "PASS"
    assert all(c["verdict"] == "PASS" and c["http_status"] == 401 for c in res["checks"])
    assert res["control"]["http_status"] == 200


def test_json_flag_prints_json(env, capsys):
    url = f"http://127.0.0.1:{env['h']}/mcp"
    rc = main(["probe", url, "--audience", url, "--issuer", env["issuer"], "--key-file", str(env["key"]), "--json"])
    assert rc == 0 and json.loads(capsys.readouterr().out)["result"] == "PASS"


def test_wrong_audience_expectation_is_inconclusive(env, capsys):
    # control token minted for an audience the hardened server does not serve -> control rejected
    url = f"http://127.0.0.1:{env['h']}/mcp"
    rc = main(
        [
            "probe",
            url,
            "--audience",
            "http://127.0.0.1:1/not-me",
            "--issuer",
            env["issuer"],
            "--key-file",
            str(env["key"]),
            "--json",
        ]
    )
    res = json.loads(capsys.readouterr().out)
    assert rc == 2 and res["result"] == "INCONCLUSIVE" and res["control"]["accepted"] is False
