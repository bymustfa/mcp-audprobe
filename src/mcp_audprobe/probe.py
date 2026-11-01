"""Runs the checks against a target MCP server and builds a result dict (stable JSON schema)."""

from __future__ import annotations

import json
from typing import Any

import httpx

from . import __version__
from .checks import ATTACKS, CONTROL, Check, Context, Verdict, attack_verdict, classify, control_ok, overall
from .tokens import KeyMaterial, mint_token

SCHEMA_VERSION = 1
PROTOCOL_VERSION = "2025-06-18"

INIT_REQUEST = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": {"name": "mcp-audprobe", "version": __version__},
    },
}


def send_initialize(client: httpx.Client, url: str, token: str) -> tuple[int | None, str | None]:
    """POST an authenticated MCP ``initialize`` request. Returns (http_status, error)."""
    try:
        r = client.post(
            url,
            json=INIT_REQUEST,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
            },
        )
        return r.status_code, None
    except httpx.HTTPError as e:
        return None, f"{type(e).__name__}: {e}"


def _entry(check: Check, claims: dict[str, Any], status: int | None, err: str | None, verdict: str) -> dict[str, Any]:
    shown = {k: claims[k] for k in ("iss", "aud", "exp") if k in claims}
    return {
        "id": check.id,
        "name": check.name,
        "description": check.description,
        "token_claims": shown,
        "aud_present": "aud" in claims,
        "http_status": status,
        "outcome": classify(status) if verdict != Verdict.SKIPPED.value else None,
        "verdict": verdict,
        "error": err,
    }


def preflight_jwks(auth_server: str, km: KeyMaterial, timeout: float) -> str | None:
    """Return an error string if the fake AS is unreachable or does not serve our key id."""
    url = auth_server.rstrip("/") + "/.well-known/jwks.json"
    try:
        r = httpx.get(url, timeout=timeout)
        r.raise_for_status()
        kids = {k.get("kid") for k in r.json().get("keys", [])}
    except (httpx.HTTPError, json.JSONDecodeError) as e:
        return f"cannot read JWKS from {url}: {e}"
    if km.kid not in kids:
        return f"JWKS at {url} does not contain kid {km.kid}; auth server and --key-file do not match"
    return None


def run_probe(
    target: str,
    km: KeyMaterial,
    ctx: Context,
    *,
    timeout: float = 10.0,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    own = client is None
    client = client or httpx.Client(timeout=timeout)
    try:
        claims = CONTROL.build(ctx)
        status, err = send_initialize(client, target, mint_token(km, claims))
        accepted = control_ok(status)
        control = _entry(CONTROL, claims, status, err, "PASS" if accepted else "FAIL")
        control["accepted"] = accepted
        control.pop("verdict")

        checks: list[dict[str, Any]] = []
        verdicts: list[Verdict] = []
        for check in ATTACKS:
            claims = check.build(ctx)
            if not accepted:
                v, status, err = Verdict.SKIPPED, None, None
            else:
                status, err = send_initialize(client, target, mint_token(km, claims))
                v = attack_verdict(status)
            verdicts.append(v)
            checks.append(_entry(check, claims, status, err, v.value))
    finally:
        if own:
            client.close()

    result_name, code = overall(accepted, verdicts)
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": "mcp-audprobe",
        "tool_version": __version__,
        "target": target,
        "expected_audience": ctx.audience,
        "other_audience": ctx.other_audience,
        "issuer": ctx.issuer,
        "request": "POST initialize (JSON-RPC) with Authorization: Bearer <token>",
        "control": control,
        "checks": checks,
        "summary": {
            "passed": sum(v is Verdict.PASS for v in verdicts),
            "failed": sum(v is Verdict.FAIL for v in verdicts),
            "errors": sum(v is Verdict.ERROR for v in verdicts),
            "skipped": sum(v is Verdict.SKIPPED for v in verdicts),
        },
        "result": result_name,
        "exit_code": code,
    }
