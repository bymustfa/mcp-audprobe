"""Check definitions and verdict logic (pure functions, no I/O)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .tokens import build_claims

# --- classification of an HTTP response to an authenticated MCP request -------------------------
ACCEPTED = "accepted"  # 2xx: the server processed the request with this token
REJECTED = "rejected"  # 401 / 403: the server refused the credential
UNEXPECTED = "unexpected"  # anything else (other 4xx/5xx, network error, timeout): not conclusive


def classify(http_status: int | None) -> str:
    """Map an HTTP status (``None`` = transport error) to accepted / rejected / unexpected."""
    if http_status is None:
        return UNEXPECTED
    if 200 <= http_status < 300:
        return ACCEPTED
    if http_status in (401, 403):
        return REJECTED
    return UNEXPECTED


class Verdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"  # attack token got an unexpected response; cannot tell
    SKIPPED = "SKIPPED"  # not run because the control token was not accepted


@dataclass(frozen=True)
class Context:
    issuer: str
    audience: str
    other_audience: str
    ttl: int = 600


@dataclass(frozen=True)
class Check:
    id: str
    name: str
    description: str
    build: Callable[[Context], dict[str, Any]]


def _control(c: Context) -> dict[str, Any]:
    return build_claims(issuer=c.issuer, audience=c.audience, ttl=c.ttl)


def _other_aud(c: Context) -> dict[str, Any]:
    return build_claims(issuer=c.issuer, audience=c.other_audience, ttl=c.ttl)


def _no_aud(c: Context) -> dict[str, Any]:
    return build_claims(issuer=c.issuer, audience=None, ttl=c.ttl)


def _wrong_iss(c: Context) -> dict[str, Any]:
    return build_claims(issuer=c.issuer.rstrip("/") + "/evil-issuer", audience=c.audience, ttl=c.ttl)


def _expired(c: Context) -> dict[str, Any]:
    return build_claims(issuer=c.issuer, audience=c.audience, ttl=-3600)


CONTROL = Check(
    "CONTROL",
    "Valid control token",
    "Correct iss, aud, signature and expiry. Must be accepted, otherwise the run is inconclusive.",
    _control,
)

ATTACKS: tuple[Check, ...] = (
    Check(
        "AUD-OTHER",
        "Token for another audience",
        "Valid signature/iss/exp but aud is a different service. Must be rejected.",
        _other_aud,
    ),
    Check(
        "AUD-MISSING",
        "Token without aud",
        "Valid signature/iss/exp but no aud claim at all. Must be rejected.",
        _no_aud,
    ),
    Check(
        "ISS-WRONG",
        "Wrong issuer",
        "Valid signature and aud, but iss is not the trusted issuer. Must be rejected.",
        _wrong_iss,
    ),
    Check(
        "EXP-EXPIRED",
        "Expired token",
        "Valid signature/iss/aud but exp is one hour in the past. Must be rejected.",
        _expired,
    ),
)


def attack_verdict(http_status: int | None) -> Verdict:
    """Verdict for checks 1-4: accepted -> FAIL, rejected -> PASS, otherwise ERROR."""
    outcome = classify(http_status)
    if outcome == ACCEPTED:
        return Verdict.FAIL
    if outcome == REJECTED:
        return Verdict.PASS
    return Verdict.ERROR


def control_ok(http_status: int | None) -> bool:
    return classify(http_status) == ACCEPTED


# Exit codes
EXIT_PASS, EXIT_FAIL, EXIT_INCONCLUSIVE, EXIT_USAGE = 0, 1, 2, 3


def overall(control_accepted: bool, verdicts: list[Verdict]) -> tuple[str, int]:
    """Overall result and process exit code."""
    if not control_accepted:
        return "INCONCLUSIVE", EXIT_INCONCLUSIVE
    if Verdict.FAIL in verdicts:
        return "FAIL", EXIT_FAIL
    if Verdict.ERROR in verdicts:
        return "INCONCLUSIVE", EXIT_INCONCLUSIVE
    return "PASS", EXIT_PASS
