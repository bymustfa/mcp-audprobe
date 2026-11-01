import pytest

from mcp_audprobe.checks import (
    ACCEPTED, ATTACKS, CONTROL, REJECTED, UNEXPECTED, Context, Verdict, attack_verdict, classify, control_ok, overall,
)

CTX = Context(issuer="http://iss", audience="http://me/mcp", other_audience="http://other/mcp")


@pytest.mark.parametrize(
    "status,outcome",
    [(200, ACCEPTED), (202, ACCEPTED), (401, REJECTED), (403, REJECTED), (400, UNEXPECTED), (404, UNEXPECTED),
     (500, UNEXPECTED), (302, UNEXPECTED), (None, UNEXPECTED)],
)
def test_classify(status, outcome):
    assert classify(status) == outcome


@pytest.mark.parametrize(
    "status,verdict",
    [(200, Verdict.FAIL), (401, Verdict.PASS), (403, Verdict.PASS), (500, Verdict.ERROR), (None, Verdict.ERROR)],
)
def test_attack_verdict(status, verdict):
    assert attack_verdict(status) == verdict


def test_control_ok():
    assert control_ok(200) and not control_ok(401) and not control_ok(None) and not control_ok(500)


def test_claims_per_check():
    c = {k.id: k.build(CTX) for k in (CONTROL, *ATTACKS)}
    assert c["CONTROL"]["aud"] == CTX.audience and c["CONTROL"]["iss"] == CTX.issuer
    assert c["AUD-OTHER"]["aud"] == CTX.other_audience and c["AUD-OTHER"]["iss"] == CTX.issuer
    assert "aud" not in c["AUD-MISSING"]
    assert c["ISS-WRONG"]["iss"] != CTX.issuer and c["ISS-WRONG"]["aud"] == CTX.audience
    assert c["EXP-EXPIRED"]["exp"] < c["CONTROL"]["iat"]
    assert [a.id for a in ATTACKS] == ["AUD-OTHER", "AUD-MISSING", "ISS-WRONG", "EXP-EXPIRED"]


def test_overall():
    P, F, E, S = Verdict.PASS, Verdict.FAIL, Verdict.ERROR, Verdict.SKIPPED
    assert overall(True, [P, P, P, P]) == ("PASS", 0)
    assert overall(True, [F, P, P, P]) == ("FAIL", 1)
    assert overall(True, [F, E, P, P]) == ("FAIL", 1)
    assert overall(True, [P, E, P, P]) == ("INCONCLUSIVE", 2)
    assert overall(False, [S, S, S, S]) == ("INCONCLUSIVE", 2)
