import time

import jwt
import pytest

from mcp_audprobe.tokens import KeyMaterial, build_claims, mint_token


def decode(token, km, **kw):
    return jwt.decode(token, km.private_key.public_key(), algorithms=["RS256"], **kw)


def test_mint_roundtrip_and_kid(km):
    claims = build_claims(issuer="http://i", audience="http://a")
    tok = mint_token(km, claims)
    assert jwt.get_unverified_header(tok) == {"alg": "RS256", "typ": "JWT", "kid": km.kid}
    out = decode(tok, km, audience="http://a", issuer="http://i")
    assert out["iss"] == "http://i" and out["aud"] == "http://a"


def test_jwks_contains_public_key_only(km):
    (jwk,) = km.jwks()["keys"]
    assert jwk["kid"] == km.kid and jwk["alg"] == "RS256" and jwk["kty"] == "RSA"
    assert "d" not in jwk and "p" not in jwk
    # token verifies using the JWKS entry alone
    pub = jwt.PyJWK(jwk).key
    tok = mint_token(km, build_claims(issuer="i", audience="a"))
    assert jwt.decode(tok, pub, algorithms=["RS256"], audience="a", issuer="i")["iss"] == "i"


def test_no_aud_claim_omitted(km):
    claims = build_claims(issuer="i", audience=None)
    assert "aud" not in claims
    assert "aud" not in decode(mint_token(km, claims), km, options={"verify_aud": False})


def test_expired_token_claims(km):
    now = int(time.time())
    claims = build_claims(issuer="i", audience="a", ttl=-3600, now=now)
    assert claims["exp"] == now - 3600 and claims["iat"] < claims["exp"]
    with pytest.raises(jwt.ExpiredSignatureError):
        decode(mint_token(km, claims), km, audience="a")


def test_key_persistence(tmp_path):
    p = tmp_path / "k.pem"
    a = KeyMaterial.load_or_create(p)
    b = KeyMaterial.load_or_create(p)
    assert a.kid == b.kid
    assert oct(p.stat().st_mode & 0o777) == "0o600"


def test_other_key_does_not_verify(km):
    other = KeyMaterial.generate()
    tok = mint_token(other, build_claims(issuer="i", audience="a"))
    with pytest.raises(jwt.InvalidSignatureError):
        decode(tok, km, audience="a")
