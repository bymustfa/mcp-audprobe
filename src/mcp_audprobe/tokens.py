"""Local RS256 key handling and JWT minting for the fake authorization server."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ALGORITHM = "RS256"


@dataclass
class KeyMaterial:
    """An RSA signing key plus its key id (``kid``)."""

    private_key: rsa.RSAPrivateKey

    @classmethod
    def generate(cls, bits: int = 2048) -> "KeyMaterial":
        return cls(rsa.generate_private_key(public_exponent=65537, key_size=bits))

    @classmethod
    def load(cls, path: str | Path) -> "KeyMaterial":
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError(f"{path}: not an RSA private key")
        return cls(key)

    @classmethod
    def load_or_create(cls, path: str | Path) -> "KeyMaterial":
        p = Path(path)
        if p.exists():
            return cls.load(p)
        km = cls.generate()
        km.save(p)
        return km

    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(
            self.private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        p.chmod(0o600)

    @property
    def kid(self) -> str:
        der = self.private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return hashlib.sha256(der).hexdigest()[:16]

    def jwks(self) -> dict[str, Any]:
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.private_key.public_key()))
        jwk.update({"kid": self.kid, "use": "sig", "alg": ALGORITHM})
        return {"keys": [jwk]}


_UNSET: Any = object()


def build_claims(
    *,
    issuer: str,
    audience: Any,
    subject: str = "audprobe-test-client",
    ttl: int = 600,
    now: int | None = None,
    scope: str = "mcp",
) -> dict[str, Any]:
    """Build a claim set. ``audience=None`` omits ``aud`` entirely. ``ttl`` may be negative (expired)."""
    now = int(time.time()) if now is None else now
    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": subject,
        "client_id": subject,
        "scope": scope,
        "iat": now - 5 if ttl >= 0 else now + ttl - 60,
        "exp": now + ttl,
        "jti": hashlib.sha256(f"{subject}{now}{ttl}{audience}{issuer}".encode()).hexdigest()[:16],
    }
    if audience is not None:
        claims["aud"] = audience
    return claims


def mint_token(km: KeyMaterial, claims: dict[str, Any]) -> str:
    """Sign ``claims`` with the local key (RS256, ``kid`` header set)."""
    return jwt.encode(claims, km.private_key, algorithm=ALGORITHM, headers={"kid": km.kid})
