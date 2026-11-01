"""Demo MCP servers (real MCP Python SDK >= 1.30) for mcp-audprobe.

--mode vulnerable : verifies signature, iss and exp, but NOT the audience (the bug in the advisories).
                    AuthSettings.validate_token_resource=False and verify_token() does not set
                    AccessToken.resource, so a valid token minted for another service is accepted.
--mode hardened   : same verifier, but returns the token's aud as AccessToken.resource AND sets
                    AuthSettings(validate_token_resource=True, resource_server_url=<this server's URL>),
                    which is the fix described in GHSA-w4fh-qvv9-3v23.

Binds to 127.0.0.1 only. For local demo/testing; not hardened for production.
"""

from __future__ import annotations

import argparse
import logging

import jwt
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP


class JwksVerifier:
    """TokenVerifier: RS256 signature (via JWKS), iss and exp. Audience handling depends on mode."""

    def __init__(self, issuer: str, jwks_url: str, report_resource: bool, expected_aud: str):
        self.issuer = issuer
        self.jwks = jwt.PyJWKClient(jwks_url, cache_keys=True, timeout=5)
        self.report_resource = report_resource
        self.expected_aud = expected_aud

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            key = self.jwks.get_signing_key_from_jwt(token).key
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                issuer=self.issuer,
                options={"require": ["exp", "iss"], "verify_aud": False},  # aud is NOT checked here
            )
        except jwt.PyJWTError as e:
            logging.getLogger("demo").info("token rejected by verifier: %s", e)
            return None
        resource = None
        if self.report_resource:
            aud = claims.get("aud")
            if isinstance(aud, list):
                aud = self.expected_aud if self.expected_aud in aud else (aud[0] if aud else None)
            resource = aud  # None when the token has no aud -> SDK rejects it
        return AccessToken(
            token=token,
            client_id=str(claims.get("client_id", claims.get("sub", "unknown"))),
            scopes=str(claims.get("scope", "")).split(),
            expires_at=int(claims["exp"]),
            resource=resource,
        )


def build_server(mode: str, port: int, issuer: str, jwks_url: str) -> FastMCP:
    resource_url = f"http://127.0.0.1:{port}/mcp"
    hardened = mode == "hardened"
    verifier = JwksVerifier(issuer, jwks_url, report_resource=hardened, expected_aud=resource_url)
    mcp = FastMCP(
        f"demo-{mode}",
        host="127.0.0.1",
        port=port,
        stateless_http=True,
        json_response=True,
        token_verifier=verifier,
        auth=AuthSettings(
            issuer_url=issuer,
            resource_server_url=resource_url,
            required_scopes=["mcp"],
            validate_token_resource=hardened,
        ),
    )

    @mcp.tool()
    def ping() -> str:
        """Health tool."""
        return f"pong from {mode}"

    return mcp


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["vulnerable", "hardened"], required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--issuer", default="http://127.0.0.1:9000")
    ap.add_argument("--jwks-url", default=None)
    a = ap.parse_args()
    jwks = a.jwks_url or a.issuer.rstrip("/") + "/.well-known/jwks.json"
    build_server(a.mode, a.port, a.issuer, jwks).run(transport="streamable-http")


if __name__ == "__main__":
    main()
