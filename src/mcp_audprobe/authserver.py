"""Minimal fake authorization server: JWKS + OAuth/OIDC discovery metadata.

It issues nothing over HTTP. Tokens are minted locally by the probe with the same key file; the
MCP server under test only needs to trust this server's JWKS. Demo/testing use only.
"""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from .tokens import KeyMaterial


def create_app(km: KeyMaterial, issuer: str) -> Starlette:
    issuer = issuer.rstrip("/")
    jwks_uri = f"{issuer}/.well-known/jwks.json"

    async def jwks(_: Request) -> JSONResponse:
        return JSONResponse(km.jwks())

    async def metadata(_: Request) -> JSONResponse:
        return JSONResponse(
            {
                "issuer": issuer,
                "jwks_uri": jwks_uri,
                "id_token_signing_alg_values_supported": ["RS256"],
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "token_endpoint_auth_methods_supported": ["none"],
                "note": "mcp-audprobe fake authorization server (testing only)",
            }
        )

    async def health(_: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "kid": km.kid})

    return Starlette(
        routes=[
            Route("/.well-known/jwks.json", jwks),
            Route("/.well-known/openid-configuration", metadata),
            Route("/.well-known/oauth-authorization-server", metadata),
            Route("/health", health),
        ]
    )
