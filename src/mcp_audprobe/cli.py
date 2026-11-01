"""Command line interface: ``mcp-audprobe probe|auth-server``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console

from . import __version__
from .checks import EXIT_USAGE, Context
from .probe import preflight_jwks, run_probe
from .report import make_console, render_table, to_json
from .safety import UnsafeTargetError, check_target
from .tokens import KeyMaterial

DEFAULT_ISSUER = "http://127.0.0.1:9000"
DEFAULT_OTHER_AUD = "https://other-service.example/mcp"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcp-audprobe",
        description="Actively test whether an MCP server you own validates bearer-token aud/iss/exp. "
        "ONLY use against servers you own or are authorized to test.",
    )
    p.add_argument("--version", action="version", version=f"mcp-audprobe {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("auth-server", help="run the local fake authorization server (JWKS + metadata)")
    a.add_argument("--host", default="127.0.0.1")
    a.add_argument("--port", type=int, default=9000)
    a.add_argument("--issuer", default=None, help="issuer URL (default http://HOST:PORT)")
    a.add_argument("--key-file", required=True, help="RSA private key PEM; created if missing")

    q = sub.add_parser("probe", help="probe a target MCP server URL")
    q.add_argument("url", help="MCP endpoint URL, e.g. http://127.0.0.1:8001/mcp")
    q.add_argument("--audience", required=True, help="audience/resource the server must accept (e.g. its own URL)")
    q.add_argument("--issuer", default=DEFAULT_ISSUER, help=f"trusted issuer (default {DEFAULT_ISSUER})")
    q.add_argument("--key-file", required=True, help="signing key shared with the fake auth server")
    q.add_argument("--auth-server", default=None, help="fake auth server base URL; if set, its JWKS is checked first")
    q.add_argument("--other-audience", default=DEFAULT_OTHER_AUD, help="audience used for the wrong-audience token")
    q.add_argument("--timeout", type=float, default=10.0)
    q.add_argument("--json", action="store_true", help="print JSON to stdout instead of the table")
    q.add_argument("--json-out", metavar="FILE", help="also write JSON to FILE")
    q.add_argument("--no-color", action="store_true")
    q.add_argument(
        "--allow-remote",
        action="store_true",
        help="allow non-loopback targets. Only for servers you own / are authorized to test.",
    )
    return p


def _auth_server(args: argparse.Namespace) -> int:
    import uvicorn

    from .authserver import create_app

    issuer = args.issuer or f"http://{args.host}:{args.port}"
    km = KeyMaterial.load_or_create(args.key_file)
    print(f"fake auth server: issuer={issuer} kid={km.kid} jwks={issuer}/.well-known/jwks.json", flush=True)
    uvicorn.run(create_app(km, issuer), host=args.host, port=args.port, log_level="warning")
    return 0


def _probe(args: argparse.Namespace) -> int:
    err = Console(stderr=True)
    try:
        check_target(args.url, args.allow_remote)
        if args.auth_server:
            check_target(args.auth_server, args.allow_remote)
        km = KeyMaterial.load(args.key_file)
    except (UnsafeTargetError, OSError, ValueError) as e:
        err.print(f"error: {e}")
        return EXIT_USAGE
    if args.auth_server:
        problem = preflight_jwks(args.auth_server, km, args.timeout)
        if problem:
            err.print(f"error: {problem}")
            return EXIT_USAGE
    ctx = Context(issuer=args.issuer, audience=args.audience, other_audience=args.other_audience)
    result = run_probe(args.url, km, ctx, timeout=args.timeout)
    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(to_json(result) + "\n")
    if args.json:
        print(to_json(result))
    else:
        render_table(result, make_console(no_color=args.no_color))
    return result["exit_code"]


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return _auth_server(args) if args.cmd == "auth-server" else _probe(args)


if __name__ == "__main__":
    sys.exit(main())
