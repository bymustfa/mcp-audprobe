"""Human-readable table and JSON rendering."""

from __future__ import annotations

import json
from typing import Any

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

STYLE = {"PASS": "bold green", "FAIL": "bold red", "ERROR": "bold yellow", "SKIPPED": "dim", "INCONCLUSIVE": "bold yellow"}


def make_console(*, no_color: bool = False, width: int | None = None, **kw: Any) -> Console:
    """Console with a sane width. (rich ignores ``width`` unless ``height`` is also given on dumb terminals.)"""
    import shutil

    width = width or max(shutil.get_terminal_size().columns, 110)
    return Console(no_color=no_color, highlight=False, width=width, height=50, **kw)


def to_json(result: dict[str, Any]) -> str:
    return json.dumps(result, indent=2, sort_keys=False)


def _fmt_aud(c: dict[str, Any], aud_present: bool) -> str:
    return str(c["aud"]) if aud_present else "(none)"


def render_table(result: dict[str, Any], console: Console) -> None:
    console.print(f"[bold]mcp-audprobe[/bold] {result['tool_version']}  target: [cyan]{result['target']}[/cyan]")
    console.print(f"expected aud: {result['expected_audience']}   trusted iss: {result['issuer']}")
    ctl = result["control"]
    st = ctl["http_status"] if ctl["http_status"] is not None else "-"
    console.print(
        "control token: "
        + ("[green]accepted[/green]" if ctl["accepted"] else "[yellow]NOT accepted[/yellow]")
        + f" (HTTP {st})"
        + (f"  {ctl['error']}" if ctl.get("error") else "")
    )
    t = Table(box=box.SIMPLE_HEAVY, header_style="bold")
    t.add_column("Check", no_wrap=True)
    t.add_column("Token sent", min_width=40, no_wrap=True)
    t.add_column("HTTP", justify="right")
    t.add_column("Server", justify="left", min_width=10, no_wrap=True)
    t.add_column("Verdict", min_width=8, no_wrap=True)
    for c in result["checks"]:
        claims = c["token_claims"]
        sent = f"aud={_fmt_aud(claims, c['aud_present'])}" if c["id"].startswith("AUD") else c["name"].lower()
        if c["id"] == "ISS-WRONG":
            sent = "iss=" + claims["iss"].removeprefix("http://").removeprefix("https://")
        if c["id"] == "EXP-EXPIRED":
            sent = "exp = 1h ago"
        http = "-" if c["http_status"] is None else str(c["http_status"])
        outcome = {"accepted": "accepted", "rejected": "rejected", "unexpected": "unexpected", None: "not sent"}[c["outcome"]]
        t.add_row(f"{c['id']}\n[dim]{c['name']}[/dim]", sent, http, outcome, Text(c["verdict"], style=STYLE[c["verdict"]]))
    console.print(t)
    s = result["summary"]
    console.print(
        f"RESULT: [{STYLE[result['result']]}]{result['result']}[/]   "
        f"passed={s['passed']} failed={s['failed']} errors={s['errors']} skipped={s['skipped']}"
    )
    if result["result"] == "FAIL":
        bad = ", ".join(c["id"] for c in result["checks"] if c["verdict"] == "FAIL")
        console.print(f"[red]Server accepted tokens it should have rejected: {bad}[/red]")
    elif result["result"] == "INCONCLUSIVE":
        console.print("[yellow]Inconclusive: control token not accepted or an unexpected response was seen.[/yellow]")
