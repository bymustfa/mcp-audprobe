"""Render the table output of result JSON files as a terminal-style PNG.

Usage: render_png.py result1.json [result2.json ...] out.png
Uses the very same renderer as the CLI (rich), records the styled segments and draws them with Pillow.
(Headless Chrome was not used so the demo has no browser dependency.)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont
from rich.terminal_theme import MONOKAI

from mcp_audprobe.report import make_console, render_table

FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_B = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
BG, FG = (30, 30, 46), (205, 214, 244)
SIZE, PAD, COLS = 17, 28, 110


def main(argv: list[str]) -> int:
    *jsons, out = argv
    console = make_console(width=COLS, record=True, force_terminal=True, color_system="truecolor", file=open("/dev/null", "w"))
    for i, j in enumerate(jsons):
        console.print(f"[bold cyan]$ mcp-audprobe probe --audience <url> <{Path(j).stem} server>[/bold cyan]")
        render_table(json.loads(Path(j).read_text()), console)
        if i < len(jsons) - 1:
            console.print()
    # Lay out recorded segments into (text, color, bold) runs per line
    lines: list[list[tuple[str, tuple[int, int, int], bool]]] = [[]]
    for seg in console._record_buffer:  # public API has no segment accessor; pinned rich>=13
        if seg.control:
            continue
        style = seg.style
        color = FG
        if style and style.color:
            color = tuple(style.color.get_truecolor(MONOKAI))
        bold = bool(style and style.bold)
        if style and style.dim:
            color = tuple(int(c * 0.6) for c in color)
        parts = seg.text.split("\n")
        for k, part in enumerate(parts):
            if k:
                lines.append([])
            if part:
                lines[-1].append((part, color, bold))
    font, fontb = ImageFont.truetype(FONT, SIZE), ImageFont.truetype(FONT_B, SIZE)
    cw = font.getlength("M")
    lh = int(SIZE * 1.35)
    width = int(PAD * 2 + cw * COLS)
    img = Image.new("RGB", (width, PAD * 2 + lh * len(lines)), BG)
    d = ImageDraw.Draw(img)
    for y, line in enumerate(lines):
        x = PAD
        for text, color, bold in line:
            d.text((x, PAD + y * lh), text, font=fontb if bold else font, fill=color)
            x += cw * len(text)
    img.save(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
