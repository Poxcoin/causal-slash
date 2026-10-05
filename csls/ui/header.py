# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Header rendering for CSLS terminal shell.
Displays logo on the left and title, tagline, cwd on the right.
Never paints a background color.
"""

import os
from rich.console import Console
from rich.table import Table
from rich.text import Text

from csls.ui.theme import TEAL_HEX, DIM_GRAY, has_truecolor
from csls.ui.logo import get_logo_rich, LOGO_PLAIN

VERSION = "0.3.0"
TAGLINE = "Sovereign M2M clearing for autonomous agents"


def render_header(
    console: Console, cwd: str | None = None, memory_turns: int = 0
) -> None:
    """Print the launch header into the normal scrollback."""
    if cwd is None:
        cwd = os.getcwd()

    home = os.path.expanduser("~")
    display_cwd = cwd.replace(home, "~", 1) if cwd.startswith(home) else cwd

    mem_text = (
        f"resumed session: {memory_turns} dialog turns remembered (/memory)"
        if memory_turns > 0
        else ""
    )

    if not has_truecolor():
        # Fallback for minimal non-truecolor terminals
        console.print(f"[bold {TEAL_HEX}]{LOGO_PLAIN} CLI {VERSION}[/]")
        console.print(f"[dim {DIM_GRAY}]{TAGLINE}[/]")
        console.print(f"[dim {DIM_GRAY}]{display_cwd}[/]")
        if mem_text:
            console.print(f"[dim {TEAL_HEX}]{mem_text}[/]")
        console.print()
        return

    # Left: logo half-block art (9 lines: glyph + wordmark)
    logo_lines = get_logo_rich(small=False)

    # Right: title, tagline, cwd, memory context
    right_lines = [
        Text(f"Causal-Slash CLI {VERSION}", style=f"bold {TEAL_HEX}"),
        Text(TAGLINE, style=f"dim {DIM_GRAY}"),
        Text(display_cwd, style=f"dim {DIM_GRAY}"),
        Text(mem_text, style=f"dim {TEAL_HEX}") if mem_text else Text(""),
        Text(""),
    ]

    # Render side-by-side using Table.grid without any borders or background
    table = Table.grid(padding=(0, 4))
    table.add_column(no_wrap=True)
    table.add_column(no_wrap=False)

    for i in range(max(len(logo_lines), len(right_lines))):
        left = logo_lines[i] if i < len(logo_lines) else Text("")
        right = right_lines[i] if i < len(right_lines) else Text("")
        table.add_row(left, right)

    console.print()
    console.print(table)
    console.print()
