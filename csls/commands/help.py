# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
/help command implementation.
Shows commands table with small logo header and aligned columns.
"""

from __future__ import annotations
from typing import List
from rich.table import Table
from rich.text import Text

from csls.commands.base import Command, CommandContext
from csls.ui.theme import TEAL_HEX, DIM_GRAY
from csls.ui.logo import get_logo_rich, LOGO_PLAIN, get_logo_lines
from csls.ui.theme import has_truecolor


class HelpCommand(Command):
    name = "/help"
    description = "show this table"
    args_spec = "[command]"

    async def run(self, ctx: CommandContext, args: List[str]) -> int:
        from csls.commands import registry

        console = ctx.console

        # If a specific command is requested, show its details
        if args:
            target = args[0]
            if not target.startswith("/"):
                target = "/" + target
            cmd = registry.get(target)
            if cmd:
                console.print(f"[bold {TEAL_HEX}]{cmd.name}[/] {cmd.args_spec}")
                console.print(f"[dim {DIM_GRAY}]{cmd.description}[/]")
                return 0
            else:
                console.print(f"[red]Unknown command for help: {args[0]}[/]")
                return 1

        # Header for /help: small 3-line logo on the left, "Commands" on the right
        console.print()
        if has_truecolor():
            logo_lines = get_logo_rich(small=True)
            right_lines = [
                Text("Commands", style=f"bold {TEAL_HEX}"),
                Text("Type / to autocomplete or select from the list below", style=f"dim {DIM_GRAY}"),
                Text(""),
            ]
            header_grid = Table.grid(padding=(0, 2))
            header_grid.add_column(no_wrap=True)
            header_grid.add_column(no_wrap=False)
            for i in range(max(len(logo_lines), len(right_lines))):
                left = logo_lines[i] if i < len(logo_lines) else Text("")
                right = right_lines[i] if i < len(right_lines) else Text("")
                header_grid.add_row(left, right)
            console.print(header_grid)
        else:
            console.print(f"[bold {TEAL_HEX}]Commands[/]")
            console.print(f"[dim {DIM_GRAY}]Type / to autocomplete or select from the list below[/]")

        console.print()

        # Commands table: teal bold command, dim gray description, aligned columns
        table = Table(
            show_header=False,
            box=None,
            padding=(0, 4),
            pad_edge=False,
            collapse_padding=True,
        )
        table.add_column("Command", style=f"bold {TEAL_HEX}", no_wrap=True)
        table.add_column("Description", style=f"dim {DIM_GRAY}")

        for cmd in registry.list_all():
            table.add_row(cmd.name, cmd.description)

        console.print(table)
        console.print()
        return 0
