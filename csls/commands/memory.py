# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
/memory command implementation.
Inspects persistent project conversation context and remembered turns.
"""

from __future__ import annotations
from typing import List
from rich.table import Table

from csls.commands.base import Command, CommandContext
from csls.ui.theme import TEAL_HEX, DIM_GRAY, SUCCESS_GREEN, WARN_YELLOW


class MemoryCommand(Command):
    name = "/memory"
    description = "inspect persistent chat conversation memory"
    args_spec = ""

    async def run(self, ctx: CommandContext, args: List[str]) -> int:
        console = ctx.console
        session = ctx.session

        turns = session.conversation_memory
        num_turns = len(turns) // 2

        console.print()
        console.print(f"[bold {TEAL_HEX}]Persistent Chat Memory:[/]")
        console.print(f"  [dim {DIM_GRAY}]Workspace Directory:[/] {session.cwd}")
        console.print(f"  [dim {DIM_GRAY}]Storage File:[/]        {session.project_memory_file}")
        console.print(f"  [dim {DIM_GRAY}]Remembered Turns:[/]    [bold {TEAL_HEX}]{num_turns}[/] dialog turns ({len(turns)} messages)")
        console.print(f"  [dim {DIM_GRAY}]Active Frontier Model:[/] [cyan]{session.current_model}[/cyan]")
        console.print()

        if turns:
            table = Table(
                title=f"[{TEAL_HEX}]Recent Memory Buffer[/]",
                box=None,
                padding=(0, 2),
                collapse_padding=True,
            )
            table.add_column("Role", style=f"bold {TEAL_HEX}", no_wrap=True)
            table.add_column("Preview", style=f"dim {DIM_GRAY}")

            for msg in turns[-8:]:
                role = msg.get("role", "unknown").upper()
                content = msg.get("content", "").replace("\n", " ")
                if len(content) > 75:
                    content = content[:72] + "..."
                table.add_row(role, content)

            console.print(table)
            console.print()
            console.print(f"[dim {DIM_GRAY}]To clear memory for this project, run [bold {TEAL_HEX}]/clear[/bold {TEAL_HEX}][/dim {DIM_GRAY}]")
        else:
            console.print(f"[dim {DIM_GRAY}]No past turns recorded for this project yet. Ask any question to start.[/dim {DIM_GRAY}]")

        console.print()
        return 0
