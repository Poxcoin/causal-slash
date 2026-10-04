# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
/clear command implementation.
Clears active conversation memory context in the session.
"""

from __future__ import annotations
from typing import List

from csls.commands.base import Command, CommandContext
from csls.ui.theme import DIM_GRAY, SUCCESS_GREEN


class ClearCommand(Command):
    name = "/clear"
    description = "reset agent conversation memory"
    args_spec = ""

    async def run(self, ctx: CommandContext, args: List[str]) -> int:
        console = ctx.console
        session = ctx.session
        turns_count = len(session.conversation_memory)
        session.clear_memory()
        console.print(f"[{SUCCESS_GREEN}]Conversation memory reset[/] [dim {DIM_GRAY}]({turns_count} turns cleared).[/]")
        return 0
