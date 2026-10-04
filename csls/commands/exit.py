# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
/exit command implementation.
Exits the CSLS interactive shell.
"""

from __future__ import annotations
from typing import List

from csls.commands.base import Command, CommandContext
from csls.ui.theme import DIM_GRAY


class ExitCommand(Command):
    name = "/exit"
    description = "quit"
    args_spec = ""

    async def run(self, ctx: CommandContext, args: List[str]) -> int:
        ctx.session.should_exit = True
        return 0
