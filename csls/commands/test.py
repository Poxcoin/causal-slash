# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
/test command implementation.
Executes C11, Foundry, and pytest suites with real-time streamed output.
"""

from __future__ import annotations
import shutil
from typing import List

from csls.commands.base import Command, CommandContext
from csls.core.backends import get_repo_root
from csls.core.runner import run_subprocess_stream
from csls.ui.theme import TEAL_HEX, DIM_GRAY, WARN_YELLOW, ERROR_RED, SUCCESS_GREEN


class TestCommand(Command):
    name = "/test"
    description = "run C11, Foundry and pytest suites"
    args_spec = "[all | c | forge | pytest]"

    async def run(self, ctx: CommandContext, args: List[str]) -> int:
        console = ctx.console
        root = get_repo_root()
        mode = args[0].lower() if args else "all"

        tasks = []
        if mode in ("all", "c"):
            if shutil.which("make"):
                tasks.append(("C11 Daemon Suite", ["make", "test"]))
            else:
                console.print(f"[{WARN_YELLOW}]not connected: `make` not found in PATH[/]")

        if mode in ("all", "forge"):
            if shutil.which("forge"):
                tasks.append(("Foundry Contract Suite", ["forge", "test"]))
            else:
                console.print(f"[{WARN_YELLOW}]not connected: `forge` (Foundry) not found in PATH[/]")

        if mode in ("all", "pytest"):
            tasks.append(("Python SDK Suite", ["pytest", "-q", "--tb=short"]))

        if not tasks:
            console.print(f"[red]No test runners available for mode: {mode}[/]")
            return 1

        overall_ok = True
        for name, cmd in tasks:
            console.print(f"[{TEAL_HEX}]Running {name}...[/]")
            ret = await run_subprocess_stream(cmd, ctx.session, console, cwd=root)
            if ret != 0:
                overall_ok = False
                console.print(f"[{ERROR_RED}]✗ {name} failed with exit code {ret}[/]")
            else:
                console.print(f"[{SUCCESS_GREEN}]✓ {name} passed[/]")
            console.print()

        return 0 if overall_ok else 1
