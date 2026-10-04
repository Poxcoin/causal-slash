# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
/bench command implementation.
Executes latency, throughput, and sub-millisecond cryptographic settlement benchmarks.
"""

from __future__ import annotations
import os
import sys
from typing import List

from csls.commands.base import Command, CommandContext
from csls.core.backends import get_repo_root
from csls.core.runner import run_subprocess_stream
from csls.ui.theme import TEAL_HEX, WARN_YELLOW


class BenchCommand(Command):
    name = "/bench"
    description = "latency and throughput benchmark"
    args_spec = "[e2e | stream | quick]"

    async def run(self, ctx: CommandContext, args: List[str]) -> int:
        console = ctx.console
        root = get_repo_root()
        mode = args[0].lower() if args else "quick"

        bench_script = os.path.join(root, "benchmarks", "slashbench.py")
        if mode == "e2e":
            bench_script = os.path.join(root, "benchmarks", "benchmark_e2e_streaming.py")

        if not os.path.exists(bench_script):
            console.print(f"[{WARN_YELLOW}]not connected: benchmark script not found at {bench_script}[/]")
            return 1

        cmd = [sys.executable, bench_script] + args[1:]
        console.print(f"[{TEAL_HEX}]Running Causal-Slash protocol benchmark ({mode})...[/]")
        ret = await run_subprocess_stream(cmd, ctx.session, console, cwd=root)
        return ret
