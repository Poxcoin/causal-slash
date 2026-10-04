# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
/daemon command implementation.
Starts the C11 high-throughput streaming daemon.
"""

from __future__ import annotations
from typing import List

from csls.commands.base import Command, CommandContext
from csls.core.backends import DaemonBackend
from csls.core.runner import run_subprocess_stream
from csls.ui.theme import WARN_YELLOW, DIM_GRAY, TEAL_HEX


class DaemonCommand(Command):
    name = "/daemon"
    description = "start C11 streaming daemon"
    args_spec = "[--port N] [--vendor-sk KEY] [--buffer N] [--no-mac] [--max-conns N] [--bind ADDR]"

    async def run(self, ctx: CommandContext, args: List[str]) -> int:
        console = ctx.console
        ok, bin_or_msg = DaemonBackend.get_daemon_binary()
        if not ok:
            console.print(f"[{WARN_YELLOW}]{bin_or_msg}[/]")
            return 1

        # Check required args for vendor-sk if starting in listening mode
        has_sk = False
        for i, a in enumerate(args):
            if a == "--vendor-sk" and i + 1 < len(args):
                has_sk = True
                break

        # Fallback vendor-sk for local testing if not passed
        cmd_args = list(args)
        if not has_sk and "-h" not in args and "--help" not in args:
            cfg_sk = ctx.session.config.daemon.get("vendor_sk", "")
            if cfg_sk:
                cmd_args.extend(["--vendor-sk", cfg_sk])
            else:
                # Default 64 hex char deterministic local vendor test key
                default_sk = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                console.print(f"[dim {DIM_GRAY}]Note: --vendor-sk not provided, using local node key.[/]")
                cmd_args.extend(["--vendor-sk", default_sk])

        full_cmd = [bin_or_msg] + cmd_args
        console.print(f"[{TEAL_HEX}]Launching C11 streaming daemon... (Ctrl+C to stop)[/]")
        ret = await run_subprocess_stream(full_cmd, ctx.session, console)
        return ret
