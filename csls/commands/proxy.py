# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
/proxy command implementation.
Starts the SlashSidecarProxy reverse proxy sidecar.
"""

from __future__ import annotations
import sys
from typing import List

from csls.commands.base import Command, CommandContext
from csls.core.backends import ProxyBackend
from csls.core.runner import run_subprocess_stream
from csls.ui.theme import WARN_YELLOW, TEAL_HEX


class ProxyCommand(Command):
    name = "/proxy"
    description = "start SlashSidecarProxy sidecar"
    args_spec = "[--price 0.0005] [--port 8999] [--host 127.0.0.1]"

    async def run(self, ctx: CommandContext, args: List[str]) -> int:
        console = ctx.console
        ok, script_or_msg = ProxyBackend.get_proxy_script()
        if not ok:
            console.print(f"[{WARN_YELLOW}]{script_or_msg}[/]")
            return 1

        cmd = [sys.executable, script_or_msg] + args
        console.print(f"[{TEAL_HEX}]Starting SlashSidecarProxy sidecar... (Ctrl+C to stop)[/]")
        ret = await run_subprocess_stream(cmd, ctx.session, console)
        return ret
