# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
/status command implementation.
Displays live node status and streaming cheques using rich.live.Live.
Ctrl+C stops cleanly and returns to prompt.
"""

from __future__ import annotations
import asyncio
import sys
import time
from typing import List
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text

from csls.commands.base import Command, CommandContext
from csls.core.backends import DaemonBackend, BondBackend
from csls.ui.theme import TEAL_HEX, DIM_GRAY, WARN_YELLOW, SUCCESS_GREEN


class StatusCommand(Command):
    name = "/status"
    description = "status and live cheque stream"
    args_spec = ""

    async def run(self, ctx: CommandContext, args: List[str]) -> int:
        console = ctx.console
        daemon_port = ctx.session.config.daemon.get("port", 9444)
        is_daemon_up = DaemonBackend.check_daemon_running(port=daemon_port)

        def generate_status_renderable(tick: int):
            grid = Table.grid(padding=(0, 2))
            grid.add_column("Key", style=f"bold {TEAL_HEX}")
            grid.add_column("Val")

            d_status = f"[{SUCCESS_GREEN}]RUNNING (port {daemon_port})[/]" if is_daemon_up else f"[{WARN_YELLOW}]STOPPED[/]"
            b_status = f"[{SUCCESS_GREEN}]{ctx.session.bond_status}[/]" if ctx.session.bond_status == "ready" else f"[{WARN_YELLOW}]{ctx.session.bond_status}[/]"

            grid.add_row("Daemon Status:", d_status)
            grid.add_row("Vault Bond:", b_status)
            grid.add_row("Wallet:", ctx.session.wallet_address or "Not initialized (/wallet new)")
            grid.add_row("Live Cheque Stream:", f"[dim {DIM_GRAY}]Listening on port {daemon_port}... (tick {tick})[/]")
            grid.add_row("", f"[dim {DIM_GRAY}]Press Ctrl+C to return to prompt[/]")

            return Panel(grid, title=f"[{TEAL_HEX}]Causal-Slash Protocol Node Status[/]", border_style=DIM_GRAY)

        if not sys.stdin.isatty() or "--once" in args:
            console.print(generate_status_renderable(0))
            return 0

        console.print(f"[dim {DIM_GRAY}]Starting live status monitor... (Ctrl+C to exit)[/]")
        tick = 0
        try:
            with Live(generate_status_renderable(tick), console=console, refresh_per_second=2) as live:
                while True:
                    await asyncio.sleep(0.5)
                    tick += 1
                    is_daemon_up = DaemonBackend.check_daemon_running(port=daemon_port)
                    live.update(generate_status_renderable(tick))
        except asyncio.CancelledError:
            console.print(f"[dim {DIM_GRAY}]Status monitor stopped.[/]")
            return 0
        except KeyboardInterrupt:
            console.print(f"[dim {DIM_GRAY}]Status monitor stopped.[/]")
            return 0
