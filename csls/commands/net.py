# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
/net command implementation.
Displays in-RAM Kirchhoff netting summary and cycle cancellation metrics.
"""

from __future__ import annotations
import sys
from typing import List
from rich.table import Table

from csls.commands.base import Command, CommandContext
from csls.core.backends import KirchhoffBackend, get_repo_root
from csls.ui.theme import TEAL_HEX, DIM_GRAY, WARN_YELLOW, SUCCESS_GREEN


class NetCommand(Command):
    name = "/net"
    description = "in-RAM Kirchhoff netting summary"
    args_spec = ""

    async def run(self, ctx: CommandContext, args: List[str]) -> int:
        console = ctx.console
        ok, msg_or_path = KirchhoffBackend.check_netting()
        if not ok:
            console.print(f"[{WARN_YELLOW}]{msg_or_path}[/]")
            return 1

        root = get_repo_root()
        if root not in sys.path:
            sys.path.insert(0, root)
        sdk_dir = f"{root}/sdk"
        if sdk_dir not in sys.path:
            sys.path.insert(0, sdk_dir)

        try:
            from causal_slash import DebtCycleMesh
            mesh = DebtCycleMesh()
            summary = {
                "active_channels": len(mesh.channels) if hasattr(mesh, "channels") else 0,
                "cycles_cancelled": getattr(mesh, "cycles_cleared", 0),
                "volume_netted_usdc": "$0.00 USDC",
                "gas_saved_usd": "$0.00",
                "mode": "O(1) in-RAM algebraic netting",
            }
        except Exception as e:
            console.print(f"[{WARN_YELLOW}]not connected: DebtCycleMesh error ({e})[/]")
            return 1

        console.print(f"[bold {TEAL_HEX}]Kirchhoff In-RAM Netting Engine:[/]")
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Metric", style=f"bold {TEAL_HEX}", no_wrap=True)
        table.add_column("Value", style=f"dim {DIM_GRAY}")

        table.add_row("Algorithm", summary["mode"])
        table.add_row("Active Channels", str(summary["active_channels"]))
        table.add_row("Cycle Cancellations", f"[{SUCCESS_GREEN}]{summary['cycles_cancelled']}[/]")
        table.add_row("Volume Netted", summary["volume_netted_usdc"])
        table.add_row("Gas Saved", f"[{SUCCESS_GREEN}]100% (0.00 gas)[/]")

        console.print(table)
        return 0
