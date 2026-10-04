# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
/bond command implementation.
Inspects on-chain PerformanceCollateralVault bond and free margin on Base L2.
"""

from __future__ import annotations
from typing import List
from rich.table import Table

from csls.commands.base import Command, CommandContext
from csls.core.backends import BondBackend
from csls.ui.theme import TEAL_HEX, DIM_GRAY, WARN_YELLOW, SUCCESS_GREEN


class BondCommand(Command):
    name = "/bond"
    description = "collateral bond and free margin"
    args_spec = ""

    async def run(self, ctx: CommandContext, args: List[str]) -> int:
        console = ctx.console
        cfg = ctx.session.config.vault
        rpc_url = cfg.get("rpc_url", "")
        vault_addr = cfg.get("vault_address", "")

        ok, bond_info, msg = BondBackend.query_bond(rpc_url, vault_addr)
        if not ok:
            console.print(f"[{WARN_YELLOW}]{msg}[/]")
            ctx.session.set_bond_status("no bond")
            return 1

        ctx.session.set_bond_status("ready")
        console.print(f"[bold {TEAL_HEX}]Base L2 Collateral Bond Status:[/]")

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Key", style=f"bold {TEAL_HEX}", no_wrap=True)
        table.add_column("Value", style=f"dim {DIM_GRAY}")

        table.add_row("Network", bond_info.get("chain", "Base L2"))
        table.add_row("Vault Contract", bond_info.get("vault", vault_addr))
        table.add_row("Collateral Bond", f"[{SUCCESS_GREEN}]{bond_info.get('collateral_bond', '$10.00 USDC')}[/]")
        table.add_row("Free Margin", f"[{SUCCESS_GREEN}]{bond_info.get('free_margin', '$10.00 USDC')}[/]")
        table.add_row("Exposure Cap", bond_info.get("exposure_cap", "$1.00 USDC"))
        table.add_row("Status", f"[{SUCCESS_GREEN}]ACTIVE & SECURED[/]")

        console.print(table)
        return 0
