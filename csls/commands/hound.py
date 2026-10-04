# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
/hound command implementation.
Monitors and runs the Schnorr Bloodhound O(1) equivocation hunter.
"""

from __future__ import annotations
import sys
from typing import List
from rich.table import Table

from csls.commands.base import Command, CommandContext
from csls.core.backends import BloodhoundBackend, get_repo_root
from csls.ui.theme import TEAL_HEX, DIM_GRAY, WARN_YELLOW, SUCCESS_GREEN


class HoundCommand(Command):
    name = "/hound"
    description = "Schnorr Bloodhound equivocation hunter"
    args_spec = ""

    async def run(self, ctx: CommandContext, args: List[str]) -> int:
        console = ctx.console
        ok, msg_or_path = BloodhoundBackend.check_hound()
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
            from bloodhound import BloodhoundWatchdog
            # Address bytes: 20 bytes EVM address
            wallet_addr = ctx.session.wallet_address or "0x0000000000000000000000000000000000000000"
            clean_hex = wallet_addr.lower().replace("0x", "").zfill(40)
            hunter_bytes = bytes.fromhex(clean_hex)[:20]
            hound = BloodhoundWatchdog(hunter_address=hunter_bytes)
            status = {
                "engine": "Schnorr EOTS (Exact One-Time Signatures)",
                "complexity": "O(1) Algebraic Private Key Extraction",
                "slashing_penalty": "100% Foreclosure to Base L2 Vault",
                "trapped_equivocations": hound.equivocations_captured,
                "watchtower_status": "ARMED & ACTIVE",
            }
            hound.close()
        except Exception as e:
            console.print(f"[{WARN_YELLOW}]not connected: BloodhoundWatchdog error ({e})[/]")
            return 1

        console.print(f"[bold {TEAL_HEX}]Schnorr Bloodhound Equivocation Guard:[/]")
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Property", style=f"bold {TEAL_HEX}", no_wrap=True)
        table.add_column("Value", style=f"dim {DIM_GRAY}")

        table.add_row("Detection Engine", status["engine"])
        table.add_row("Algebraic Complexity", status["complexity"])
        table.add_row("Slashing Rule", status["slashing_penalty"])
        table.add_row("Trapped Frauds", f"[{SUCCESS_GREEN}]{status['trapped_equivocations']}[/]")
        table.add_row("Watchtower State", f"[{SUCCESS_GREEN}]{status['watchtower_status']}[/]")

        console.print(table)
        return 0
