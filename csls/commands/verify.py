# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
/verify command implementation.
Inspects contract addresses, deployment status, and bytecode sizes against EIP-170 limit.
"""

from __future__ import annotations
import json
import os
from typing import List, Dict, Any, Optional
from rich.table import Table
from rich.panel import Panel

from csls.commands.base import Command, CommandContext
from csls.core.backends import VerificationBackend, get_repo_root
from csls.ui.theme import TEAL_HEX, DIM_GRAY, WARN_YELLOW

# EIP-170 limit for contract code size
MAX_BYTECODE_SIZE = 24576


class VerifyCommand(Command):
    name = "/verify"
    description = "contract addresses and bytecode size"
    args_spec = "[contract]"

    async def run(self, ctx: CommandContext, args: List[str]) -> int:
        console = ctx.console
        ok, res = VerificationBackend.check_contracts()
        if not ok:
            console.print(f"[{WARN_YELLOW}]{res}[/]")
            return 1

        root = get_repo_root()
        receipt_path = os.path.join(root, "scripts", "deployment_receipt_base_sepolia.json")
        receipt_data: Dict[str, Any] = {}
        if os.path.exists(receipt_path):
            try:
                with open(receipt_path, "r", encoding="utf-8") as f:
                    receipt_data = json.load(f)
            except Exception:
                receipt_data = {}

        contracts = [
            {
                "name": "PerformanceCollateralVault",
                "file": "PerformanceCollateralVault.sol",
                "address": receipt_data.get("performanceCollateralVault", "Not deployed"),
                "network": receipt_data.get("network", "Base Sepolia (84532)"),
            },
            {
                "name": "SwarmDelegationVault",
                "file": "SwarmDelegationVault.sol",
                "address": receipt_data.get("swarmDelegationVault", "Not deployed"),
                "network": receipt_data.get("network", "Base Sepolia (84532)"),
            },
            {
                "name": "MockUSDC",
                "file": "MockUSDC.sol",
                "address": receipt_data.get("mockUSDC", "Not deployed"),
                "network": receipt_data.get("network", "Base Sepolia (84532)"),
            },
        ]

        if args:
            filter_name = args[0].lower()
            contracts = [c for c in contracts if filter_name in c["name"].lower()]
            if not contracts:
                console.print(f"[red]No contract matches '{args[0]}'[/]")
                return 1

        table = Table(
            title=f"[{TEAL_HEX}]On-Chain Contracts & EIP-170 Verification[/]",
            box=None,
            padding=(0, 1),
            collapse_padding=True,
        )
        table.add_column("Contract", style=f"bold {TEAL_HEX}", no_wrap=True, min_width=25)
        table.add_column("Address", style="cyan", no_wrap=True)
        table.add_column("Bytecode", no_wrap=True)
        table.add_column("Limit Margin", no_wrap=True)
        table.add_column("Network", style=f"dim {DIM_GRAY}", no_wrap=True)

        for c in contracts:
            c_name = c["name"]
            c_file = c["file"]
            json_path = os.path.join(root, "out", c_file, f"{c_name}.json")

            size_str = "n/a"
            margin_str = "n/a"

            if os.path.exists(json_path):
                try:
                    with open(json_path, "r", encoding="utf-8") as f:
                        artifact = json.load(f)
                    hex_code = artifact.get("deployedBytecode", {}).get("object", "")
                    if hex_code.startswith("0x"):
                        hex_code = hex_code[2:]
                    byte_size = len(hex_code) // 2
                    pct = (byte_size / MAX_BYTECODE_SIZE) * 100
                    color = "green" if pct < 85 else ("yellow" if pct < 98 else "red")
                    size_str = f"[{color}]{byte_size:,} B[/]"
                    margin_str = f"[{color}]{pct:.1f}% / 24KB[/]"
                except Exception as e:
                    size_str = f"[dim]err: {e}[/dim]"
                    margin_str = "n/a"

            addr_display = c["address"]
            if len(addr_display) == 42 and console.width < 100:
                addr_display = f"{addr_display[:6]}...{addr_display[-4:]}"

            table.add_row(
                c_name,
                addr_display,
                size_str,
                margin_str,
                "Base Sepolia" if "Base" in c["network"] else c["network"]
            )

        console.print(table)
        console.print(f"[dim {DIM_GRAY}]Max contract size limit (EIP-170): 24,576 bytes[/]")
        return 0
