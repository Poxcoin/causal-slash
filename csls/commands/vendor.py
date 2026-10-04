# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
/vendor command implementation.
Inspects connected Frontier Model Vendor Node status, settlement metrics, and latency.
"""

from __future__ import annotations
import time
from typing import List
from rich.table import Table
import httpx

from csls.commands.base import Command, CommandContext
from csls.ui.theme import TEAL_HEX, DIM_GRAY, SUCCESS_GREEN, WARN_YELLOW, ERROR_RED


class VendorCommand(Command):
    name = "/vendor"
    description = "vendor connection and settlement status"
    args_spec = "[status | ping | url]"

    async def run(self, ctx: CommandContext, args: List[str]) -> int:
        console = ctx.console
        session = ctx.session
        vendor_url = session.vendor_url.rstrip("/")

        if args and args[0].startswith("http"):
            session.vendor_url = args[0]
            session.session_initialized = False
            session.vendor_pk = None
            console.print(f"[{SUCCESS_GREEN}]Vendor URL updated to:[/] [bold {TEAL_HEX}]{args[0]}[/]")
            vendor_url = args[0].rstrip("/")

        console.print(f"[dim {DIM_GRAY}]Querying sovereign vendor node at {vendor_url}...[/]")
        t0 = time.time()
        is_healthy = False
        health_data = {}
        ping_ms = 0.0

        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(f"{vendor_url}/health")
                ping_ms = (time.time() - t0) * 1000
                if resp.status_code == 200:
                    is_healthy = True
                    health_data = resp.json()
        except Exception:
            is_healthy = False

        table = Table(
            title=f"[{TEAL_HEX}]Causal-Slash Frontier Vendor Connection[/]",
            box=None,
            padding=(0, 2),
            collapse_padding=True,
        )
        table.add_column("Property", style=f"bold {TEAL_HEX}", no_wrap=True)
        table.add_column("Status / Value", no_wrap=True)

        status_str = f"[{SUCCESS_GREEN}]ONLINE ({ping_ms:.1f} ms)[/]" if is_healthy else f"[{WARN_YELLOW}]UNREACHABLE[/]"
        table.add_row("Vendor Node:", vendor_url)
        table.add_row("Node Status:", status_str)
        table.add_row("Active Model:", f"[cyan]{session.current_model}[/cyan]")

        if is_healthy:
            table.add_row("Vendor Public Key:", health_data.get("vendor_pk", "n/a")[:18] + "...")
            table.add_row("Settlement Mode:", health_data.get("settlement_mode", "167-byte Session MAC"))
            table.add_row("Web2 API Keys:", health_data.get("web2_api_keys", "BANNED"))
            table.add_row("Edge Guardrail:", f"[{SUCCESS_GREEN}]{health_data.get('guardrail_status', 'active').upper()}[/]")

        table.add_row("Conversation Memory:", f"{len(session.conversation_memory)} turns recorded")
        table.add_row("Session Queries:", str(session.total_queries))
        table.add_row("Cumulative Settled:", f"[{SUCCESS_GREEN}]${session.accumulated_spent_usdc:.4f} USDC (0 gas)[/]")

        console.print(table)
        if not is_healthy:
            console.print(f"[dim {DIM_GRAY}]Connect to a sovereign vendor node via [bold {TEAL_HEX}]/vendor <url>[/bold {TEAL_HEX}][/]")
        console.print()
        return 0
