# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
/stream command implementation.
Inspects live 167-byte cheque stream from local C11 daemon.
Uses rich.live.Live and stops cleanly on Ctrl+C.
"""

from __future__ import annotations
import asyncio
from typing import List
from rich.table import Table
from rich.live import Live

from csls.commands.base import Command, CommandContext
from csls.core.backends import ChequeStreamBackend
from csls.ui.theme import TEAL_HEX, DIM_GRAY, WARN_YELLOW


class StreamCommand(Command):
    name = "/stream"
    description = "live 167-byte cheque stream"
    args_spec = "[--port 9444]"

    async def run(self, ctx: CommandContext, args: List[str]) -> int:
        console = ctx.console
        port = ctx.session.config.daemon.get("port", 9444)
        for i, a in enumerate(args):
            if a == "--port" and i + 1 < len(args):
                try:
                    port = int(args[i + 1])
                except ValueError:
                    pass

        ok, msg = ChequeStreamBackend.check_stream(port=port)
        if not ok:
            console.print(f"[{WARN_YELLOW}]{msg}[/]")
            return 1

        console.print(f"[bold {TEAL_HEX}]Listening for 167-byte Session MAC cheques on 127.0.0.1:{port}...[/]")
        console.print(f"[dim {DIM_GRAY}]Press Ctrl+C to return to prompt.[/]")

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                count = 0
                while True:
                    data = await reader.read(167)
                    if not data:
                        console.print(f"[dim {DIM_GRAY}]Stream closed by daemon.[/]")
                        break
                    count += 1
                    console.print(
                        f"[{TEAL_HEX}]Cheque #{count:04d}[/] "
                        f"[dim {DIM_GRAY}]len={len(data)}B payload={data[:16].hex()}...[/]"
                    )
            finally:
                writer.close()
                await writer.wait_closed()
        except asyncio.CancelledError:
            console.print(f"[dim {DIM_GRAY}]Cheque stream closed.[/]")
            return 0
        except (ConnectionRefusedError, OSError) as e:
            console.print(f"[{WARN_YELLOW}]not connected: failed to stream from 127.0.0.1:{port} ({e})[/]")
            return 1
        return 0
