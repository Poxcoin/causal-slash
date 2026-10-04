# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
/model command implementation.
Inspects or switches the active frontier model for sovereign M2M inference.
"""

from __future__ import annotations
from typing import List
from rich.table import Table

from csls.commands.base import Command, CommandContext
from csls.ui.theme import TEAL_HEX, DIM_GRAY, SUCCESS_GREEN

SUPPORTED_MODELS = [
    ("claude-opus-5.5", "Frontier reasoning, deep architecture, agentic coding (Default)"),
    ("claude-opus-4.6", "Extended context reasoning and formal verification"),
    ("deepseek-v4.1-flash", "Ultra-low-latency high-throughput agentic execution"),
    ("deepseek-v4-pro", "Frontier mathematics, code synthesis, and deep reasoning"),
    ("glm-5.3", "Multilingual frontier reasoning and complex workflows"),
    ("glm-5.2", "High-efficiency multilingual coding and logic routing"),
    ("gemini-3.8-flash", "Sub-10ms multimodal streaming and real-time tool orchestration"),
    ("gemini-3.8-live", "Bidirectional live audio/vision and real-time streaming"),
]


class ModelCommand(Command):
    name = "/model"
    description = "select or view active frontier model"
    args_spec = "[model_name]"

    async def run(self, ctx: CommandContext, args: List[str]) -> int:
        console = ctx.console
        session = ctx.session

        is_error = False
        if args:
            target = args[0].strip().lower()
            valid_names = [m[0].lower() for m in SUPPORTED_MODELS]
            if target in valid_names:
                session.current_model = target
                console.print(f"[{SUCCESS_GREEN}]Active model set to:[/] [bold {TEAL_HEX}]{target}[/]")
                return 0
            else:
                # Partial matching
                matched = [m[0] for m in SUPPORTED_MODELS if target in m[0].lower()]
                if len(matched) == 1:
                    session.current_model = matched[0]
                    console.print(f"[{SUCCESS_GREEN}]Active model set to:[/] [bold {TEAL_HEX}]{matched[0]}[/]")
                    return 0
                console.print(f"[red]Unknown model '{args[0]}'. See available models below:[/]")
                is_error = True

        # Display current and available models
        console.print()
        console.print(f"[bold {TEAL_HEX}]Active Model:[/] [cyan]{session.current_model}[/cyan]")
        console.print()

        table = Table(
            title=f"[{TEAL_HEX}]Supported Frontier Models (Zero API Keys)[/]",
            box=None,
            padding=(0, 2),
            collapse_padding=True,
        )
        table.add_column("Model ID", style=f"bold {TEAL_HEX}", no_wrap=True)
        table.add_column("Capabilities", style=f"dim {DIM_GRAY}")
        table.add_column("Status", no_wrap=True)

        for mid, desc in SUPPORTED_MODELS:
            status = f"[{SUCCESS_GREEN}]ACTIVE[/]" if mid.lower() == session.current_model.lower() else "[dim]Available[/dim]"
            table.add_row(mid, desc, status)

        console.print(table)
        console.print(f"[dim {DIM_GRAY}]Switch model with: [bold {TEAL_HEX}]/model <model_id>[/bold {TEAL_HEX}][/]")
        console.print()
        return 1 if is_error else 0
