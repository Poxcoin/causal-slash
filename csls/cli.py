# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Causal-Slash CLI entry point and interactive shell controller.
"""

from __future__ import annotations
import asyncio
import os
import shlex
import sys
import time
from typing import List, Optional

from rich.console import Console

from csls.core.session import SessionState
from csls.core.agent import get_agent_backend
from csls.commands import registry
from csls.commands.base import CommandContext
from csls.ui.theme import create_console, TEAL_HEX, DIM_GRAY, ERROR_RED
from csls.ui.header import render_header, VERSION
from csls.ui.prompt import (
    create_prompt_session,
    make_prompt_message,
    make_bottom_toolbar,
    show_shortcuts_panel,
)
from csls.ui.gate import check_activation_needed, ensure_sovereign_identity, run_activation_gate


async def execute_line(raw_line: str, ctx: CommandContext) -> None:
    """Execute a single command line or free-text query."""
    console = ctx.console
    session = ctx.session
    stripped = raw_line.strip()
    if not stripped:
        return

    if stripped == "?":
        show_shortcuts_panel(console)
        return

    if stripped.startswith("/"):
        try:
            parts = shlex.split(stripped)
        except ValueError as e:
            console.print(f"[{ERROR_RED}]Parse error: {e}[/]")
            return

        cmd_name = parts[0].lower()
        cmd_args = parts[1:]

        cmd = registry.get(cmd_name)
        if cmd:
            task = asyncio.create_task(cmd.run(ctx, cmd_args))
            session.running_task = task
            try:
                await task
            except asyncio.CancelledError:
                console.print(f"[dim {DIM_GRAY}]Command cancelled.[/]")
            except Exception as e:
                console.print(f"[{ERROR_RED}]Error executing {cmd_name}: {e}[/]")
            finally:
                session.running_task = None
        else:
            console.print(f"[{ERROR_RED}]Unknown command: {cmd_name}[/]")
            suggestion = registry.get_closest_match(cmd_name)
            if suggestion:
                console.print(
                    f"[dim {DIM_GRAY}]Did you mean [bold {TEAL_HEX}]{suggestion}[/bold {TEAL_HEX}]?[/dim {DIM_GRAY}]"
                )
    else:
        # Free text query routed to AgentBackend
        agent = get_agent_backend(session)
        task = asyncio.create_task(agent.process_query(stripped, session, console))
        session.running_task = task
        try:
            await task
        except asyncio.CancelledError:
            console.print(f"[dim {DIM_GRAY}]Agent query cancelled.[/]")
        except Exception as e:
            console.print(f"[{ERROR_RED}]Agent error: {e}[/]")
        finally:
            session.running_task = None


async def run_interactive_shell(
    session: SessionState, console: Console, bypass_gate: bool = False
) -> int:
    """Run full interactive TUI shell with inline scrollback rendering."""
    # Render launch header
    render_header(
        console, cwd=session.cwd, memory_turns=len(session.conversation_memory) // 2
    )

    # Zero-Friction Autonomous Identity & Margin Auto-Provisioning
    if check_activation_needed(session):
        ensure_sovereign_identity(session)

    prompt_session = create_prompt_session(session)
    ctx = CommandContext(session=session, console=console)
    prompt_message = make_prompt_message()
    bottom_toolbar = make_bottom_toolbar(session)

    last_ctrl_c: float = 0.0

    while not session.should_exit:
        try:
            line = await prompt_session.prompt_async(
                prompt_message,
                bottom_toolbar=bottom_toolbar,
                placeholder="Type a command or /help",
            )
            last_ctrl_c = 0.0
        except KeyboardInterrupt:
            now = time.time()
            if now - last_ctrl_c < 1.0:
                console.print(f"[dim {DIM_GRAY}]Exiting CSLS.[/]")
                break
            last_ctrl_c = now
            console.print(f"[dim {DIM_GRAY}](Press Ctrl+C again or Ctrl+D to exit)[/]")
            continue
        except EOFError:
            console.print(f"[dim {DIM_GRAY}]Exiting CSLS.[/]")
            break

        await execute_line(line, ctx)

    return 0


async def run_non_interactive(session: SessionState, console: Console) -> int:
    """Run in non-interactive / piped mode (reading stdin lines until EOF)."""
    render_header(console, cwd=session.cwd)
    ctx = CommandContext(session=session, console=console)

    for line in sys.stdin:
        if session.should_exit:
            break
        await execute_line(line, ctx)

    return 0


async def async_main(argv: Optional[List[str]] = None) -> int:
    """Async main routine."""
    if argv is None:
        argv = sys.argv[1:]

    console = create_console()
    session = SessionState()

    bypass_gate = False
    if "--dev" in argv or "--bypass" in argv or "-b" in argv:
        bypass_gate = True
        argv = [a for a in argv if a not in ("--dev", "--bypass", "-b")]

    # CLI flags handling
    if argv:
        first = argv[0]
        if first in ("--setup", "-s"):
            render_header(console, cwd=session.cwd)
            run_activation_gate(session, console)
            return 0
        if first in ("-v", "--version"):
            console.print(f"Causal-Slash CLI {VERSION}")
            return 0
        if first in ("-h", "--help"):
            render_header(console, cwd=session.cwd)
            ctx = CommandContext(session=session, console=console)
            help_cmd = registry.get("/help")
            if help_cmd:
                return await help_cmd.run(ctx, argv[1:])
            return 0
        if first.startswith("/"):
            ctx = CommandContext(session=session, console=console)
            await execute_line(" ".join(argv), ctx)
            return 0

    # Interactive TUI mode or piped input
    if sys.stdin.isatty():
        return await run_interactive_shell(session, console, bypass_gate=bypass_gate)
    else:
        return await run_non_interactive(session, console)


def main() -> None:
    """Synchronous entry point registered in pyproject.toml."""
    try:
        code = asyncio.run(async_main())
        sys.exit(code)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
