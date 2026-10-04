# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Async subprocess runner for CSLS CLI.
Streams stdout/stderr line-by-line via rich and handles clean cancellation on Ctrl+C.
"""

from __future__ import annotations
import asyncio
import os
import sys
from typing import List, Optional, Callable
from rich.console import Console

from csls.core.session import SessionState
from csls.ui.theme import DIM_GRAY, ERROR_RED


async def run_subprocess_stream(
    cmd: List[str],
    session: SessionState,
    console: Console,
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
    on_line: Optional[Callable[[str], None]] = None,
) -> int:
    """
    Run subprocess and stream stdout and stderr line-by-line into the terminal.
    Cancels gracefully on Ctrl+C (SIGINT) without leaving orphan processes.
    """
    if cwd is None:
        cwd = session.cwd

    sub_env = os.environ.copy()
    if env:
        sub_env.update(env)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=cwd,
            env=sub_env,
        )
    except FileNotFoundError:
        console.print(f"[{ERROR_RED}]Error: Command not found: {cmd[0]}[/]")
        return 127
    except Exception as e:
        console.print(f"[{ERROR_RED}]Failed to start process: {e}[/]")
        return 1

    session.active_process = proc

    async def _read_stream():
        assert proc.stdout is not None
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            text = line.decode("utf-8", errors="replace").rstrip("\r\n")
            if on_line:
                on_line(text)
            else:
                console.print(text)

    try:
        await _read_stream()
        returncode = await proc.wait()
        return returncode
    except asyncio.CancelledError:
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=1.5)
        except (asyncio.TimeoutError, ProcessLookupError):
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        console.print(f"[dim {DIM_GRAY}]Command stopped by user.[/]")
        return 130
    finally:
        session.active_process = None
