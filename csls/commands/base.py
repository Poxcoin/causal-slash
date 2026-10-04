# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Base command specification for CSLS slash commands.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional
from rich.console import Console

from csls.core.session import SessionState


@dataclass
class CommandContext:
    session: SessionState
    console: Console


class Command(ABC):
    """
    Abstract base class for all CSLS slash commands.
    name: The slash command identifier (e.g. "/help")
    description: Human-readable description
    args_spec: Arguments signature / specification
    """
    name: str = ""
    description: str = ""
    args_spec: str = ""

    @abstractmethod
    async def run(self, ctx: CommandContext, args: List[str]) -> int:
        """
        Execute command with given tokenized arguments.
        Returns exit code (0 for success).
        """
        pass
