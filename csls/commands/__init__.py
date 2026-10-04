# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
CSLS Command Registry and Autocomplete Completer.
Ensures autocomplete and /help derive from identical source of truth.
"""

from __future__ import annotations
import difflib
from typing import Dict, List, Optional, Iterable

from prompt_toolkit.completion import Completer, Completion, CompleteEvent
from prompt_toolkit.document import Document

from csls.commands.base import Command, CommandContext
from csls.commands.help import HelpCommand
from csls.commands.daemon import DaemonCommand
from csls.commands.proxy import ProxyCommand
from csls.commands.wallet import WalletCommand
from csls.commands.bond import BondCommand
from csls.commands.status import StatusCommand
from csls.commands.stream import StreamCommand
from csls.commands.net import NetCommand
from csls.commands.hound import HoundCommand
from csls.commands.test import TestCommand
from csls.commands.bench import BenchCommand
from csls.commands.verify import VerifyCommand
from csls.commands.exit import ExitCommand
from csls.commands.model import ModelCommand
from csls.commands.vendor import VendorCommand
from csls.commands.clear import ClearCommand
from csls.commands.memory import MemoryCommand
from csls.commands.exit import ExitCommand

class CommandRegistry:
    """Registry maintaining all slash commands."""

    def __init__(self) -> None:
        self._commands: Dict[str, Command] = {}
        self._ordered: List[Command] = []

    def register(self, command: Command) -> None:
        name = command.name.lower()
        self._commands[name] = command
        if command not in self._ordered:
            self._ordered.append(command)

    def get(self, name: str) -> Optional[Command]:
        return self._commands.get(name.lower())

    def list_all(self) -> List[Command]:
        return list(self._ordered)

    def get_closest_match(self, name: str) -> Optional[str]:
        """Find the closest valid slash command for a typo/unknown command."""
        target = name.lower()
        if not target.startswith("/"):
            target = "/" + target
        valid_names = list(self._commands.keys())
        matches = difflib.get_close_matches(target, valid_names, n=1, cutoff=0.35)
        if matches:
            return matches[0]
        return None


# Global registry singleton
registry = CommandRegistry()

# Register core slash commands
registry.register(HelpCommand())
registry.register(DaemonCommand())
registry.register(ProxyCommand())
registry.register(WalletCommand())
registry.register(BondCommand())
registry.register(StatusCommand())
registry.register(StreamCommand())
registry.register(NetCommand())
registry.register(HoundCommand())
registry.register(TestCommand())
registry.register(BenchCommand())
registry.register(VerifyCommand())
registry.register(ModelCommand())
registry.register(VendorCommand())
registry.register(ClearCommand())
registry.register(MemoryCommand())
registry.register(ExitCommand())


class CslsSlashCompleter(Completer):
    """
    Prompt-toolkit completer triggered on '/' or typing.
    Displays command name on left, description on right.
    """

    def get_completions(
        self, document: Document, complete_event: CompleteEvent
    ) -> Iterable[Completion]:
        text = document.text_before_cursor.lstrip()

        # If empty or not starting with slash, do not show slash commands
        if not text.startswith("/"):
            return

        tokens = text.split()
        is_first_word = len(tokens) <= 1 and not text.endswith(" ")

        if is_first_word:
            word = tokens[0] if tokens else "/"
            for cmd in registry.list_all():
                if cmd.name.lower().startswith(word.lower()):
                    yield Completion(
                        cmd.name,
                        start_position=-len(word),
                        display=cmd.name,
                        display_meta=cmd.description,
                    )
        elif len(tokens) >= 1:
            cmd_name = tokens[0].lower()
            current_word = tokens[-1] if not text.endswith(" ") else ""

            # Specialized argument autocompletions
            if cmd_name == "/wallet":
                subcmds = [
                    ("new", "generate fresh secp256k1 keypair"),
                    ("info", "display loaded wallet and public key"),
                ]
                for sub, desc in subcmds:
                    if sub.startswith(current_word.lower()):
                        yield Completion(
                            sub,
                            start_position=-len(current_word),
                            display=sub,
                            display_meta=desc,
                        )
            elif cmd_name == "/daemon":
                flags = [
                    ("--port", "C11 UDP/TCP port (default 9444)"),
                    ("--vendor-sk", "vendor private key (64 hex characters)"),
                    ("--buffer", "ring buffer capacity (packets)"),
                    ("--no-mac", "disable HMAC-SHA256 signature verification"),
                    ("--max-conns", "maximum concurrent M2M connections"),
                    ("--bind", "bind IP address (default 127.0.0.1)"),
                ]
                for flag, desc in flags:
                    if flag.startswith(current_word.lower()) and flag not in tokens[:-1]:
                        yield Completion(
                            flag,
                            start_position=-len(current_word),
                            display=flag,
                            display_meta=desc,
                        )
            elif cmd_name == "/proxy":
                flags = [
                    ("--price", "price per request in USDC (default 0.0005)"),
                    ("--port", "reverse proxy listening port (default 8999)"),
                    ("--target", "upstream backend URL"),
                ]
                for flag, desc in flags:
                    if flag.startswith(current_word.lower()) and flag not in tokens[:-1]:
                        yield Completion(
                            flag,
                            start_position=-len(current_word),
                            display=flag,
                            display_meta=desc,
                        )
            elif cmd_name == "/test":
                suites = [
                    ("c11", "C11 daemon unit and benchmark test suite"),
                    ("foundry", "Foundry smart contract invariant tests"),
                    ("pytest", "Python SDK integration and agent tests"),
                    ("all", "run all test suites"),
                ]
                for suite, desc in suites:
                    if suite.startswith(current_word.lower()):
                        yield Completion(
                            suite,
                            start_position=-len(current_word),
                            display=suite,
                            display_meta=desc,
                        )
            elif cmd_name == "/model":
                models = [
                    ("claude-opus-5.5", "Frontier reasoning, deep architecture, agentic coding (Default)"),
                    ("claude-opus-4.6", "Extended context reasoning and formal verification"),
                    ("deepseek-v4.1-flash", "Ultra-low-latency high-throughput agentic execution"),
                    ("deepseek-v4-pro", "Frontier mathematics, code synthesis, and deep reasoning"),
                    ("glm-5.3", "Multilingual frontier reasoning and complex workflows"),
                    ("glm-5.2", "High-efficiency multilingual coding and logic routing"),
                    ("gemini-3.8-flash", "Sub-10ms multimodal streaming and real-time tool orchestration"),
                    ("gemini-3.8-live", "Bidirectional live audio/vision and real-time streaming"),
                ]
                for mid, desc in models:
                    if mid.startswith(current_word.lower()):
                        yield Completion(
                            mid,
                            start_position=-len(current_word),
                            display=mid,
                            display_meta=desc,
                        )


__all__ = ["registry", "CommandRegistry", "CslsSlashCompleter"]
