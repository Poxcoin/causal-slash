# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
CSLS interactive prompt setup using prompt_toolkit.
Handles input box, horizontal rules, placeholder, bottom toolbar, autocomplete, and keybindings.
"""

from __future__ import annotations
import shutil
import sys
from typing import Optional, Callable
from prompt_toolkit.shortcuts import PromptSession
from prompt_toolkit.formatted_text import FormattedText, HTML
from prompt_toolkit.styles import Style
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from csls.core.session import SessionState
from csls.commands import CslsSlashCompleter
from csls.ui.theme import TEAL_HEX, DIM_GRAY, PROMPT_BLUE, WARN_YELLOW, ERROR_RED


def get_rule_character() -> str:
    """Return appropriate horizontal rule character for the terminal encoding."""
    try:
        "─".encode(sys.stdout.encoding or "utf-8")
        return "─"
    except Exception:
        return "-"


def create_csls_style() -> Style:
    """Build prompt_toolkit style with terminal's own background."""
    return Style.from_dict({
        "rule": f"#{DIM_GRAY.lstrip('#')}",
        "prompt": f"#{PROMPT_BLUE.lstrip('#')} bold",
        "placeholder": f"#{DIM_GRAY.lstrip('#')}",
        "bottom-toolbar": "",
        "toolbar.dim": f"#{DIM_GRAY.lstrip('#')}",
        "toolbar.ready": f"#{TEAL_HEX.lstrip('#')} bold",
        "toolbar.warn": f"#{WARN_YELLOW.lstrip('#')} bold",
        "toolbar.error": f"#{ERROR_RED.lstrip('#')} bold",
        "completion-menu": "",
        "completion-menu.completion": f"#{TEAL_HEX.lstrip('#')}",
        "completion-menu.completion.current": f"bold #{TEAL_HEX.lstrip('#')} underline",
        "completion-menu.meta": f"#{DIM_GRAY.lstrip('#')}",
        "completion-menu.meta.current": f"bold #{DIM_GRAY.lstrip('#')}",
    })


def create_csls_key_bindings() -> KeyBindings:
    """Keybindings: ? on empty line shows shortcuts, Esc clears line."""
    kb = KeyBindings()

    @kb.add("?")
    def handle_question_mark(event):
        buf = event.current_buffer
        if not buf.text:
            buf.text = "?"
            buf.validate_and_handle()
        else:
            buf.insert_text("?")

    @kb.add("escape")
    def handle_escape(event):
        event.current_buffer.text = ""

    return kb


def make_prompt_message() -> Callable[[], FormattedText]:
    """Generates the top horizontal rule and the prompt line '> '."""
    rule_char = get_rule_character()

    def _get_prompt() -> FormattedText:
        cols = shutil.get_terminal_size((80, 24)).columns
        rule_str = rule_char * cols
        return FormattedText([
            ("class:rule", rule_str + "\n"),
            ("class:prompt", "> "),
        ])

    return _get_prompt


def make_bottom_toolbar(session: SessionState) -> Callable[[], FormattedText]:
    """
    Generates the bottom horizontal rule and bottom toolbar under input:
    left dim '? for shortcuts', right teal 'bond: ready'.
    """
    rule_char = get_rule_character()

    def _get_toolbar() -> FormattedText:
        cols = shutil.get_terminal_size((80, 24)).columns
        rule_str = rule_char * cols
        left = "? for shortcuts"
        bond_status = session.bond_status
        right = f"bond: {bond_status}"

        # Calculate spacing between left and right indicators
        space_len = max(1, cols - len(left) - len(right))

        if bond_status == "ready":
            right_class = "class:toolbar.ready"
        elif bond_status == "no bond":
            right_class = "class:toolbar.warn"
        else:
            right_class = "class:toolbar.error"

        return FormattedText([
            ("class:rule", rule_str + "\n"),
            ("class:toolbar.dim", left),
            ("", " " * space_len),
            (right_class, right),
        ])

    return _get_toolbar


def show_shortcuts_panel(console: Console) -> None:
    """Render the shortcuts reference panel in rich."""
    table = Table(
        box=None,
        padding=(0, 2),
        collapse_padding=True,
    )
    table.add_column("Key / Command", style=f"bold {TEAL_HEX}", no_wrap=True)
    table.add_column("Action", style=f"dim {DIM_GRAY}")

    shortcuts = [
        ("?", "Show this shortcuts guide (when prompt is empty)"),
        ("/", "Open slash command autocomplete menu"),
        ("Tab / Enter", "Accept selected slash command"),
        ("Esc", "Clear current input line"),
        ("Up / Down", "Navigate persistent command history"),
        ("Ctrl+C", "Cancel running command (or double-press to quit)"),
        ("Ctrl+D", "Exit CSLS shell"),
        ("/help", "Display complete slash command reference"),
        ("/exit", "Quit CSLS shell"),
    ]
    for key, action in shortcuts:
        table.add_row(key, action)

    panel = Panel(
        table,
        title=f"[{TEAL_HEX}]Keyboard Shortcuts[/]",
        title_align="left",
        border_style=DIM_GRAY,
        box=box.ROUNDED,
        padding=(0, 1),
    )
    console.print()
    console.print(panel)
    console.print()


def create_prompt_session(session: SessionState) -> PromptSession:
    """Create and configure the PromptSession for the interactive shell."""
    return PromptSession(
        completer=CslsSlashCompleter(),
        complete_while_typing=True,
        key_bindings=create_csls_key_bindings(),
        history=FileHistory(session.history_file),
        auto_suggest=AutoSuggestFromHistory(),
        style=create_csls_style(),
    )
