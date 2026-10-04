# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Theme and color definitions for CSLS terminal UI.

Rules:
- Never paint a background color (use terminal's own background).
- Accent: teal #21E2CC (from logo).
- Secondary text: dim gray.
- Prompt: blue.
- Errors: red, warnings: yellow.
"""

import os
import sys
from rich.console import Console
from rich.theme import Theme

TEAL_HEX = "#21E2CC"
DIM_GRAY = "#888888"
PROMPT_BLUE = "#3B82F6"
ERROR_RED = "#EF4444"
WARN_YELLOW = "#F59E0B"
SUCCESS_GREEN = "#10B981"

# Rich theme for CSLS
CSLS_THEME = Theme({
    "accent": f"bold {TEAL_HEX}",
    "accent.dim": TEAL_HEX,
    "secondary": f"dim {DIM_GRAY}",
    "prompt": f"bold {PROMPT_BLUE}",
    "error": f"bold {ERROR_RED}",
    "warning": f"bold {WARN_YELLOW}",
    "success": f"bold {SUCCESS_GREEN}",
    "info": "dim",
    "command": f"bold {TEAL_HEX}",
    "arg": "italic cyan",
    "tagline": f"dim {DIM_GRAY}",
    "cwd": f"dim {DIM_GRAY}",
    "rule": f"{DIM_GRAY}",
})


def has_truecolor() -> bool:
    """Check if current terminal environment supports 24-bit truecolor."""
    colorterm = os.environ.get("COLORTERM", "").lower()
    if colorterm in ("truecolor", "24bit"):
        return True
    term = os.environ.get("TERM", "").lower()
    if "256color" in term or "xterm" in term or "kitty" in term or "alacritty" in term:
        return True
    return sys.stdout.isatty()


def create_console() -> Console:
    """Create a rich Console configured with CSLS theme and no background painting."""
    return Console(
        theme=CSLS_THEME,
        highlight=False,
        soft_wrap=False,
    )
