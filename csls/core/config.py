# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Configuration manager for CSLS CLI.
Reads and writes ~/.csls/config.toml using standard library tomllib.
"""

from __future__ import annotations
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Dict

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

CONFIG_DIR = os.path.expanduser(os.environ.get("CSLS_HOME", "~/.csls"))
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.toml")
HISTORY_FILE = os.path.join(CONFIG_DIR, "history")

DEFAULT_TOML = """# Causal-Slash Protocol CLI Configuration
# Location: ~/.csls/config.toml

[general]
version = "0.3.0"
tagline = "Sovereign M2M clearing for autonomous agents"

[vault]
chain = "base"
rpc_url = "https://mainnet.base.org"
vault_address = "0x4b7f4336B26b7D99Afb7faE3b320dFFd22c9C802"

[daemon]
port = 9444
buffer = 1000000
vendor_sk = ""

[agent]
backend = "vendor"
vendor_url = "https://gateway.causal-slash.net"
model = "claude-opus-5.5"
"""


@dataclass
class CslsConfig:
    general: Dict[str, Any] = field(default_factory=lambda: {
        "version": "0.3.0",
        "tagline": "Sovereign M2M clearing for autonomous agents",
    })
    vault: Dict[str, Any] = field(default_factory=lambda: {
        "chain": "base",
        "rpc_url": "https://mainnet.base.org",
        "vault_address": "0x4b7f4336B26b7D99Afb7faE3b320dFFd22c9C802",
    })
    daemon: Dict[str, Any] = field(default_factory=lambda: {
        "port": 9444,
        "buffer": 1000000,
        "vendor_sk": "",
    })
    agent: Dict[str, Any] = field(default_factory=lambda: {
        "backend": "vendor",
        "vendor_url": "https://gateway.causal-slash.net",
        "model": "claude-opus-5.5",
    })

    @classmethod
    def load(cls, path: str = CONFIG_FILE) -> "CslsConfig":
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                f.write(DEFAULT_TOML)
            return cls()

        if tomllib is None:
            return cls()

        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
            return cls(
                general=data.get("general", {}),
                vault=data.get("vault", {}),
                daemon=data.get("daemon", {}),
                agent=data.get("agent", {}),
            )
        except Exception:
            return cls()
