# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Session state for CSLS CLI.
Maintains live runtime status, bond state, active processes, and toolbar indicators.
"""

from __future__ import annotations
import os
import asyncio
from dataclasses import dataclass, field
from typing import List, Optional

from csls.core.config import CslsConfig, CONFIG_DIR, HISTORY_FILE


_UNSET = object()


@dataclass
class SessionState:
    config: CslsConfig = field(default_factory=CslsConfig.load)
    bond_status: str = "no bond"  # "ready" | "no bond" | "error"
    wallet_address: Optional[str] = _UNSET  # type: ignore
    vault_address: str = "0x8faAD06ef5937Ad1019CD49f5Dcab36181e266A5"
    collateral_usdc: float = 0.0
    free_margin_usdc: float = 0.0
    active_process: Optional[asyncio.subprocess.Process] = None
    running_task: Optional[asyncio.Task] = None
    current_model: str = "claude-opus-5.5"
    vendor_url: str = "https://gateway.causal-slash.net"
    conversation_memory: List[dict] = field(default_factory=list)
    accumulated_spent_usdc: float = 0.0
    total_queries: int = 0
    vendor_pk: Optional[str] = None
    session_initialized: bool = False
    should_exit: bool = False
    history_file: str = HISTORY_FILE
    cwd: str = field(default_factory=os.getcwd)

    @property
    def project_memory_file(self) -> str:
        """Deterministic path to project conversation memory file on disk."""
        import hashlib
        slug = hashlib.sha256(self.cwd.encode("utf-8")).hexdigest()[:12]
        proj_dir = os.path.join(CONFIG_DIR, "projects", slug)
        os.makedirs(proj_dir, exist_ok=True)
        return os.path.join(proj_dir, "chat_memory.json")

    def load_persistent_memory(self) -> None:
        """Load conversation memory from disk if available."""
        path = self.project_memory_file
        if os.path.exists(path):
            try:
                import json
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    self.conversation_memory = data[-50:]
            except Exception:
                pass

    def save_persistent_memory(self) -> None:
        """Atomically persist conversation memory to disk."""
        path = self.project_memory_file
        try:
            import json
            tmp_path = path + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(self.conversation_memory, f, indent=2, ensure_ascii=False)
            os.replace(tmp_path, path)
        except Exception:
            pass

    def clear_memory(self) -> None:
        """Clear conversation memory context both in RAM and on disk."""
        self.conversation_memory.clear()
        path = self.project_memory_file
        if os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass

    def add_dialog_turn(self, user_msg: str, assistant_msg: str) -> None:
        """Record dialog turn in rolling memory and persist to disk."""
        self.conversation_memory.append({"role": "user", "content": user_msg})
        self.conversation_memory.append({"role": "assistant", "content": assistant_msg})
        # Keep rolling memory limited to last 50 turns
        if len(self.conversation_memory) > 50:
            self.conversation_memory = self.conversation_memory[-50:]
        self.save_persistent_memory()

    def __post_init__(self) -> None:
        if hasattr(self.config, "agent") and isinstance(self.config.agent, dict):
            if "model" in self.config.agent:
                self.current_model = self.config.agent["model"]
            if "vendor_url" in self.config.agent:
                self.vendor_url = self.config.agent["vendor_url"]

        self.load_persistent_memory()

        if self.wallet_address is _UNSET:
            wallet_path = os.path.join(CONFIG_DIR, "wallet.json")
            if os.path.exists(wallet_path):
                try:
                    import json
                    with open(wallet_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    self.wallet_address = data.get("address")
                    self.collateral_usdc = float(data.get("collateral_bond", 0.0))
                    self.free_margin_usdc = float(data.get("free_margin", self.collateral_usdc))
                    if self.collateral_usdc > 0.0 and data.get("status") == "ready":
                        self.bond_status = "ready"
                    else:
                        self.bond_status = "no bond"
                except Exception:
                    self.bond_status = "no bond"
            else:
                self.wallet_address = None
                self.bond_status = "no bond"
                self.collateral_usdc = 0.0

    def set_bond_status(self, status: str) -> None:
        """Update live bond state for the bottom toolbar."""
        if status in ("ready", "no bond", "error"):
            self.bond_status = status
        else:
            self.bond_status = "error"

    def cancel_active_process(self) -> None:
        """Terminate currently running subprocess if any."""
        if self.active_process and self.active_process.returncode is None:
            try:
                self.active_process.terminate()
            except ProcessLookupError:
                pass
        if self.running_task and not self.running_task.done():
            self.running_task.cancel()
