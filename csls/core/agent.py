# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Agent Backend interface and implementations for CSLS terminal shell.
Routes free-text user queries to Sovereign M2M Frontier Model Vendors.
Zero Web2 API keys: uses 167-byte Session MAC micro-cheques over HTTP.
Maintains persistent conversational memory in the active session.
"""

from __future__ import annotations
import asyncio
from abc import ABC, abstractmethod
import json
import os
import sys
from typing import Optional, List, Dict, Any
from rich.console import Console
import httpx

from csls.core.session import SessionState
from csls.core.config import CONFIG_DIR
from csls.core.discovery import NetworkDiscovery
from csls.ui.theme import TEAL_HEX, DIM_GRAY, WARN_YELLOW, ERROR_RED, SUCCESS_GREEN

# Ensure SDK is in sys.path
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if os.path.join(_ROOT, "sdk") not in sys.path:
    sys.path.insert(0, os.path.join(_ROOT, "sdk"))

from causal_slash import CausalAgentWallet


class AgentBackend(ABC):
    """Abstract interface for autonomous agent backends."""

    @abstractmethod
    async def process_query(
        self, query: str, session: SessionState, console: Console
    ) -> None:
        """Process free-form user query and stream response."""
        pass


class StubAgentBackend(AgentBackend):
    """Fallback stub backend when no vendor or model proxy is active."""

    async def process_query(
        self, query: str, session: SessionState, console: Console
    ) -> None:
        console.print(f"[{WARN_YELLOW}]agent backend not configured[/]")
        console.print(
            f"[dim {DIM_GRAY}]Type a slash command (e.g. [bold]/help[/], [bold]/status[/], [bold]/wallet[/]) "
            f"or configure a vendor node via [bold]/vendor <url>[/bold].[/dim {DIM_GRAY}]"
        )


class VendorAgentBackend(AgentBackend):
    """
    Sovereign M2M Frontier Model Vendor Backend.
    - Zero human API keys.
    - Signed 167-byte Session MAC micro-cheques attached per request.
    - Streaming token delivery directly into rich console.
    - Persistent conversation memory across queries in session.
    """

    def __init__(self) -> None:
        self._wallet: Optional[CausalAgentWallet] = None

    def _get_wallet(self, session: SessionState, console: Console) -> Optional[CausalAgentWallet]:
        if self._wallet is not None:
            return self._wallet

        wallet_path = os.path.join(CONFIG_DIR, "wallet.json")
        if not os.path.exists(wallet_path):
            console.print(f"[{WARN_YELLOW}]No agent wallet found at {wallet_path}. Run [bold]/wallet new[/] first.[/]")
            return None

        try:
            with open(wallet_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            priv_hex = data.get("private_key", "")
            if not priv_hex:
                console.print(f"[{ERROR_RED}]Private key missing in wallet keystore.[/]")
                return None
            clean_hex = priv_hex.lower().replace("0x", "")
            self._wallet = CausalAgentWallet(agent_private_key=bytes.fromhex(clean_hex))
            return self._wallet
        except Exception as e:
            console.print(f"[{ERROR_RED}]Failed to load agent wallet: {e}[/]")
            return None

    async def process_query(
        self, query: str, session: SessionState, console: Console
    ) -> None:
        wallet = self._get_wallet(session, console)
        if wallet is None:
            return

        # 1. Dynamic Network Discovery
        active_url, health_data = await NetworkDiscovery.resolve_active_vendor(session.vendor_url)
        if not active_url or not health_data:
            console.print(f"[{ERROR_RED}]Network unreachable:[/] Failed to connect to Sovereign Vendor Network.")
            console.print(
                f"[dim {DIM_GRAY}]Check your internet connection or configure a remote vendor node via [bold]/vendor <url>[/bold].[/dim {DIM_GRAY}]"
            )
            return

        session.vendor_url = active_url
        vendor_url = active_url
        vendor_pk_hex = health_data.get("vendor_pk", "")
        if not vendor_pk_hex:
            console.print(f"[{ERROR_RED}]Vendor node at {vendor_url} did not provide a public key.[/]")
            return

        session.vendor_pk = vendor_pk_hex
        vendor_pk_bytes = bytes.fromhex(vendor_pk_hex.replace("0x", ""))

        async with httpx.AsyncClient(timeout=30.0) as client:

            # 2. Session MAC Handshake if not initialized
            if not session.session_initialized:
                try:
                    init_pkt = wallet.create_session(vendor_pk_bytes)
                    init_resp = await client.post(
                        f"{vendor_url}/v1/session/init",
                        json={"session_init_pkt": init_pkt.hex()},
                    )
                    if init_resp.status_code != 200:
                        console.print(f"[{ERROR_RED}]Session authentication failed: {init_resp.text}[/]")
                        return
                    session.session_initialized = True
                except Exception as e:
                    console.print(f"[{ERROR_RED}]Handshake error: {e}[/]")
                    return

            # 3. Build Conversation Context from Rolling Memory
            messages: List[Dict[str, str]] = list(session.conversation_memory)
            messages.append({"role": "user", "content": query})

            # 4. Sign 167-Byte Session MAC Micro-Cheque (0 Gas)
            price_per_call = session.config.agent.get("price_per_call", 0.0005)
            try:
                cheque = wallet.sign_cheque(vendor_pk_bytes, amount_usdc=price_per_call, session_mac=True)
                cheque_hex = "0x" + cheque.raw_packet.hex()
            except Exception as e:
                console.print(f"[{ERROR_RED}]Failed to sign micro-cheque: {e}[/]")
                return

            # 5. Stream Completion from Frontier Vendor
            payload = {
                "model": session.current_model,
                "messages": messages,
                "stream": True,
            }
            headers = {
                "Content-Type": "application/json",
                "X-Causal-Cheque": cheque_hex,
            }

            assistant_reply_chunks: List[str] = []

            try:
                async with client.stream(
                    "POST",
                    f"{vendor_url}/v1/chat/completions",
                    json=payload,
                    headers=headers,
                    timeout=60.0,
                ) as resp:
                    if resp.status_code != 200:
                        err_content = await resp.aread()
                        console.print(
                            f"[{ERROR_RED}]Vendor rejected request ({resp.status_code}): "
                            f"{err_content.decode('utf-8', errors='replace')}[/]"
                        )
                        return

                    async for line in resp.aiter_lines():
                        if not line:
                            continue
                        if line.startswith("data: "):
                            data_str = line[6:].strip()
                            if data_str == "[DONE]":
                                break
                            try:
                                chunk_json = json.loads(data_str)
                                choices = chunk_json.get("choices", [])
                                if choices:
                                    delta = choices[0].get("delta", {})
                                    content = delta.get("content", "")
                                    if content:
                                        assistant_reply_chunks.append(content)
                                        console.print(content, end="", highlight=False)
                            except Exception:
                                pass

            except asyncio.CancelledError:
                console.print(f"\n[dim {DIM_GRAY}]Stream cancelled by user.[/]")
                return
            except Exception as e:
                console.print(f"\n[{ERROR_RED}]Streaming error: {e}[/]")
                return

            full_reply = "".join(assistant_reply_chunks).strip()
            console.print()

            # 6. Update Persistent Conversation Memory & Metrics
            if full_reply:
                session.add_dialog_turn(query, full_reply)

            session.accumulated_spent_usdc += price_per_call
            session.total_queries += 1

            # 7. Settlement Audit Info
            console.print(
                f"[dim {DIM_GRAY}]── ${price_per_call:.4f} USDC settled (0 gas) | "
                f"seq #{cheque.height} | model: [bold {TEAL_HEX}]{session.current_model}[/bold {TEAL_HEX}][/]"
            )
            console.print()


def get_agent_backend(session: SessionState) -> AgentBackend:
    """Factory to retrieve configured agent backend."""
    backend_type = session.config.agent.get("backend", "vendor").lower()
    if backend_type == "stub":
        return StubAgentBackend()
    return VendorAgentBackend()
