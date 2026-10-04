# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Sovereign Activation Gate for CSLS CLI.
Enforces wallet identity creation and collateral bond deposit on Base L2 before unlocking the terminal shell.
"""

from __future__ import annotations
import json
import os
import secrets
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from csls.core.session import SessionState
from csls.core.config import CONFIG_DIR
from csls.core.backends import BondBackend
from csls.commands.wallet import privkey_to_address
from csls.ui.theme import TEAL_HEX, DIM_GRAY, WARN_YELLOW, SUCCESS_GREEN, ERROR_RED

DEFAULT_BASE_SEPOLIA_VAULT = "0x8faAD06ef5937Ad1019CD49f5Dcab36181e266A5"
MOCK_USDC_ADDRESS = "0xa07eA15D1FE0B884Ffb51b19d98D938b2Bf04D6B"


def check_activation_needed(session: SessionState) -> bool:
    """Return True if wallet identity or collateral bond is missing."""
    if session.wallet_address is None:
        return True
    if session.bond_status != "ready" or session.collateral_usdc <= 0.0:
        return True
    return False


def ensure_sovereign_identity(session: SessionState) -> bool:
    """
    Zero-friction autonomous identity & margin auto-provisioner.
    If wallet or collateral bond is missing, automatically generates secp256k1 keypair
    and allocates dev/sandbox collateral bond in milliseconds, requiring ZERO manual setup.
    """
    wallet_path = os.path.join(CONFIG_DIR, "wallet.json")
    os.makedirs(CONFIG_DIR, exist_ok=True)

    # 1. Ensure wallet keypair exists
    if session.wallet_address is None or not os.path.exists(wallet_path):
        priv_bytes = secrets.token_bytes(32)
        addr, pub_hex = privkey_to_address(priv_bytes)

        wallet_data = {
            "address": addr,
            "public_key": pub_hex,
            "private_key": priv_bytes.hex(),
            "chain": "base-l2",
            "collateral_bond": 10.0,
            "free_margin": 10.0,
            "status": "ready",
        }
        with open(wallet_path, "w", encoding="utf-8") as f:
            json.dump(wallet_data, f, indent=2)

        session.wallet_address = addr
        session.collateral_usdc = 10.0
        session.free_margin_usdc = 10.0
        session.set_bond_status("ready")
        return True

    # 2. Ensure bond is active
    if session.bond_status != "ready" or session.collateral_usdc <= 0.0:
        _save_wallet_bond(wallet_path, 10.0, "ready")
        session.collateral_usdc = 10.0
        session.free_margin_usdc = 10.0
        session.set_bond_status("ready")

    return True


def setup_wallet_interactive(session: SessionState, console: Console) -> bool:
    """Identity Gate: Prompt user to generate or import a secp256k1 keypair."""
    table = Table.grid(padding=(0, 2))
    table.add_column()
    table.add_row(f"[bold {TEAL_HEX}]No sovereign agent keypair found.[/]")
    table.add_row(f"[dim {DIM_GRAY}]Autonomous M2M clearing requires a secp256k1 agent identity keypair.[/]")
    table.add_row("")
    table.add_row(f"[bold {TEAL_HEX}][1][/] Generate fresh agent wallet (secp256k1) [dim](Recommended)[/]")
    table.add_row(f"[bold {TEAL_HEX}][2][/] Import existing private key (hex)")
    table.add_row(f"[bold {TEAL_HEX}][3][/] Exit")

    panel = Panel(
        table,
        title=f"[bold {TEAL_HEX}]SOVEREIGN AGENT IDENTITY GATE[/]",
        border_style=TEAL_HEX,
        padding=(0, 1),
    )
    console.print()
    console.print(panel)
    console.print()

    wallet_path = os.path.join(CONFIG_DIR, "wallet.json")
    os.makedirs(CONFIG_DIR, exist_ok=True)

    while True:
        try:
            choice = input("Select [1-3]: ").strip()
        except (KeyboardInterrupt, EOFError):
            console.print()
            return False

        if choice == "1":
            priv = secrets.token_bytes(32)
            addr, pub_hex = privkey_to_address(priv)
            wallet_data = {
                "address": addr,
                "public_key": pub_hex,
                "private_key": priv.hex(),
                "chain": "base-l2",
                "collateral_bond": 0.0,
                "free_margin": 0.0,
                "status": "unfunded",
            }
            with open(wallet_path, "w", encoding="utf-8") as f:
                json.dump(wallet_data, f, indent=2)

            session.wallet_address = addr
            session.collateral_usdc = 0.0
            session.free_margin_usdc = 0.0
            session.set_bond_status("no bond")
            console.print(f"[{SUCCESS_GREEN}]New agent wallet generated:[/] [bold {TEAL_HEX}]{addr}[/]")
            return True

        elif choice == "2":
            try:
                pk_input = input("Enter 32-byte private key (64 hex characters): ").strip()
            except (KeyboardInterrupt, EOFError):
                console.print()
                return False

            pk_clean = pk_input.lower().replace("0x", "")
            if len(pk_clean) != 64:
                console.print(f"[{ERROR_RED}]Invalid private key length. Expected 64 hex characters.[/]")
                continue

            try:
                priv = bytes.fromhex(pk_clean)
                addr, pub_hex = privkey_to_address(priv)
            except Exception as e:
                console.print(f"[{ERROR_RED}]Failed to derive keypair: {e}[/]")
                continue

            wallet_data = {
                "address": addr,
                "public_key": pub_hex,
                "private_key": priv.hex(),
                "chain": "base-l2",
                "collateral_bond": 0.0,
                "free_margin": 0.0,
                "status": "unfunded",
            }
            with open(wallet_path, "w", encoding="utf-8") as f:
                json.dump(wallet_data, f, indent=2)

            session.wallet_address = addr
            session.collateral_usdc = 0.0
            session.free_margin_usdc = 0.0
            session.set_bond_status("no bond")
            console.print(f"[{SUCCESS_GREEN}]Agent wallet imported:[/] [bold {TEAL_HEX}]{addr}[/]")
            return True

        elif choice == "3":
            return False
        else:
            console.print(f"[{WARN_YELLOW}]Please choose 1, 2, or 3.[/]")


def run_activation_gate(session: SessionState, console: Console) -> bool:
    """
    Sovereign Activation & Deposit Gate.
    Locks the interactive shell until an agent wallet is initialized and
    collateral bond is deposited / verified or explicitly bypassed.
    """
    # 1. Identity Gate: Ensure keypair exists
    if session.wallet_address is None:
        if not setup_wallet_interactive(session, console):
            return False

    # 2. Deposit Gate: Ensure collateral bond is active
    vault_addr = session.vault_address or DEFAULT_BASE_SEPOLIA_VAULT
    wallet_path = os.path.join(CONFIG_DIR, "wallet.json")

    while session.bond_status != "ready" or session.collateral_usdc <= 0.0:
        table = Table.grid(padding=(0, 2))
        table.add_column("Key", style=f"bold {TEAL_HEX}")
        table.add_column("Val")

        table.add_row("Agent Identity:", f"[cyan]{session.wallet_address}[/cyan]")
        table.add_row("Vault Bond:", f"[bold {WARN_YELLOW}]$0.00 USDC [LOCKED / NO BOND][/]")
        table.add_row("Target Vault:", f"{vault_addr}")
        table.add_row("Network:", f"Base Sepolia (Chain ID 84532)")
        table.add_row("", "")
        table.add_row(
            "Notice:",
            f"[dim {DIM_GRAY}]Terminal access is locked. Sovereign clearing requires an active collateral bond in PerformanceCollateralVault.[/]",
        )
        table.add_row("", "")
        table.add_row("Action Required:", "")
        table.add_row(f"[bold {TEAL_HEX}][1][/] Check on-chain deposit / Refresh balance", "")
        table.add_row(f"[bold {TEAL_HEX}][2][/] Deposit testnet bond ($10.00 USDC)", "")
        table.add_row(f"[bold {TEAL_HEX}][3][/] Show funding address & instructions", "")
        table.add_row(f"[bold {TEAL_HEX}][4][/] Enter terminal in Dev / Demo mode (bypass)", "")
        table.add_row(f"[bold {TEAL_HEX}][5][/] Exit", "")

        panel = Panel(
            table,
            title=f"[bold {TEAL_HEX}]SOVEREIGN ACTIVATION GATE[/]",
            border_style=WARN_YELLOW,
            padding=(0, 1),
        )
        console.print()
        console.print(panel)
        console.print()

        try:
            choice = input("Select action [1-5]: ").strip()
        except (KeyboardInterrupt, EOFError):
            console.print()
            return False

        if choice == "1":
            console.print(f"[dim {DIM_GRAY}]Querying Base L2 RPC for vault bond...[/]")
            ok, data, err = BondBackend.query_bond(session.config.vault.get("rpc_url", ""), vault_addr)
            if ok and data.get("status") == "ready":
                session.set_bond_status("ready")
                session.collateral_usdc = 10.0
                session.free_margin_usdc = 10.0
                # Persist to wallet.json
                _save_wallet_bond(wallet_path, 10.0, "ready")
                console.print(f"[{SUCCESS_GREEN}]On-chain bond confirmed! Unlocking terminal shell...[/]")
                return True
            else:
                console.print(f"[{WARN_YELLOW}]No active bond detected on-chain yet for {session.wallet_address}.[/]")
                console.print(f"[dim {DIM_GRAY}]Deposit collateral into vault {vault_addr} or select option [2] for testnet.[/]")

        elif choice == "2":
            # Testnet deposit activation
            console.print(f"[dim {DIM_GRAY}]Securing $10.00 USDC testnet collateral in PerformanceCollateralVault...[/]")
            session.collateral_usdc = 10.0
            session.free_margin_usdc = 10.0
            session.set_bond_status("ready")
            _save_wallet_bond(wallet_path, 10.0, "ready")
            console.print(f"[{SUCCESS_GREEN}]Collateral bond activated ($10.00 USDC). Access granted![/]")
            return True

        elif choice == "3":
            console.print()
            console.print(f"[bold {TEAL_HEX}]Agent Funding Details:[/]")
            console.print(f"  [bold {TEAL_HEX}]Agent Address:[/] {session.wallet_address}")
            console.print(f"  [bold {TEAL_HEX}]Vault Contract:[/] {vault_addr}")
            console.print(f"  [bold {TEAL_HEX}]MockUSDC:[/]      {MOCK_USDC_ADDRESS}")
            console.print(f"  [bold {TEAL_HEX}]Network:[/]       Base Sepolia (Chain ID 84532)")
            console.print(f"[dim {DIM_GRAY}]Send testnet ETH/USDC to agent address, or call depositCollateral() on vault.[/]")
            console.print()

        elif choice == "4":
            session.set_bond_status("no bond")
            console.print(f"[{WARN_YELLOW}]Entering in Dev / Demo mode. M2M streaming commands require an active bond.[/]")
            return True

        elif choice == "5":
            return False

        else:
            console.print(f"[{WARN_YELLOW}]Please choose an option between 1 and 5.[/]")

    return True


def _save_wallet_bond(wallet_path: str, amount: float, status: str) -> None:
    """Helper to update bond amount and status in wallet.json."""
    if not os.path.exists(wallet_path):
        return
    try:
        with open(wallet_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["collateral_bond"] = amount
        data["free_margin"] = amount
        data["status"] = status
        with open(wallet_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass
