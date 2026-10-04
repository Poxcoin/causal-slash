# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
/wallet command implementation.
Creates and manages sovereign agent secp256k1 cryptographic wallets.
"""

from __future__ import annotations
import hashlib
import json
import os
import secrets
from typing import List
import ecdsa

from csls.commands.base import Command, CommandContext
from csls.core.config import CONFIG_DIR
from csls.ui.theme import TEAL_HEX, DIM_GRAY, SUCCESS_GREEN, WARN_YELLOW


def privkey_to_address(priv_bytes: bytes) -> tuple[str, str]:
    """Derive canonical Ethereum address and uncompressed hex public key."""
    from sdk.causal_eth import derive_address, secp256k1_mul
    sk_int = int.from_bytes(priv_bytes, "big")
    addr = "0x" + derive_address(sk_int).hex()
    x, y = secp256k1_mul(sk_int)
    pub_hex = "04" + x.to_bytes(32, "big").hex() + y.to_bytes(32, "big").hex()
    return addr, pub_hex


class WalletCommand(Command):
    name = "/wallet"
    description = "create agent wallet (secp256k1 public key)"
    args_spec = "[new | info]"

    async def run(self, ctx: CommandContext, args: List[str]) -> int:
        console = ctx.console
        wallet_path = os.path.join(CONFIG_DIR, "wallet.json")
        subcmd = args[0].lower() if args else "info"

        if subcmd == "new":
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
            os.makedirs(CONFIG_DIR, exist_ok=True)
            with open(wallet_path, "w", encoding="utf-8") as f:
                json.dump(wallet_data, f, indent=2)

            ctx.session.wallet_address = addr
            ctx.session.collateral_usdc = 0.0
            ctx.session.free_margin_usdc = 0.0
            ctx.session.set_bond_status("no bond")
            console.print(f"[{SUCCESS_GREEN}]New sovereign agent wallet generated:[/]")
            console.print(f"  [bold {TEAL_HEX}]Address:[/]    {addr}")
            console.print(f"  [bold {TEAL_HEX}]Public Key:[/] {pub_hex[:32]}...{pub_hex[-16:]}")
            console.print(f"  [dim {DIM_GRAY}]Keystore saved to {wallet_path}[/]")
            return 0

        elif subcmd == "info":
            if not os.path.exists(wallet_path):
                console.print(f"[{WARN_YELLOW}]No wallet found at {wallet_path}.[/]")
                console.print(f"[dim {DIM_GRAY}]Run [bold]/wallet new[/] to create a new secp256k1 keypair.[/]")
                return 1

            with open(wallet_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            addr = data.get("address", "unknown")
            pub_hex = data.get("public_key", "")
            ctx.session.wallet_address = addr

            console.print(f"[bold {TEAL_HEX}]Agent Wallet Status:[/]")
            console.print(f"  [bold {TEAL_HEX}]Address:[/]    {addr}")
            if pub_hex:
                console.print(f"  [bold {TEAL_HEX}]Public Key:[/] {pub_hex[:32]}...{pub_hex[-16:]}")
            console.print(f"  [dim {DIM_GRAY}]Keystore: {wallet_path}[/]")
            return 0

        else:
            console.print(f"[red]Unknown wallet subcommand: {subcmd}. Use [bold]/wallet new[/] or [bold]/wallet info[/].[/]")
            return 1
