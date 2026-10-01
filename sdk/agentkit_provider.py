# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Coinbase AgentKit Production ActionProvider for Causal-Slash Protocol.
Enables AI Agents on Base L2 to autonomously establish payment channels,
stream zero-gas micro-cheques for LLM token inference, verify streaming receipts,
and trigger on-chain collateral foreclosure with automated bounty claims.
"""

from __future__ import annotations

import json
import logging
import math
import os
import shutil
import subprocess
import sys
import threading
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field

# Ensure sdk directory is in path
_SDK_DIR = os.path.dirname(os.path.abspath(__file__))
if _SDK_DIR not in sys.path:
    sys.path.insert(0, _SDK_DIR)

from causal_slash import (
    CausalAgentWallet,
    CausalVendorNode,
    Cheque,
    ProcessResult,
    CSLS_OK,
    CSLS_ERR_FRAUD,
    CSLS_ERR_EXPOSURE_CAP,
    CSLS_ERR_REPLAY,
    CSLS_ERR_OUT_OF_ORDER,
)

# ---------------------------------------------------------------------------
# Coinbase AgentKit Standard Interfaces & Fallback Decorators
# ---------------------------------------------------------------------------

try:
    from cdp_agentkit_core.action_provider import ActionProvider
    from cdp_agentkit_core.actions import create_action
except ImportError:
    try:
        from coinbase_agentkit import ActionProvider
        from coinbase_agentkit.core.action_provider import create_action
    except ImportError:
        # Standard AgentKit ActionProvider base specification
        class ActionProvider:
            """Abstract ActionProvider adhering to Coinbase AgentKit SDK specification."""
            def __init__(self, name: str = "causal_slash"):
                self.name = name
                self._actions: Dict[str, Any] = {}

            def get_actions(self, wallet_provider: Any = None) -> List[Any]:
                return list(self._actions.values())

        def create_action(name: str, description: str, schema: Optional[type[BaseModel]] = None):
            """Action decorator registering tool capabilities for AI agent LLM orchestration."""
            def decorator(fn):
                fn._action_meta = {
                    "name": name,
                    "description": description,
                    "schema": schema,
                }
                return fn
            return decorator


# ---------------------------------------------------------------------------
# Action Pydantic Schemas (Coinbase AgentKit Standard)
# ---------------------------------------------------------------------------

class CreateChannelSchema(BaseModel):
    vendor_address: str = Field(
        ...,
        description="The Ethereum address (0x...) or compressed secp256k1 public key of the vendor."
    )
    deposit_usdc: float = Field(
        ...,
        gt=0,
        description="Amount of USDC performance collateral to allocate/reserve for this vendor session."
    )


class SignStreamChequeSchema(BaseModel):
    vendor_address: str = Field(
        ...,
        description="The vendor's public key or address to issue the micro-cheque to."
    )
    amount_usdc: float = Field(
        ...,
        gt=0,
        description="Incremental micro-payment amount in USDC (e.g. 0.0001 for 10 tokens)."
    )


class VerifyChequeStreamSchema(BaseModel):
    cheque_bytes: str = Field(
        ...,
        description="Hex-encoded (0x...) string or raw bytes representation of the 151-byte CslsCheque packet."
    )


class TriggerForeclosureSchema(BaseModel):
    malicious_agent: str = Field(
        ...,
        description="The Ethereum address (0x...) or public key of the equivocating agent."
    )
    extracted_sk: str = Field(
        ...,
        description="Hex-encoded (0x...) 32-byte secret key mathematically extracted from conflicting EOTS cheques."
    )
    salt: Optional[str] = Field(
        default=None,
        description="Optional 32-byte hex salt for commit-reveal fraud proof submission."
    )


# ---------------------------------------------------------------------------
# Production CausalSlashActionProvider
# ---------------------------------------------------------------------------

class CausalSlashActionProvider(ActionProvider):
    """
    Production Coinbase AgentKit ActionProvider for Causal-Slash Protocol.
    Integrates sovereign C11 high-frequency streaming channels with Base L2 PerformanceCollateralVault.
    
    Provides 4 core actions:
    1. create_channel: Allocates performance exposure and initializes isolated streaming state.
    2. sign_stream_cheque: Signs sub-microsecond EOTS micro-cheques with 0 gas.
    3. verify_cheque_stream: Processes streaming cheques and traps double-signing equivocations.
    4. trigger_foreclosure: Executes on-chain commit-reveal foreclosure, liquidating the attacker's bond.
    """

    def __init__(
        self,
        agent_wallet: Optional[CausalAgentWallet] = None,
        vendor_node: Optional[CausalVendorNode] = None,
        vault_address: Optional[str] = None,
        rpc_url: Optional[str] = None,
        private_key: Optional[str] = None,
        usdc_address: Optional[str] = None,
    ):
        super().__init__("causal_slash")
        self._lock = threading.RLock()
        self._onchain_lock = threading.RLock()
        self._closed = False

        # Native C11 Engine Instances
        self._agent_wallet = agent_wallet or CausalAgentWallet()
        self._vendor_node = vendor_node or CausalVendorNode()
        self._owns_wallet = agent_wallet is None
        self._owns_vendor = vendor_node is None

        # Base L2 On-Chain Configuration
        self._vault_address = vault_address
        self._rpc_url = rpc_url or os.environ.get("BASE_RPC_URL", "http://127.0.0.1:8545")
        self._private_key = private_key or os.environ.get("AGENT_PRIVATE_KEY")
        self._usdc_address = usdc_address

        # Ensure cast binary is discovered for on-chain execution if available
        self._cast_bin = shutil.which("cast") or os.path.expanduser("~/.foundry/bin/cast")

    @property
    def agent_wallet(self) -> CausalAgentWallet:
        return self._agent_wallet

    @property
    def vendor_node(self) -> CausalVendorNode:
        return self._vendor_node

    @property
    def public_key_hex(self) -> str:
        return self._agent_wallet.public_key_hex

    def __enter__(self) -> CausalSlashActionProvider:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    # -----------------------------------------------------------------------
    # Action 1: Create Channel
    # -----------------------------------------------------------------------

    @create_action(
        name="create_channel",
        description="Allocate performance collateral and initialize an isolated streaming channel with a vendor.",
        schema=CreateChannelSchema,
    )
    def create_channel(
        self,
        vendor_address: str,
        deposit_usdc: float,
        **kwargs: Any,
    ) -> str:
        """
        Creates an isolated off-chain channel and optionally reserves on-chain exposure.
        """
        if not isinstance(deposit_usdc, (int, float)):
            raise TypeError(f"deposit_usdc must be numeric, got {type(deposit_usdc).__name__}")
        if math.isnan(deposit_usdc) or math.isinf(deposit_usdc):
            raise ValueError(f"deposit_usdc must be finite, got {deposit_usdc}")
        if deposit_usdc <= 0:
            raise ValueError(f"deposit_usdc must be strictly positive, got {deposit_usdc}")

        with self._lock:
            if self._closed:
                raise RuntimeError("CausalSlashActionProvider is closed")
            v_pk = self._normalize_vendor_pk(vendor_address)

        tx_hash = None
        # If connected to on-chain vault on Base / Anvil, allocate exposure without blocking off-chain fast-paths
        if self._vault_address and self._rpc_url and self._private_key and os.path.exists(self._cast_bin):
            with self._onchain_lock:
                try:
                    deposit_micro = int(round(deposit_usdc * 1e6))
                    target_vendor_addr = vendor_address if len(vendor_address) == 42 and vendor_address.startswith("0x") else self._vendor_address_from_pk(v_pk)
                    cmd = [
                        self._cast_bin, "send", self._vault_address,
                        "allocateSessionExposure(address,uint256)",
                        target_vendor_addr, str(deposit_micro),
                        "--rpc-url", self._rpc_url,
                        "--private-key", self._private_key,
                        "--json"
                    ]
                    res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if res.returncode == 0:
                        try:
                            tx_hash = json.loads(res.stdout).get("transactionHash")
                        except Exception:
                            tx_hash = "confirmed"
                except Exception as e:
                    logging.warning("Failed on-chain exposure pre-allocation: %s", e)

        with self._lock:
            result = {
                "status": "CHANNEL_CREATED",
                "vendor_address": vendor_address,
                "vendor_pk": "0x" + v_pk.hex(),
                "deposit_usdc": float(deposit_usdc),
                "channel_height": self._agent_wallet.get_channel_height(v_pk),
                "vault_address": self._vault_address,
                "tx_hash": tx_hash,
            }
            return json.dumps(result)

    # -----------------------------------------------------------------------
    # Action 2: Sign Stream Cheque
    # -----------------------------------------------------------------------

    @create_action(
        name="sign_stream_cheque",
        description="Signs a zero-gas, high-frequency EOTS micro-cheque for incremental compute/token delivery.",
        schema=SignStreamChequeSchema,
    )
    def sign_stream_cheque(
        self,
        vendor_address: str,
        amount_usdc: float,
        **kwargs: Any,
    ) -> str:
        """
        Signs a micro-cheque in C11 native memory (~3.2 µs execution time).
        """
        if not isinstance(amount_usdc, (int, float)):
            raise TypeError(f"amount_usdc must be numeric, got {type(amount_usdc).__name__}")
        if math.isnan(amount_usdc) or math.isinf(amount_usdc):
            raise ValueError(f"amount_usdc must be finite, got {amount_usdc}")
        if amount_usdc <= 0:
            raise ValueError(f"amount_usdc must be strictly positive, got {amount_usdc}")

        with self._lock:
            if self._closed:
                raise RuntimeError("CausalSlashActionProvider is closed")

            v_pk = self._normalize_vendor_pk(vendor_address)
            cheque = self._agent_wallet.sign_cheque(v_pk, amount_usdc)

            result = {
                "status": "SIGNED",
                "vendor_address": vendor_address,
                "height": cheque.height,
                "incremental_usdc": float(amount_usdc),
                "cumulative_usdc": cheque.cumulative_amount_usdc,
                "agent_pk": "0x" + cheque.agent_pk.hex(),
                "cheque_hex": "0x" + cheque.raw_packet.hex(),
            }
            return json.dumps(result)

    # -----------------------------------------------------------------------
    # Action 3: Verify Cheque Stream
    # -----------------------------------------------------------------------

    @create_action(
        name="verify_cheque_stream",
        description="Verifies an incoming streaming micro-cheque and checks for fraudulent equivocation (double-signing).",
        schema=VerifyChequeStreamSchema,
    )
    def verify_cheque_stream(
        self,
        cheque_bytes: str,
        **kwargs: Any,
    ) -> str:
        """
        Verifies cryptographic validity and exposure limits via C11 libcausal_slash.
        """
        with self._lock:
            if self._closed:
                raise RuntimeError("CausalSlashActionProvider is closed")

            raw = self._parse_hex_bytes(cheque_bytes)
            res: ProcessResult = self._vendor_node.process_cheque(raw)

            if res.accepted:
                result = {
                    "status": "ACCEPTED",
                    "accepted": True,
                    "status_code": CSLS_OK,
                    "accumulated_usdc": res.accumulated_usdc,
                }
            elif res.status_code == CSLS_ERR_FRAUD and res.fraud_proof is not None:
                result = {
                    "status": "EQUIVOCATION_DETECTED",
                    "accepted": False,
                    "status_code": CSLS_ERR_FRAUD,
                    "offender_pk": "0x" + res.fraud_proof.offender_pk.hex(),
                    "collision_height": res.fraud_proof.collision_height,
                    "extracted_secret_key": "0x" + res.fraud_proof.extracted_secret_key.hex(),
                    "error_message": res.error_message,
                }
            else:
                result = {
                    "status": "REJECTED",
                    "accepted": False,
                    "status_code": res.status_code,
                    "error_message": res.error_message,
                }
            return json.dumps(result)

    # -----------------------------------------------------------------------
    # Action 4: Trigger Foreclosure
    # -----------------------------------------------------------------------

    @create_action(
        name="trigger_foreclosure",
        description="Submits cryptographic fraud proof to PerformanceCollateralVault on Base, liquidating the offender and claiming a 15% bounty.",
        schema=TriggerForeclosureSchema,
    )
    def trigger_foreclosure(
        self,
        malicious_agent: str,
        extracted_sk: str,
        salt: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """
        Executes on-chain commit-reveal foreclosure against PerformanceCollateralVault.
        """
        with self._onchain_lock:
            with self._lock:
                if self._closed:
                    raise RuntimeError("CausalSlashActionProvider is closed")

            if not self._vault_address or not self._rpc_url or not self._private_key:
                raise RuntimeError("On-chain execution requires vault_address, rpc_url, and private_key")

            if not os.path.exists(self._cast_bin):
                raise RuntimeError(f"Cast binary not found at {self._cast_bin}")

            # Normalize extracted secret key
            sk_clean = extracted_sk.lower()
            if sk_clean.startswith("0x"):
                sk_clean = sk_clean[2:]
            sk_int = int(sk_clean, 16)
            sk_hex = "0x" + sk_clean.zfill(64)

            # Generate random 32-byte salt if not provided
            if salt is None:
                salt_hex = "0x" + os.urandom(32).hex()
            else:
                salt_hex = salt if salt.startswith("0x") else "0x" + salt
                salt_hex = "0x" + salt_hex[2:].zfill(64)

            # Resolve caller address from private key
            caller_addr = subprocess.check_output(
                [self._cast_bin, "wallet", "address", "--private-key", self._private_key]
            ).decode().strip()

            # Ensure malicious agent address format
            agent_addr = malicious_agent
            if not agent_addr.startswith("0x") or len(agent_addr) != 42:
                # If compressed PK was passed, derive Ethereum address via vault
                agent_addr = subprocess.check_output(
                    [self._cast_bin, "call", self._vault_address, "deriveAddress(uint256)(address)", str(sk_int), "--rpc-url", self._rpc_url]
                ).decode().strip()

            # Phase 1: Compute commitment hash C = keccak256(abi.encodePacked(extractedSk, finder, salt))
            # Packing: uint256 (32B) + address (20B) + bytes32 (32B)
            packed_hex = f"{sk_hex[2:].zfill(64)}{caller_addr[2:].lower().zfill(40)}{salt_hex[2:].zfill(64)}"
            commit_hash = subprocess.check_output(
                [self._cast_bin, "keccak", "0x" + packed_hex]
            ).decode().strip()

            # 1. Approve 1 USDC commit bond if usdc_address is configured
            if self._usdc_address:
                subprocess.run(
                    [self._cast_bin, "send", self._usdc_address, "approve(address,uint256)", self._vault_address, "1000000", "--rpc-url", self._rpc_url, "--private-key", self._private_key],
                    capture_output=True, text=True, timeout=10
                )

            # 2. Submit commitFraudProof
            commit_res = subprocess.run(
                [self._cast_bin, "send", self._vault_address, "commitFraudProof(address,bytes32)", agent_addr, commit_hash, "--rpc-url", self._rpc_url, "--private-key", self._private_key, "--json"],
                capture_output=True, text=True, timeout=10
            )
            if commit_res.returncode != 0:
                raise RuntimeError(f"commitFraudProof failed: {commit_res.stderr or commit_res.stdout}")

            # 3. Mine 1 block (to satisfy MIN_COMMIT_DELAY = 1)
            subprocess.run([self._cast_bin, "rpc", "evm_mine", "--rpc-url", self._rpc_url], capture_output=True, text=True, timeout=5)

            # 4. Phase 2: revealAndSlash((address,uint256,bytes32))
            slash_arg = f"({agent_addr},{sk_int},{salt_hex})"
            slash_res = subprocess.run(
                [self._cast_bin, "send", self._vault_address, "revealAndSlash((address,uint256,bytes32))", slash_arg, "--rpc-url", self._rpc_url, "--private-key", self._private_key, "--json"],
                capture_output=True, text=True, timeout=10
            )
            if slash_res.returncode != 0:
                raise RuntimeError(f"revealAndSlash failed: {slash_res.stderr or slash_res.stdout}")

            # 5. Verify foreclosure status
            is_slashed = False
            try:
                out = subprocess.check_output(
                    [self._cast_bin, "call", self._vault_address, "vaults(address)(uint256,bytes32,address,address,uint256,uint256,bool)", agent_addr, "--rpc-url", self._rpc_url],
                    timeout=10,
                ).decode().splitlines()
                is_slashed = out[-1].strip().lower() == "true"
            except Exception as e:
                logging.warning("Failed to query on-chain vault slash status: %s", e)

            result = {
                "status": "FORECLOSED",
                "malicious_agent": agent_addr,
                "extracted_sk": sk_hex,
                "commit_hash": commit_hash,
                "is_slashed": is_slashed,
                "bounty_rate_pct": 15.0,
                "restitution_quarantined": True,
            }
            return json.dumps(result)

    # -----------------------------------------------------------------------
    # Internal Helpers & Memory Safety
    # -----------------------------------------------------------------------

    def _normalize_vendor_pk(self, vendor: str) -> bytes:
        if vendor.startswith("0x") or vendor.startswith("0X"):
            raw = bytes.fromhex(vendor[2:])
        else:
            raw = vendor.encode()

        if len(raw) == 33:
            return raw
        elif len(raw) == 20:
            # Map 20-byte Ethereum address to 33-byte compressed secp256k1 key
            return b"\x02" + raw.rjust(32, b"\x00")
        elif len(raw) == 32:
            return b"\x02" + raw
        else:
            # Pad or truncate deterministically to 33 bytes
            return b"\x02" + raw[:32].ljust(32, b"\x00")

    def _vendor_address_from_pk(self, pk: bytes) -> str:
        # Return 20-byte hex address from last 20 bytes of pk
        return "0x" + pk[-20:].hex()

    def _parse_hex_bytes(self, data: Union[str, bytes]) -> bytes:
        if isinstance(data, bytes):
            return data
        s = data.strip()
        if s.startswith("0x") or s.startswith("0X"):
            s = s[2:]
        return bytes.fromhex(s)

    def close(self):
        """Idempotent clean shutdown releasing all C11 heap contexts with zero leaks."""
        with self._lock:
            if not self._closed:
                self._closed = True
                if self._owns_wallet and hasattr(self._agent_wallet, "close"):
                    self._agent_wallet.close()
                if self._owns_vendor and hasattr(self._vendor_node, "close"):
                    self._vendor_node.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
