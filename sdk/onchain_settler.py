# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Causal-Slash Protocol: Automated On-Chain Settlement Engine (Base Sepolia L2).

Production-grade Web3 interaction module for SwarmDelegationVault on Base Sepolia.
Constructs canonical ABI calldata, generates cryptographic EIP-712 / Schnorr proofs,
broadcasts transactions via Foundry cast CLI or public Base Sepolia JSON-RPC,
and enforces real-time on-chain transaction confirmation.

Zero-Mock, Zero-Sleep production architecture compliant with all 6 Protocol Axioms.
Denominated strictly in micro-USDC (6 decimal places: 1,000,000 = 1.0 USDC).
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import ecdsa

from sdk.causal_eth import (
    SECP256K1_N,
    _point_add,
    abi_encode_address,
    abi_encode_bytes32,
    abi_encode_uint256,
    commit_hash_for,
    compute_eip712_domain_separator,
    compute_subagent_leaf,
    compute_swarm_cheque_digest,
    compute_swarm_cheque_struct_hash,
    decompress_pubkey,
    derive_address,
    encode_commit_fraud_proof,
    encode_reveal_and_slash,
    encode_slash_swarm_subagent,
    encode_settle_swarm_cheque,
    keccak256,
    secp256k1_mul,
)

logger = logging.getLogger("causal_slash.onchain_settler")

# ---------------------------------------------------------------------------
# Protocol Constants (Base Sepolia L2)
# ---------------------------------------------------------------------------

DEFAULT_BASE_SEPOLIA_VAULT = "0x33BD2908a372cf6A533B75e79D3cAa754da8775c"
DEFAULT_BASE_SEPOLIA_RPC = "https://sepolia.base.org"
DEFAULT_BASE_SEPOLIA_CHAIN_ID = 84532


class OnChainSettlementError(Exception):
    """Base exception for on-chain settlement failures."""


class TransactionRevertedError(OnChainSettlementError):
    """Raised when an on-chain settlement transaction reverts."""


class TransactionTimeoutError(OnChainSettlementError):
    """Raised when transaction confirmation times out."""


@dataclass
class SwarmSlashParams:
    """Canonical parameters for SwarmDelegationVault.slashSwarmSubAgent."""

    master_agent: str
    leaf_hash: bytes
    merkle_proof: List[bytes]
    leaf_index: int
    extracted_sk: int
    subagent_quota: int
    nonce_root: bytes
    expiry: int


def _normalize_hex(val: Union[str, bytes, int], length: Optional[int] = None) -> bytes:
    """Normalizes int, hex-str, or bytes into raw bytes."""
    if isinstance(val, int):
        byte_len = length if length is not None else (val.bit_length() + 7) // 8 or 1
        return val.to_bytes(byte_len, "big")
    if isinstance(val, bytes):
        if length is not None and len(val) != length:
            if len(val) < length:
                return val.rjust(length, b"\x00")
            raise ValueError(f"Expected {length} bytes, got {len(val)}")
        return val
    if isinstance(val, str):
        cleaned = val.strip().lower()
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        if len(cleaned) % 2 != 0:
            cleaned = "0" + cleaned
        b = bytes.fromhex(cleaned)
        if length is not None and len(b) != length:
            if len(b) < length:
                return b.rjust(length, b"\x00")
            raise ValueError(f"Expected {length} bytes, got {len(b)}")
        return b
    raise TypeError(f"Cannot normalize type {type(val)} to bytes")


def _to_checksum_address(addr_bytes: bytes) -> str:
    """ERC-55 checksum encoding for an Ethereum address."""
    if len(addr_bytes) != 20:
        raise ValueError("Address must be 20 bytes")
    hex_addr = addr_bytes.hex()
    hash_addr = keccak256(hex_addr.encode("ascii")).hex()
    checksummed = "".join(
        hex_addr[i].upper() if int(hash_addr[i], 16) >= 8 else hex_addr[i]
        for i in range(40)
    )
    return "0x" + checksummed


def sign_digest_secp256k1(sk_int: int, digest32: bytes) -> bytes:
    """
    Signs a 32-byte hash using secp256k1 deterministic ECDSA (RFC 6979)
    and computes the exact recovery ID (v = 27 or 28, BIP-146 low-s).
    Returns 65-byte packed signature: r (32B) || s (32B) || v (1B).
    """
    if len(digest32) != 32:
        raise ValueError("digest must be 32 bytes")
    sk_bytes = sk_int.to_bytes(32, "big")
    signing_key = ecdsa.SigningKey.from_string(sk_bytes, curve=ecdsa.SECP256k1)
    sig = signing_key.sign_digest_deterministic(digest32, sigencode=ecdsa.util.sigencode_string)
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")

    # Enforce BIP-146 / EIP-2 low-s
    if s > SECP256K1_N // 2:
        s = SECP256K1_N - s

    expected_addr = derive_address(sk_int)

    for v in (27, 28):
        y_odd = (v - 27) & 1
        prefix = 0x03 if y_odd else 0x02
        try:
            pt = decompress_pubkey(bytes([prefix]) + r.to_bytes(32, "big"))
            sR = secp256k1_mul(s, pt)
            inv_r = pow(r, -1, SECP256K1_N)
            e = int.from_bytes(digest32, "big")
            neg_eG = secp256k1_mul(SECP256K1_N - (e % SECP256K1_N))
            cand_Q = _point_add(sR, neg_eG)
            if cand_Q is None:
                continue
            Q = secp256k1_mul(inv_r, cand_Q)
            addr = keccak256(Q[0].to_bytes(32, "big") + Q[1].to_bytes(32, "big"))[12:]
            if addr == expected_addr:
                return r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([v])
        except Exception:
            continue

    raise RuntimeError("Failed to compute valid ECDSA recovery ID v for secp256k1 signature")


class BaseOnChainSettler:
    """
    Autonomous on-chain clearing and slashing client for SwarmDelegationVault
    and PerformanceCollateralVault on Base Sepolia.

    Supports:
    - BaseOnChainSettler(rpc_url, private_key, vault_address)
    - BaseOnChainSettler(vault_address, rpc_url, private_key)
    - Keyword arguments: vault_address=..., rpc_url=..., private_key=...
    """

    def __init__(
        self,
        arg1: Optional[str] = None,
        arg2: Optional[Union[str, bytes, int]] = None,
        arg3: Optional[str] = None,
        *,
        rpc_url: Optional[str] = None,
        private_key: Optional[Union[str, bytes, int]] = None,
        vault_address: Optional[str] = None,
        master_agent: Optional[str] = None,
        chain_id: Optional[int] = None,
        use_cast: bool = True,
        timeout: float = 60.0,
        **kwargs: Any,
    ) -> None:
        # Determine parameter mapping from positional args
        resolved_rpc = rpc_url or kwargs.get("rpc_url")
        resolved_pk = private_key or kwargs.get("private_key")
        resolved_vault = vault_address or kwargs.get("vault_address")

        if arg1 is not None:
            # Check if arg1 is an RPC url
            if isinstance(arg1, str) and ("://" in arg1 or "localhost" in arg1):
                if resolved_rpc is None:
                    resolved_rpc = arg1
                if resolved_pk is None and arg2 is not None:
                    resolved_pk = arg2
                if resolved_vault is None and arg3 is not None and isinstance(arg3, str):
                    resolved_vault = arg3
            # Check if arg1 is a 20-byte address (starts with 0x and len 42)
            elif isinstance(arg1, str) and arg1.startswith("0x") and len(arg1) == 42:
                if resolved_vault is None:
                    resolved_vault = arg1
                if resolved_rpc is None and arg2 is not None and isinstance(arg2, str) and ("://" in arg2 or "localhost" in arg2):
                    resolved_rpc = arg2
                    if resolved_pk is None and arg3 is not None:
                        resolved_pk = arg3
                elif resolved_pk is None and arg2 is not None:
                    resolved_pk = arg2

        self.vault_address = resolved_vault or os.getenv("SWARM_VAULT_ADDRESS") or DEFAULT_BASE_SEPOLIA_VAULT
        self.vault_bytes = _normalize_hex(self.vault_address, 20)
        self.rpc_url = resolved_rpc or os.getenv("BASE_SEPOLIA_RPC") or os.getenv("RPC_URL") or DEFAULT_BASE_SEPOLIA_RPC
        self.chain_id = int(chain_id or os.getenv("BASE_CHAIN_ID") or DEFAULT_BASE_SEPOLIA_CHAIN_ID)
        self.timeout = float(timeout)

        # Parse private key if provided
        raw_pk = resolved_pk or os.getenv("SETTLER_PRIVATE_KEY") or os.getenv("PRIVATE_KEY")
        if raw_pk is not None:
            self.private_key_bytes = _normalize_hex(raw_pk, 32)
            self.private_key_int = int.from_bytes(self.private_key_bytes, "big")
            self.caller_address = _to_checksum_address(derive_address(self.private_key_int))
        else:
            self.private_key_bytes = None
            self.private_key_int = None
            self.caller_address = None

        # Master agent address backing the swarm
        raw_master = master_agent or os.getenv("MASTER_AGENT_ADDRESS")
        if raw_master is not None:
            self.master_agent = _to_checksum_address(_normalize_hex(raw_master, 20))
        elif self.caller_address is not None:
            self.master_agent = self.caller_address
        else:
            self.master_agent = _to_checksum_address(self.vault_bytes)

        # Detect Foundry cast binary
        self.cast_path = shutil.which("cast")
        self.use_cast = bool(use_cast and self.cast_path is not None)

    # -----------------------------------------------------------------------
    # EIP-712 & Calldata Helpers
    # -----------------------------------------------------------------------

    def compute_domain_separator(self) -> bytes:
        """Computes canonical EIP-712 domain separator for the configured vault."""
        return compute_eip712_domain_separator(
            verifying_contract=self.vault_bytes,
            chain_id=self.chain_id,
            name="CausalSlashVault",
            version="2.0",
        )

    def sign_swarm_cheque(
        self,
        subagent_pk: Union[int, bytes, str],
        height: int,
        amount: int,
        master_agent: Optional[str] = None,
        vendor_address: Optional[str] = None,
    ) -> bytes:
        """
        Signs an EIP-712 SwarmCheque for (agent, vendor, height, amount)
        using the subagent's private key. Returns 65-byte (r, s, v) signature.
        """
        if isinstance(subagent_pk, int):
            sk_int = subagent_pk
        else:
            sk_int = int.from_bytes(_normalize_hex(subagent_pk, 32), "big")

        master_b = _normalize_hex(master_agent or self.master_agent, 20)
        vendor_b = _normalize_hex(vendor_address or self.caller_address or self.vault_address, 20)

        digest = compute_swarm_cheque_digest(
            master_agent=master_b,
            vendor_address=vendor_b,
            channel_height=int(height),
            cumulative_amount=int(amount),
            verifying_contract=self.vault_bytes,
            chain_id=self.chain_id,
        )
        return sign_digest_secp256k1(sk_int, digest)

    def encode_settle_calldata(
        self,
        subagent_pk: Union[int, bytes, str],
        height: int,
        amount: int,
        merkle_proof: Sequence[Union[bytes, str]],
        master_agent: Optional[str] = None,
        vendor_address: Optional[str] = None,
        signature: Optional[Union[bytes, str]] = None,
    ) -> bytes:
        """Assembles calldata for SwarmDelegationVault.settleSwarmCheque."""
        master_b = _normalize_hex(master_agent or self.master_agent, 20)
        proof_b = [_normalize_hex(p, 32) for p in merkle_proof]

        if signature is None:
            sig_b = self.sign_swarm_cheque(
                subagent_pk=subagent_pk,
                height=height,
                amount=amount,
                master_agent=master_agent,
                vendor_address=vendor_address,
            )
        else:
            sig_b = _normalize_hex(signature, 65)

        return encode_settle_swarm_cheque(
            agent=master_b,
            channel_height=int(height),
            cumulative_amount=int(amount),
            merkle_proof=proof_b,
            signature=sig_b,
        )

    def encode_slash_calldata(
        self,
        extracted_sk: Union[int, bytes, str],
        merkle_proof: Sequence[Union[bytes, str]],
        subagent_quota: int,
        nonce_root: Union[bytes, str],
        expiry: int,
        leaf_index: int = 0,
        master_agent: Optional[str] = None,
        leaf_hash: Optional[Union[bytes, str]] = None,
    ) -> bytes:
        """Assembles calldata for SwarmDelegationVault.slashSwarmSubAgent."""
        if isinstance(extracted_sk, int):
            sk_int = extracted_sk
        else:
            sk_int = int.from_bytes(_normalize_hex(extracted_sk, 32), "big")

        master_b = _normalize_hex(master_agent or self.master_agent, 20)
        proof_b = [_normalize_hex(p, 32) for p in merkle_proof]
        nonce_root_b = _normalize_hex(nonce_root, 32)

        if leaf_hash is None:
            subagent_addr = derive_address(sk_int)
            leaf_b = compute_subagent_leaf(
                subagent_address=subagent_addr,
                quota_usdc=int(subagent_quota),
                nonce_root=nonce_root_b,
                expiry=int(expiry),
                leaf_index=int(leaf_index),
            )
        else:
            leaf_b = _normalize_hex(leaf_hash, 32)

        return encode_slash_swarm_subagent(
            master_agent=master_b,
            leaf_hash=leaf_b,
            merkle_proof=proof_b,
            leaf_index=int(leaf_index),
            extracted_sk=sk_int,
            subagent_quota=int(subagent_quota),
            nonce_root=nonce_root_b,
            expiry=int(expiry),
        )

    # -----------------------------------------------------------------------
    # Core Protocol Methods: settle_swarm_cheque, slash_subagent, commit/reveal
    # -----------------------------------------------------------------------

    def settle_swarm_cheque(
        self,
        subagent_pk: Union[int, bytes, str],
        height: int,
        amount: int,
        merkle_proof: Sequence[Union[bytes, str]],
        master_agent: Optional[str] = None,
        vendor_address: Optional[str] = None,
        signature: Optional[Union[bytes, str]] = None,
    ) -> str:
        """
        Settles an off-chain streaming micro-cheque on Base Sepolia.

        1. Computes ABI calldata for settleSwarmCheque via sdk/causal_eth.py.
        2. Generates EIP-712 subagent signature if not explicitly provided.
        3. Sends transaction to Base Sepolia via CLI `cast` or JSON-RPC.
        4. Waits for on-chain block inclusion and returns transaction hash.
        """
        calldata = self.encode_settle_calldata(
            subagent_pk=subagent_pk,
            height=height,
            amount=amount,
            merkle_proof=merkle_proof,
            master_agent=master_agent,
            vendor_address=vendor_address,
            signature=signature,
        )
        return self.send_transaction(calldata=calldata, to_address=self.vault_address)

    def slash_subagent(
        self,
        extracted_sk: Optional[Union[int, bytes, str]] = None,
        merkle_proof: Optional[Sequence[Union[bytes, str]]] = None,
        subagent_quota: Optional[int] = None,
        nonce_root: Optional[Union[bytes, str]] = None,
        expiry: Optional[int] = None,
        leaf_index: int = 0,
        master_agent: Optional[str] = None,
        leaf_hash: Optional[Union[bytes, str]] = None,
        args: Optional[SwarmSlashParams] = None,
    ) -> str:
        """
        Liquidates a fraudulent subagent on-chain after equivocation extraction.

        1. Computes canonical leaf and Merkle proof calldata for slashSwarmSubAgent.
        2. Sends liquidation transaction to Base Sepolia via CLI `cast` or JSON-RPC.
        3. Waits for block confirmation and returns transaction hash.
        """
        if args is not None:
            calldata = self.encode_slash_calldata(
                extracted_sk=args.extracted_sk,
                merkle_proof=args.merkle_proof,
                subagent_quota=args.subagent_quota,
                nonce_root=args.nonce_root,
                expiry=args.expiry,
                leaf_index=args.leaf_index,
                master_agent=args.master_agent,
                leaf_hash=args.leaf_hash,
            )
        else:
            if extracted_sk is None or merkle_proof is None or subagent_quota is None or nonce_root is None or expiry is None:
                raise ValueError("Missing required arguments for slash_subagent")
            calldata = self.encode_slash_calldata(
                extracted_sk=extracted_sk,
                merkle_proof=merkle_proof,
                subagent_quota=subagent_quota,
                nonce_root=nonce_root,
                expiry=expiry,
                leaf_index=leaf_index,
                master_agent=master_agent,
                leaf_hash=leaf_hash,
            )

        return self.send_transaction(calldata=calldata, to_address=self.vault_address)

    def commit_fraud_proof(
        self,
        target_agent: str,
        commit_hash: Union[bytes, str],
    ) -> str:
        """
        Commits a fraud proof hash on-chain with 1 USDC bond (Axiom 4).
        Protects whistleblower searcher from MEV front-running bots.
        """
        target_b = _normalize_hex(target_agent, 20)
        hash_b = _normalize_hex(commit_hash, 32)
        calldata = encode_commit_fraud_proof(target_b, hash_b)
        return self.send_transaction(calldata=calldata, to_address=self.vault_address)

    def reveal_and_slash(
        self,
        malicious_agent: str,
        extracted_sk: Union[int, bytes, str],
        salt: Union[bytes, str],
    ) -> str:
        """
        Reveals extracted private key and executes O(1) algebraic slash (Axiom 4 & 6).
        Must be called within T_reveal window after commit_fraud_proof.
        """
        agent_b = _normalize_hex(malicious_agent, 20)
        if isinstance(extracted_sk, int):
            sk_int = extracted_sk
        else:
            sk_int = int.from_bytes(_normalize_hex(extracted_sk, 32), "big")
        salt_b = _normalize_hex(salt, 32)
        calldata = encode_reveal_and_slash(agent_b, sk_int, salt_b)
        return self.send_transaction(calldata=calldata, to_address=self.vault_address)

    def create_commit_hash(
        self,
        extracted_sk: Union[int, bytes, str],
        finder_address: Optional[str] = None,
        salt: Optional[Union[bytes, str]] = None,
    ) -> Tuple[bytes, bytes]:
        """
        Prepares (commit_hash, salt) for 2-phase fraud proof submission.
        salt is 32 random bytes if not provided.
        """
        if isinstance(extracted_sk, int):
            sk_bytes = extracted_sk.to_bytes(32, "big")
        else:
            sk_bytes = _normalize_hex(extracted_sk, 32)
        finder_b = _normalize_hex(finder_address or self.caller_address, 20)
        salt_b = _normalize_hex(salt, 32) if salt is not None else os.urandom(32)
        commit_hash = commit_hash_for(sk_bytes, finder_b, salt_b)
        return commit_hash, salt_b

    # -----------------------------------------------------------------------
    # Transport & Execution Layer (cast CLI / JSON-RPC)
    # -----------------------------------------------------------------------

    def send_transaction(
        self,
        calldata: Union[bytes, str],
        to_address: Optional[str] = None,
        value: int = 0,
    ) -> str:
        """
        Broadcasts an on-chain transaction to Base Sepolia and awaits confirmation.
        Returns mined tx_hash.
        """
        to_target = to_address or self.vault_address
        calldata_hex = "0x" + (_normalize_hex(calldata).hex())

        if self.use_cast and self.private_key_bytes is not None:
            return self._send_via_cast(to_target, calldata_hex, value)

        return self._send_via_rpc(to_target, calldata_hex, value)

    def _send_via_cast(self, to_target: str, calldata_hex: str, value: int = 0) -> str:
        """Executes transaction using Foundry `cast send` CLI."""
        assert self.cast_path is not None
        assert self.private_key_bytes is not None

        pk_hex = "0x" + self.private_key_bytes.hex()
        cmd = [
            self.cast_path,
            "send",
            to_target,
            calldata_hex,
            "--rpc-url",
            self.rpc_url,
            "--private-key",
            pk_hex,
            "--json",
        ]
        if value > 0:
            cmd.extend(["--value", str(value)])

        logger.debug("Executing cast send to %s", to_target)
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)

        if proc.returncode != 0:
            err_msg = proc.stderr.strip() or proc.stdout.strip()
            raise TransactionRevertedError(f"cast send reverted with code {proc.returncode}: {err_msg}")

        try:
            receipt = json.loads(proc.stdout)
            tx_hash = receipt.get("transactionHash") or receipt.get("hash")
            if not tx_hash:
                raise ValueError("No transactionHash in cast send receipt output")
            return str(tx_hash)
        except json.JSONDecodeError as ex:
            for line in proc.stdout.splitlines():
                if "transactionHash" in line or line.startswith("0x"):
                    tokens = line.strip().split()
                    for token in tokens:
                        if token.startswith("0x") and len(token) == 66:
                            return token
            raise TransactionRevertedError(f"Failed to parse cast output: {proc.stdout}") from ex

    def _send_via_rpc(self, to_target: str, calldata_hex: str, value: int = 0) -> str:
        """Sends transaction via standard Ethereum JSON-RPC."""
        from_addr = self.caller_address or self.master_agent
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_sendTransaction",
            "params": [
                {
                    "from": from_addr,
                    "to": to_target,
                    "data": calldata_hex,
                    "value": hex(value),
                }
            ],
        }

        res = self._json_rpc_call(payload)
        if "error" in res:
            err = res["error"]
            raise TransactionRevertedError(f"JSON-RPC error {err.get('code')}: {err.get('message')}")

        tx_hash = res.get("result")
        if not tx_hash:
            raise OnChainSettlementError("No transaction hash returned from eth_sendTransaction")

        self.wait_for_receipt(tx_hash)
        return str(tx_hash)

    def wait_for_receipt(self, tx_hash: str, timeout: Optional[float] = None) -> Dict[str, Any]:
        """
        Awaits transaction receipt until mined or timeout expires.
        Zero sleep: uses native blocking cast receipt or non-sleeping deadline loop.
        """
        max_time = timeout or self.timeout

        # Preferred path: Foundry cast receipt blocks natively until confirmation
        if self.use_cast and self.cast_path is not None:
            cmd = [
                self.cast_path,
                "receipt",
                tx_hash,
                "--confirmations",
                "1",
                "--rpc-url",
                self.rpc_url,
                "--json",
            ]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max_time)
                if proc.returncode == 0 and proc.stdout.strip():
                    receipt = json.loads(proc.stdout)
                    status = receipt.get("status")
                    if status in (1, "0x1", "1", True):
                        return receipt
                    if status in (0, "0x0", "0", False):
                        raise TransactionRevertedError(f"Transaction {tx_hash} reverted on-chain")
                else:
                    err_msg = proc.stderr.strip() or proc.stdout.strip()
                    raise TransactionRevertedError(f"cast receipt returned {proc.returncode}: {err_msg}")
            except subprocess.TimeoutExpired as ex:
                raise TransactionTimeoutError(f"Timed out waiting for receipt of {tx_hash} after {max_time}s") from ex
            except json.JSONDecodeError as ex:
                raise TransactionRevertedError(f"Failed to parse cast receipt output: {proc.stdout}") from ex

        # Non-blocking JSON-RPC deadline loop (zero time.sleep)
        deadline = time.perf_counter() + max_time
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getTransactionReceipt",
            "params": [tx_hash],
        }

        while time.perf_counter() < deadline:
            res = self._json_rpc_call(payload)
            receipt = res.get("result")
            if receipt is not None:
                status = receipt.get("status")
                if status in (1, "0x1", "1", True):
                    return receipt
                if status in (0, "0x0", "0", False):
                    raise TransactionRevertedError(f"Transaction {tx_hash} reverted on-chain")

        raise TransactionTimeoutError(f"Timed out waiting for receipt of {tx_hash} after {max_time}s")

    def _json_rpc_call(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Performs raw HTTP JSON-RPC POST request."""
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.rpc_url,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "CausalSlash-SDK/0.3.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as ex:
            raise OnChainSettlementError(f"RPC connection failed to {self.rpc_url}: {ex}") from ex

    # -----------------------------------------------------------------------
    # State Inspection Helpers
    # -----------------------------------------------------------------------

    def get_vault_info(self, agent_address: Optional[str] = None) -> Dict[str, Any]:
        """Queries master agent vault state from SwarmDelegationVault."""
        target = agent_address or self.master_agent
        sig = "vaults(address)(uint256,bytes32,address,address,uint256,uint256,bool)"

        if self.use_cast and self.cast_path is not None:
            cmd = [self.cast_path, "call", self.vault_address, sig, target, "--rpc-url", self.rpc_url]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            if proc.returncode == 0:
                lines = [line.strip() for line in proc.stdout.strip().splitlines() if line.strip()]
                if len(lines) >= 7:
                    return {
                        "collateral_bond": int(lines[0]),
                        "nonce_merkle_root": lines[1],
                        "signing_address": lines[2],
                        "active_vendor": lines[3],
                        "allocated_exposure": int(lines[4]),
                        "pending_withdrawal": int(lines[5]),
                        "is_slashed": lines[6].lower() == "true",
                    }

        return {}
