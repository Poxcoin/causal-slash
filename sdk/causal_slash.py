# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Causal-Slash Protocol: Python High-Performance Native SDK
Provides a zero-latency Python interface to the sovereign C11 cryptographic engine.
All internal settlement is denominated strictly in USD / USDC (6 decimal places: micro-USDC).
"""

from __future__ import annotations
import ctypes
import os
import sys
import subprocess
from dataclasses import dataclass
from typing import Optional, Tuple, Union

# Protocol Constants
CSLS_MAGIC = 0x43534C53
CSLS_PKT_CHEQUE = 0x01
CSLS_PKT_ACK = 0x02
CSLS_PKT_FRAUD = 0x03

CSLS_OK = 0
CSLS_ERR_EXPOSURE_CAP = -12
CSLS_ERR_FRAUD = -20
CSLS_ERR_REPLAY = -21
CSLS_ERR_OUT_OF_ORDER = -22
CSLS_ERR_FORGED_HASH = -23

# Locate / compile shared C library
_SDK_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_SDK_DIR)
_SO_PATHS = [
    os.path.join(_PROJECT_ROOT, "libcausal_slash.so"),
    os.path.join(_SDK_DIR, "libcausal_slash.so")
]

def _load_c_lib() -> ctypes.CDLL:
    for path in _SO_PATHS:
        if os.path.exists(path):
            return ctypes.CDLL(path)
    # Auto-compile in project root if missing
    cmd = ["make", "-C", _PROJECT_ROOT, "libcausal_slash.so"]
    subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return ctypes.CDLL(_SO_PATHS[0])

_LIB = _load_c_lib()

# Define C Structures
class _CslsChequePkt(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("magic", ctypes.c_uint32),
        ("type", ctypes.c_uint8),
        ("agent_pk", ctypes.c_uint8 * 33),
        ("vendor_pk", ctypes.c_uint8 * 33),
        ("height", ctypes.c_uint64),
        ("cumulative_amt", ctypes.c_uint64),
        ("challenge_e", ctypes.c_uint8 * 32),
        ("sig_s", ctypes.c_uint8 * 32),
    ]

class _CslsFraudPkt(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("magic", ctypes.c_uint32),
        ("type", ctypes.c_uint8),
        ("offender_pk", ctypes.c_uint8 * 33),
        ("collision_h", ctypes.c_uint64),
        ("extracted_sk", ctypes.c_uint8 * 32),
        ("cheque1", _CslsChequePkt),
        ("cheque2", _CslsChequePkt),
    ]

class _CslsAgentCtx(ctypes.Structure):
    _fields_ = [
        ("sk", ctypes.c_uint8 * 32),
        ("pk", ctypes.c_uint8 * 33),
        ("height", ctypes.c_uint64),
        ("cumulative_sent", ctypes.c_uint64),
        ("wal_path", ctypes.c_char * 256),
        ("wal_fd", ctypes.c_int),
    ]

class _CslsHistoryEntry(ctypes.Structure):
    _fields_ = [
        ("height", ctypes.c_uint64),
        ("amount", ctypes.c_uint64),
        ("challenge_e", ctypes.c_uint8 * 32),
        ("sig_s", ctypes.c_uint8 * 32),
        ("occupied", ctypes.c_bool),
    ]

class _CslsVendorCtx(ctypes.Structure):
    _fields_ = [
        ("sk", ctypes.c_uint8 * 32),
        ("pk", ctypes.c_uint8 * 33),
        ("last_height", ctypes.c_uint64),
        ("cleared_amount", ctypes.c_uint64),
        ("accumulated_amount", ctypes.c_uint64),
        ("max_exposure_delta_v", ctypes.c_uint64),
        ("history", _CslsHistoryEntry * 65536),
    ]

# Setup function signatures
_LIB.csls_crypto_global_init.restype = ctypes.c_int
_LIB.csls_crypto_global_init.argtypes = []

_LIB.csls_crypto_global_cleanup.restype = None
_LIB.csls_crypto_global_cleanup.argtypes = []

_LIB.csls_agent_init.restype = ctypes.c_int
_LIB.csls_agent_init.argtypes = [
    ctypes.POINTER(_CslsAgentCtx),
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_char_p,
]

_LIB.csls_agent_destroy.restype = None
_LIB.csls_agent_destroy.argtypes = [ctypes.POINTER(_CslsAgentCtx)]

_LIB.csls_agent_sign_cheque.restype = ctypes.c_int
_LIB.csls_agent_sign_cheque.argtypes = [
    ctypes.POINTER(_CslsAgentCtx),
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_uint64,
    ctypes.POINTER(_CslsChequePkt),
]

_LIB.csls_vendor_init.restype = ctypes.c_int
_LIB.csls_vendor_init.argtypes = [
    ctypes.POINTER(_CslsVendorCtx),
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_uint64,
]

_LIB.csls_vendor_destroy.restype = None
_LIB.csls_vendor_destroy.argtypes = [ctypes.POINTER(_CslsVendorCtx)]

_LIB.csls_vendor_process_cheque.restype = ctypes.c_int
_LIB.csls_vendor_process_cheque.argtypes = [
    ctypes.POINTER(_CslsVendorCtx),
    ctypes.POINTER(_CslsChequePkt),
    ctypes.POINTER(_CslsFraudPkt),
]

# Ensure global crypto is initialized once
if _LIB.csls_crypto_global_init() != 0:
    raise RuntimeError("Failed to initialize Causal-Slash OpenSSL secp256k1 crypto engine")


@dataclass(frozen=True)
class Cheque:
    """Immutable micro-payment cheque representation."""
    agent_pk: bytes
    vendor_pk: bytes
    height: int
    cumulative_amount_usdc: float
    raw_packet: bytes

    @classmethod
    def from_c_pkt(cls, pkt: _CslsChequePkt) -> Cheque:
        return cls(
            agent_pk=bytes(pkt.agent_pk),
            vendor_pk=bytes(pkt.vendor_pk),
            height=pkt.height,
            cumulative_amount_usdc=pkt.cumulative_amt / 1e6,
            raw_packet=bytes(pkt),
        )


@dataclass(frozen=True)
class ProcessResult:
    """Result of cheque processing by vendor."""
    status_code: int
    accepted: bool
    accumulated_usdc: float
    error_message: Optional[str] = None
    fraud_proof: Optional[FraudProof] = None


@dataclass(frozen=True)
class FraudProof:
    """Cryptographic proof of equivocation with extracted private key."""
    offender_pk: bytes
    collision_height: int
    extracted_secret_key: bytes
    raw_proof: bytes


def _parse_bytes(val: Union[str, bytes], expected_len: int) -> bytes:
    if isinstance(val, str):
        if val.startswith("0x") or val.startswith("0X"):
            val = val[2:]
        b = bytes.fromhex(val)
    else:
        b = bytes(val)
    if len(b) != expected_len:
        raise ValueError(f"Expected {expected_len} bytes, got {len(b)} bytes")
    return b


class CausalAgentWallet:
    """
    Sovereign AI Agent Wallet for ultra-fast, zero-gas micro-payments.
    Maintains an atomic monotonic height counter and generates deterministic EOTS cheques.
    """
    def __init__(self, secret_key: Optional[Union[str, bytes]] = None, wal_path: Optional[str] = None):
        self._ctx = _CslsAgentCtx()
        if secret_key is None:
            sk_bytes = os.urandom(32)
        else:
            sk_bytes = _parse_bytes(secret_key, 32)

        sk_arr = (ctypes.c_uint8 * 32)(*sk_bytes)
        wal_c = wal_path.encode() if wal_path else None
        res = _LIB.csls_agent_init(ctypes.byref(self._ctx), sk_arr, wal_c)
        if res != 0:
            raise RuntimeError(f"csls_agent_init failed with code {res}")

    @property
    def public_key(self) -> bytes:
        return bytes(self._ctx.pk)

    @property
    def public_key_hex(self) -> str:
        return "0x" + self.public_key.hex()

    @property
    def height(self) -> int:
        return self._ctx.height

    @property
    def total_sent_usdc(self) -> float:
        return self._ctx.cumulative_sent / 1e6

    def sign_cheque(self, vendor_pk: Union[str, bytes], amount_usdc: float) -> Cheque:
        """
        Signs a micro-payment cheque for `amount_usdc` (e.g. 0.001 for $0.001).
        Execution takes ~3-5 microseconds in native C.
        """
        v_bytes = _parse_bytes(vendor_pk, 33)
        v_arr = (ctypes.c_uint8 * 33)(*v_bytes)
        delta_micro = int(round(amount_usdc * 1e6))

        c_pkt = _CslsChequePkt()
        res = _LIB.csls_agent_sign_cheque(
            ctypes.byref(self._ctx), v_arr, delta_micro, ctypes.byref(c_pkt)
        )
        if res != 0:
            raise RuntimeError(f"csls_agent_sign_cheque failed with code {res}")

        return Cheque.from_c_pkt(c_pkt)

    def close(self):
        _LIB.csls_agent_destroy(ctypes.byref(self._ctx))

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


class CausalVendorNode:
    """
    Sovereign Vendor Node for microsecond cheque verification and equivocation trapping.
    Enforces the local unconfirmed exposure buffer (delta_v <= $1.00 USDC).
    """
    def __init__(self, secret_key: Optional[Union[str, bytes]] = None, delta_v_usdc: float = 1.0):
        self._ctx = _CslsVendorCtx()
        if secret_key is None:
            sk_bytes = os.urandom(32)
        else:
            sk_bytes = _parse_bytes(secret_key, 32)

        sk_arr = (ctypes.c_uint8 * 32)(*sk_bytes)
        delta_v_micro = int(round(delta_v_usdc * 1e6))

        res = _LIB.csls_vendor_init(ctypes.byref(self._ctx), sk_arr, delta_v_micro)
        if res != 0:
            raise RuntimeError(f"csls_vendor_init failed with code {res}")

    @property
    def public_key(self) -> bytes:
        return bytes(self._ctx.pk)

    @property
    def public_key_hex(self) -> str:
        return "0x" + self.public_key.hex()

    @property
    def accumulated_usdc(self) -> float:
        return self._ctx.accumulated_amount / 1e6

    def process_cheque(self, cheque: Union[Cheque, bytes]) -> ProcessResult:
        """
        Verifies an incoming cheque in < 15 microseconds.
        Detects equivocation and algebraically extracts private key if double-spend occurs.
        """
        if isinstance(cheque, Cheque):
            raw = cheque.raw_packet
        else:
            raw = cheque

        if len(raw) != ctypes.sizeof(_CslsChequePkt):
            return ProcessResult(
                status_code=-1,
                accepted=False,
                accumulated_usdc=self.accumulated_usdc,
                error_message=f"Invalid packet size: expected {ctypes.sizeof(_CslsChequePkt)}, got {len(raw)}",
            )

        c_pkt = _CslsChequePkt.from_buffer_copy(raw)
        c_fraud = _CslsFraudPkt()

        res = _LIB.csls_vendor_process_cheque(
            ctypes.byref(self._ctx), ctypes.byref(c_pkt), ctypes.byref(c_fraud)
        )

        if res == CSLS_OK:
            return ProcessResult(
                status_code=CSLS_OK,
                accepted=True,
                accumulated_usdc=self.accumulated_usdc,
            )

        if res == CSLS_ERR_FRAUD:
            proof = FraudProof(
                offender_pk=bytes(c_fraud.offender_pk),
                collision_height=c_fraud.collision_h,
                extracted_secret_key=bytes(c_fraud.extracted_sk),
                raw_proof=bytes(c_fraud),
            )
            return ProcessResult(
                status_code=CSLS_ERR_FRAUD,
                accepted=False,
                accumulated_usdc=self.accumulated_usdc,
                error_message="EQUIVOCATION_DETECTED: Private key algebraically extracted!",
                fraud_proof=proof,
            )

        error_map = {
            CSLS_ERR_EXPOSURE_CAP: "EXPOSURE_BUFFER_EXCEEDED: Local credit limit reached",
            CSLS_ERR_REPLAY: "REPLAY_PACKET_IGNORED",
            CSLS_ERR_OUT_OF_ORDER: "OUT_OF_ORDER_OR_OLD_HEIGHT",
            CSLS_ERR_FORGED_HASH: "FORGED_CHALLENGE_HASH",
        }
        msg = error_map.get(res, f"UNKNOWN_ERROR_{res}")
        return ProcessResult(
            status_code=res,
            accepted=False,
            accumulated_usdc=self.accumulated_usdc,
            error_message=msg,
        )

    def close(self):
        _LIB.csls_vendor_destroy(ctypes.byref(self._ctx))

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


if __name__ == "__main__":
    import time
    print("=" * 70)
    print("🚀 CAUSAL-SLASH PYTHON SDK: LIVE BENCHMARK & TEST SUITE")
    print("=" * 70)

    # 1. Initialize
    agent = CausalAgentWallet()
    vendor = CausalVendorNode(delta_v_usdc=1000.0) # High buffer for benchmark

    print(f"Agent PK:  {agent.public_key_hex[:18]}...")
    print(f"Vendor PK: {vendor.public_key_hex[:18]}...")

    # 2. Benchmark streaming 50,000 cheques
    n = 50000
    print(f"\n[1] Streaming {n:,} micro-cheques from Python through native C engine...")
    t0 = time.perf_counter()
    for _ in range(n):
        c = agent.sign_cheque(vendor.public_key, amount_usdc=0.0001)
        r = vendor.process_cheque(c)
        assert r.accepted

    t1 = time.perf_counter()
    total_time = t1 - t0
    ops_per_sec = n / total_time
    us_per_op = (total_time / n) * 1e6

    print(f"  ✅ Completed {n:,} cheques in {total_time:.4f} seconds")
    print(f"  ⚡ Latency: {us_per_op:.2f} microseconds per full cycle (Sign + Verify)")
    print(f"  🚀 Throughput: {ops_per_sec:,.0f} operations/second in Python!")
    print(f"  💰 Settled Volume: ${vendor.accumulated_usdc:.4f} USDC")

    # 3. Equivocation Detection & Key Extraction Test
    print("\n[2] Testing Equivocation Trap from Python...")
    attacker_agent = CausalAgentWallet()
    v2 = CausalVendorNode(delta_v_usdc=1.0)
    legit_cheque = attacker_agent.sign_cheque(v2.public_key, amount_usdc=0.05)
    r1 = v2.process_cheque(legit_cheque)
    assert r1.accepted, f"Legitimate cheque failed: {r1.error_message}"
    print(f"  Legitimate cheque at height h={legit_cheque.height} accepted: True")

    # Tamper height back to duplicate for double-spending attack
    attacker_agent._ctx.height = legit_cheque.height
    fake_pk = b"\x02" + (b"\x77" * 32)
    fork_cheque = attacker_agent.sign_cheque(fake_pk, amount_usdc=0.07)

    r2 = v2.process_cheque(fork_cheque)
    assert not r2.accepted
    assert r2.fraud_proof is not None
    assert r2.fraud_proof.extracted_secret_key == bytes(attacker_agent._ctx.sk)
    print("  🔥 EQUIVOCATION DETECTED & PRIVATE KEY EXTRACTED 100%!")
    print(f"  Offender PK:  {r2.fraud_proof.offender_pk.hex()[:18]}...")
    print(f"  Extracted SK: {r2.fraud_proof.extracted_secret_key.hex()[:18]}...")
    print(f"  True SK:      {bytes(attacker_agent._ctx.sk).hex()[:18]}...")
    print("  ✅ Math Invariant Verified: Extracted Key Matches 100%!")
    print("=" * 70)
    print("ALL PYTHON SDK VERIFICATIONS PASSED WITH ZERO ERRORS!")
