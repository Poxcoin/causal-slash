# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Causal-Slash Protocol: Cryptographic Operations & Pure-Python Fallbacks (sdk/crypto.py)
Provides secp256k1 signature mathematics, SipHash-2-4 128-bit MAC, ECDH shared secret derivation,
EOTS nonce generation, and pure Python fallbacks when native C11 acceleration is unavailable.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from typing import Dict, Optional, Set, Tuple, Union

# Standardized conditional import for ecdsa library
try:
    import ecdsa
    _ECDSA_AVAILABLE = True
except ImportError:
    ecdsa = None
    _ECDSA_AVAILABLE = False


# ---------------------------------------------------------------------------
# SECP256k1 Curve Constants
# ---------------------------------------------------------------------------
SECP256K1_Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


# ---------------------------------------------------------------------------
# Byte Normalization Helper
# ---------------------------------------------------------------------------
def _parse_bytes(val: Union[str, bytes], expected_len: int) -> bytes:
    """Parses hex strings or raw bytes into fixed-length bytes."""
    if isinstance(val, str):
        if val.startswith("0x") or val.startswith("0X"):
            val = val[2:]
        b = bytes.fromhex(val)
    else:
        b = bytes(val)
    if len(b) != expected_len:
        raise ValueError(f"Expected {expected_len} bytes, got {len(b)} bytes")
    return b

parse_bytes = _parse_bytes


# ---------------------------------------------------------------------------
# SipHash-2-4 128-bit MAC Pure Python Implementation
# ---------------------------------------------------------------------------
def _sipround(v0: int, v1: int, v2: int, v3: int) -> Tuple[int, int, int, int]:
    v0 = (v0 + v1) & 0xFFFFFFFFFFFFFFFF
    v1 = ((v1 << 13) | (v1 >> 51)) & 0xFFFFFFFFFFFFFFFF
    v1 ^= v0
    v0 = ((v0 << 32) | (v0 >> 32)) & 0xFFFFFFFFFFFFFFFF

    v2 = (v2 + v3) & 0xFFFFFFFFFFFFFFFF
    v3 = ((v3 << 16) | (v3 >> 48)) & 0xFFFFFFFFFFFFFFFF
    v3 ^= v2

    v0 = (v0 + v3) & 0xFFFFFFFFFFFFFFFF
    v3 = ((v3 << 21) | (v3 >> 43)) & 0xFFFFFFFFFFFFFFFF
    v3 ^= v0

    v2 = (v2 + v1) & 0xFFFFFFFFFFFFFFFF
    v1 = ((v1 << 17) | (v1 >> 47)) & 0xFFFFFFFFFFFFFFFF
    v1 ^= v2
    v2 = ((v2 << 32) | (v2 >> 32)) & 0xFFFFFFFFFFFFFFFF
    return v0, v1, v2, v3

sipround = _sipround


def _siphash24(key: bytes, msg: bytes, fin_xor: int) -> int:
    k0 = struct.unpack("<Q", key[:8])[0]
    k1 = struct.unpack("<Q", key[8:16])[0]
    v0 = 0x736F6D6570736575 ^ k0
    v1 = 0x646F72616E646F6D ^ k1
    v2 = 0x6C7967656E657261 ^ k0
    v3 = 0x7465646279746573 ^ k1 ^ fin_xor
    full = len(msg) & ~7
    for off in range(0, full, 8):
        b = struct.unpack("<Q", msg[off:off+8])[0]
        v3 ^= b
        v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
        v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
        v0 ^= b
    b = (len(msg) & 7) << 56
    rem = msg[full:]
    for i, byte in enumerate(rem):
        b |= byte << (8 * i)
    v3 ^= b
    v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
    v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
    v0 ^= b
    v2 ^= 0xFF
    v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
    v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
    v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
    v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
    return v0 ^ v1 ^ v2 ^ v3

siphash24 = _siphash24


def _mac128(key: bytes, msg: bytes) -> bytes:
    """Computes a 128-bit SipHash-2-4 MAC tag from a 16-byte session key."""
    a = _siphash24(key, msg, 0)
    b = _siphash24(key, msg, 0xEE)
    return struct.pack("<QQ", a, b)

mac128 = _mac128


# ---------------------------------------------------------------------------
# Elliptic Curve Operations & Session Key Derivation (KDF)
# ---------------------------------------------------------------------------
def _ecdh_x(sk_bytes: bytes, peer_pk_bytes: bytes) -> bytes:
    """Computes the 32-byte X-coordinate of ECDH shared secret scalar multiplication."""
    if not _ECDSA_AVAILABLE:
        raise RuntimeError("ecdsa library is required for pure Python ECDH")
    sk_int = int.from_bytes(sk_bytes, "big")
    peer_vk = ecdsa.VerifyingKey.from_string(peer_pk_bytes, curve=ecdsa.SECP256k1)
    shared_point = sk_int * peer_vk.pubkey.point
    return int(shared_point.x()).to_bytes(32, "big")

ecdh_x = _ecdh_x


def _session_kdf(ecdh_x_coord: bytes, nonce: int) -> bytes:
    """Derives a 32-byte session authentication key using HMAC-SHA256."""
    kdf_buf = nonce.to_bytes(8, "big") + b"CSLS-MAC-v1"
    return hmac.new(ecdh_x_coord, kdf_buf, hashlib.sha256).digest()

session_kdf = _session_kdf


def _session_auth(ecdh_x_coord: bytes, agent_pk: bytes, vendor_pk: bytes, nonce: int) -> bytes:
    """Computes the 16-byte mutual authentication tag for SessionInit packets."""
    buf = agent_pk + vendor_pk + nonce.to_bytes(8, "big")
    return hmac.new(ecdh_x_coord, buf, hashlib.sha256).digest()[:16]

session_auth = _session_auth


def _derive_k(sk_bytes: bytes, vendor_pk: bytes, height: int) -> int:
    """
    Derives deterministic EOTS non-colliding nonce scalar k in Z_q.
    Implements RFC 6979 style iterative HMAC-SHA256 nonce derivation.
    """
    h_be = height.to_bytes(8, "big")
    k_preimage = vendor_pk + h_be
    counter = 0
    while True:
        data = k_preimage if counter == 0 else k_preimage + bytes([counter])
        k_hash = hmac.new(sk_bytes, data, hashlib.sha256).digest()
        k_val = int.from_bytes(k_hash, "big")
        if k_val >= SECP256K1_Q:
            k_val %= SECP256K1_Q
        if k_val != 0:
            return k_val
        counter += 1
        if counter > 255:
            raise RuntimeError("Counter exhausted during nonce derivation")

derive_k = _derive_k


def derive_public_key(sk_bytes: bytes, compressed: bool = True) -> bytes:
    """Derives compressed (33 bytes) or uncompressed (65 bytes) public key from private key."""
    if not _ECDSA_AVAILABLE:
        raise RuntimeError("ecdsa library is required for pure Python public key derivation")
    sk = ecdsa.SigningKey.from_string(sk_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    if compressed:
        return vk.to_string("compressed")
    return vk.to_string("uncompressed")


def compute_challenge(agent_pk: bytes, vendor_pk: bytes, height: int, cumulative_amt: int) -> Tuple[bytes, int]:
    """Computes challenge hash e = SHA256(agent_pk || vendor_pk || height || cumulative_amt) mod Q."""
    preimage = agent_pk + vendor_pk + height.to_bytes(8, "big") + cumulative_amt.to_bytes(8, "big")
    e_bytes = hashlib.sha256(preimage).digest()
    e_int = int.from_bytes(e_bytes, "big") % SECP256K1_Q
    return e_bytes, e_int


def extract_private_key_eots(e1_bytes: bytes, s1_bytes: bytes, e2_bytes: bytes, s2_bytes: bytes) -> bytes:
    """
    Algebraically extracts the private key from two EOTS cheques at the same height:
    delta_s = (s1 - s2) mod Q
    delta_e = (e1 - e2) mod Q
    sk = (delta_s * delta_e^-1) mod Q
    """
    s1 = int.from_bytes(s1_bytes, "big")
    s2 = int.from_bytes(s2_bytes, "big")
    e1 = int.from_bytes(e1_bytes, "big")
    e2 = int.from_bytes(e2_bytes, "big")
    delta_s = (s1 - s2) % SECP256K1_Q
    delta_e = (e1 - e2) % SECP256K1_Q
    inv_delta_e = pow(delta_e, -1, SECP256K1_Q)
    extracted = ((delta_s * inv_delta_e) % SECP256K1_Q).to_bytes(32, "big")
    return extracted


def sign_cheque_python(
    sk_bytes: bytes,
    pk_bytes: bytes,
    vendor_pk: bytes,
    height: int,
    cumulative_amt: int
) -> Tuple[bytes, bytes]:
    """
    Pure Python EOTS signing implementation:
    Returns (challenge_e: 32 bytes, sig_s: 32 bytes).
    """
    k = _derive_k(sk_bytes, vendor_pk, height)
    _, e = compute_challenge(pk_bytes, vendor_pk, height, cumulative_amt)
    sk_int = int.from_bytes(sk_bytes, "big")
    s = (k + e * sk_int) % SECP256K1_Q
    return e.to_bytes(32, "big"), s.to_bytes(32, "big")


# ---------------------------------------------------------------------------
# Fallback Pure Python Context Structures
# ---------------------------------------------------------------------------
class _PyAgentCtx:
    """Pure Python context for CausalAgentWallet when native C11 library is unavailable."""
    def __init__(self, sk: bytes, pk: bytes):
        self.sk = sk
        self.pk = pk
        self.height = 1
        self.cumulative_sent = 0
        self.watermark_boundary = 0xFFFFFFFFFFFFFFFF
        self.wal_fatal = 0
        self.channels: Dict[bytes, Tuple[int, int]] = {}
        self.sessions: Dict[bytes, bytes] = {}


class _PyVendorCtx:
    """Pure Python context for CausalVendorNode when native C11 library is unavailable."""
    def __init__(self, sk: bytes, pk: bytes, max_exposure_delta_v: int):
        self.sk = sk
        self.pk = pk
        self.last_height = 0
        self.cleared_amount = 0
        self.accumulated_amount = 0
        self.max_exposure_delta_v = max_exposure_delta_v
        self.enforce_mac = 1
        self.channels: Dict[bytes, Tuple[int, int, int]] = {}
        self.sessions: Dict[bytes, bytes] = {}
        self.history: Dict[Tuple[bytes, int], Tuple[int, bytes, bytes]] = {}
        self.disputed: Set[Tuple[bytes, int]] = set()


__all__ = [
    "SECP256K1_Q",
    "SECP256K1_P",
    "_parse_bytes",
    "parse_bytes",
    "_sipround",
    "sipround",
    "_siphash24",
    "siphash24",
    "_mac128",
    "mac128",
    "_ecdh_x",
    "ecdh_x",
    "_session_kdf",
    "session_kdf",
    "_session_auth",
    "session_auth",
    "_derive_k",
    "derive_k",
    "derive_public_key",
    "compute_challenge",
    "extract_private_key_eots",
    "sign_cheque_python",
    "_PyAgentCtx",
    "_PyVendorCtx",
]
