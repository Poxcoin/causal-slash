# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Causal-Slash Protocol: Binary Packet Framing & Envelope Serialization (sdk/packet.py)
Provides binary packing, unpacking, validation, and serialization for:
- 151-byte legacy EOTS cheques
- 167-byte Session-MAC authenticated wire cheques
- 95-byte Session-Init handshake packets
- 380-byte Equivocation fraud proofs
Strictly encapsulates all packet magic bytes and wire-level protocol framing.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, Union

# ---------------------------------------------------------------------------
# Protocol Magic Bytes & Packet Types
# ---------------------------------------------------------------------------
CSLS_MAGIC = 0x43534C53  # ASCII: 'CSLS' (0x534C5343 in little-endian on wire)
CSLS_PKT_CHEQUE = 0x01
CSLS_PKT_ACK = 0x02
CSLS_PKT_FRAUD = 0x03
CSLS_PKT_HALT = 0x04
CSLS_PKT_SESSION_INIT = 0x05

# ---------------------------------------------------------------------------
# Protocol Status & Error Codes
# ---------------------------------------------------------------------------
CSLS_OK = 0
CSLS_ERR_EXPOSURE_CAP = -12
CSLS_ERR_FRAUD = -20
CSLS_ERR_REPLAY = -21
CSLS_ERR_OUT_OF_ORDER = -22
CSLS_ERR_FORGED_HASH = -23
CSLS_ERR_BAD_MAC = -24
CSLS_ERR_NO_SESSION = -25
CSLS_ERR_WAL_FATAL = -27

# ---------------------------------------------------------------------------
# Binary Packet Lengths & struct Formats
# ---------------------------------------------------------------------------
CHEQUE_PKT_LEN = 151
CHEQUE_MAC_PKT_LEN = 167
SESSION_INIT_PKT_LEN = 95
FRAUD_PKT_LEN = 380

CHEQUE_STRUCT_FMT = "<IB33s33sQQ32s32s"
SESSION_INIT_STRUCT_FMT = "<IB33s33sQ16s"
FRAUD_STRUCT_FMT = "<IB33sQ32s151s151s"


# ---------------------------------------------------------------------------
# Binary Envelope Packing & Unpacking Functions
# ---------------------------------------------------------------------------
def pack_cheque(
    agent_pk: bytes,
    vendor_pk: bytes,
    height: int,
    cumulative_amt: int,
    challenge_e: bytes,
    sig_s: bytes,
    mac: Optional[bytes] = None,
) -> bytes:
    """
    Serializes a cheque into a 151-byte (or 167-byte with MAC) wire envelope.
    """
    if len(agent_pk) != 33:
        raise ValueError(f"agent_pk must be 33 bytes, got {len(agent_pk)}")
    if len(vendor_pk) != 33:
        raise ValueError(f"vendor_pk must be 33 bytes, got {len(vendor_pk)}")
    if len(challenge_e) != 32:
        raise ValueError(f"challenge_e must be 32 bytes, got {len(challenge_e)}")
    if len(sig_s) != 32:
        raise ValueError(f"sig_s must be 32 bytes, got {len(sig_s)}")

    raw = struct.pack(
        CHEQUE_STRUCT_FMT,
        CSLS_MAGIC,
        CSLS_PKT_CHEQUE,
        agent_pk,
        vendor_pk,
        height,
        cumulative_amt,
        challenge_e,
        sig_s,
    )
    if mac is not None:
        if len(mac) != 16:
            raise ValueError(f"mac must be 16 bytes, got {len(mac)}")
        raw = raw + mac
    return raw


def unpack_cheque(raw: bytes) -> Dict[str, Any]:
    """
    Unpacks a 151-byte or 167-byte cheque envelope into its header and payload fields.
    """
    pkt_len = len(raw)
    if pkt_len != CHEQUE_PKT_LEN and pkt_len != CHEQUE_MAC_PKT_LEN:
        raise ValueError(f"Invalid cheque packet length: expected 151 or 167 bytes, got {pkt_len}")

    magic, pkt_type, agent_pk, vendor_pk, height, cumulative_amt, challenge_e, sig_s = struct.unpack(
        CHEQUE_STRUCT_FMT, raw[:CHEQUE_PKT_LEN]
    )
    mac = raw[CHEQUE_PKT_LEN:] if pkt_len == CHEQUE_MAC_PKT_LEN else None

    return {
        "magic": magic,
        "type": pkt_type,
        "agent_pk": agent_pk,
        "vendor_pk": vendor_pk,
        "height": height,
        "cumulative_amt": cumulative_amt,
        "challenge_e": challenge_e,
        "sig_s": sig_s,
        "mac": mac,
    }


def validate_cheque_header(raw: bytes, allow_mac: bool = True) -> Tuple[bool, Optional[str]]:
    """
    Validates protocol envelope framing (magic bytes, packet type, length).
    Returns (is_valid, error_reason).
    """
    pkt_len = len(raw)
    if pkt_len == CHEQUE_PKT_LEN:
        pass
    elif pkt_len == CHEQUE_MAC_PKT_LEN:
        if not allow_mac:
            return False, f"Session MAC envelope received but allow_mac is False ({pkt_len} bytes)"
    else:
        return False, f"Invalid packet length: {pkt_len} (expected 151 or 167)"

    magic = struct.unpack_from("<I", raw, 0)[0]
    if magic != CSLS_MAGIC:
        return False, f"Invalid magic bytes: 0x{magic:08X} (expected 0x{CSLS_MAGIC:08X})"

    pkt_type = raw[4]
    if pkt_type != CSLS_PKT_CHEQUE:
        return False, f"Invalid packet type: 0x{pkt_type:02X} (expected 0x{CSLS_PKT_CHEQUE:02X})"

    return True, None


def pack_session_init(
    agent_pk: bytes,
    vendor_pk: bytes,
    session_nonce: int,
    auth_mac: bytes,
) -> bytes:
    """Serializes a 95-byte Session-Init handshake packet."""
    if len(agent_pk) != 33:
        raise ValueError(f"agent_pk must be 33 bytes, got {len(agent_pk)}")
    if len(vendor_pk) != 33:
        raise ValueError(f"vendor_pk must be 33 bytes, got {len(vendor_pk)}")
    if len(auth_mac) != 16:
        raise ValueError(f"auth_mac must be 16 bytes, got {len(auth_mac)}")

    return struct.pack(
        SESSION_INIT_STRUCT_FMT,
        CSLS_MAGIC,
        CSLS_PKT_SESSION_INIT,
        agent_pk,
        vendor_pk,
        session_nonce,
        auth_mac,
    )


def unpack_session_init(raw: bytes) -> Dict[str, Any]:
    """Unpacks a 95-byte Session-Init envelope."""
    if len(raw) != SESSION_INIT_PKT_LEN:
        raise ValueError(f"Invalid Session-Init length: expected 95 bytes, got {len(raw)}")

    magic, pkt_type, agent_pk, vendor_pk, session_nonce, auth_mac = struct.unpack(
        SESSION_INIT_STRUCT_FMT, raw
    )
    return {
        "magic": magic,
        "type": pkt_type,
        "agent_pk": agent_pk,
        "vendor_pk": vendor_pk,
        "session_nonce": session_nonce,
        "auth_mac": auth_mac,
    }


def validate_session_init_header(raw: bytes) -> Tuple[bool, Optional[str]]:
    """Validates Session-Init packet framing."""
    if len(raw) != SESSION_INIT_PKT_LEN:
        return False, f"Invalid packet length: {len(raw)} (expected 95)"
    magic, pkt_type = struct.unpack_from("<IB", raw, 0)
    if magic != CSLS_MAGIC:
        return False, f"Invalid magic bytes: 0x{magic:08X} (expected 0x{CSLS_MAGIC:08X})"
    if pkt_type != CSLS_PKT_SESSION_INIT:
        return False, f"Invalid packet type: 0x{pkt_type:02X} (expected 0x{CSLS_PKT_SESSION_INIT:02X})"
    return True, None


def pack_fraud_proof(
    offender_pk: bytes,
    collision_height: int,
    extracted_sk: bytes,
    cheque1_bytes: bytes,
    cheque2_bytes: bytes,
) -> bytes:
    """Serializes a 380-byte fraud proof envelope."""
    if len(offender_pk) != 33:
        raise ValueError("offender_pk must be 33 bytes")
    if len(extracted_sk) != 32:
        raise ValueError("extracted_sk must be 32 bytes")
    if len(cheque1_bytes) != CHEQUE_PKT_LEN or len(cheque2_bytes) != CHEQUE_PKT_LEN:
        raise ValueError("Both cheques in fraud proof must be 151 bytes")

    return struct.pack(
        FRAUD_STRUCT_FMT,
        CSLS_MAGIC,
        CSLS_PKT_FRAUD,
        offender_pk,
        collision_height,
        extracted_sk,
        cheque1_bytes,
        cheque2_bytes,
    )


def unpack_fraud_proof(raw: bytes) -> Dict[str, Any]:
    """Unpacks a 380-byte fraud proof packet."""
    if len(raw) != FRAUD_PKT_LEN:
        raise ValueError(f"Invalid fraud proof length: expected 380 bytes, got {len(raw)}")

    magic, pkt_type, offender_pk, collision_h, extracted_sk, c1, c2 = struct.unpack(
        FRAUD_STRUCT_FMT, raw
    )
    return {
        "magic": magic,
        "type": pkt_type,
        "offender_pk": offender_pk,
        "collision_height": collision_h,
        "extracted_sk": extracted_sk,
        "cheque1": c1,
        "cheque2": c2,
    }


# ---------------------------------------------------------------------------
# High-Level Data Structures
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Cheque:
    """Immutable micro-payment cheque representation (151B legacy or 167B with Session MAC)."""
    agent_pk: bytes
    vendor_pk: bytes
    height: int
    cumulative_amount_usdc: float
    raw_packet: bytes
    mac: Optional[bytes] = None

    @classmethod
    def from_c_pkt(cls, pkt: Any, mac: Optional[bytes] = None) -> Cheque:
        raw = bytes(pkt)
        if mac is not None:
            raw = raw + mac
        return cls(
            agent_pk=bytes(pkt.agent_pk),
            vendor_pk=bytes(pkt.vendor_pk),
            height=pkt.height,
            cumulative_amount_usdc=pkt.cumulative_amt / 1e6,
            raw_packet=raw,
            mac=mac,
        )

    @classmethod
    def from_raw(cls, raw: bytes) -> Cheque:
        """Constructs a Cheque from raw wire bytes (151 or 167 bytes)."""
        fields = unpack_cheque(raw)
        return cls(
            agent_pk=fields["agent_pk"],
            vendor_pk=fields["vendor_pk"],
            height=fields["height"],
            cumulative_amount_usdc=fields["cumulative_amt"] / 1e6,
            raw_packet=raw,
            mac=fields["mac"],
        )

    @property
    def cumulative_amt(self) -> int:
        return int(round(self.cumulative_amount_usdc * 1e6))

    @property
    def challenge_e(self) -> bytes:
        if len(self.raw_packet) >= 151:
            return self.raw_packet[87:119]
        return b""

    @property
    def sig_s(self) -> bytes:
        if len(self.raw_packet) >= 151:
            return self.raw_packet[119:151]
        return b""


CslsCheque = Cheque


@dataclass(frozen=True)
class FraudProof:
    """Cryptographic proof of equivocation with extracted private key."""
    offender_pk: bytes
    collision_height: int
    extracted_secret_key: bytes
    raw_proof: bytes


@dataclass(frozen=True)
class ProcessResult:
    """Result of cheque processing by vendor."""
    status_code: int
    accepted: bool
    accumulated_usdc: float
    error_message: Optional[str] = None
    fraud_proof: Optional[FraudProof] = None


__all__ = [
    "CSLS_MAGIC",
    "CSLS_PKT_CHEQUE",
    "CSLS_PKT_ACK",
    "CSLS_PKT_FRAUD",
    "CSLS_PKT_HALT",
    "CSLS_PKT_SESSION_INIT",
    "CSLS_OK",
    "CSLS_ERR_EXPOSURE_CAP",
    "CSLS_ERR_FRAUD",
    "CSLS_ERR_REPLAY",
    "CSLS_ERR_OUT_OF_ORDER",
    "CSLS_ERR_FORGED_HASH",
    "CSLS_ERR_BAD_MAC",
    "CSLS_ERR_NO_SESSION",
    "CSLS_ERR_WAL_FATAL",
    "CHEQUE_PKT_LEN",
    "CHEQUE_MAC_PKT_LEN",
    "SESSION_INIT_PKT_LEN",
    "FRAUD_PKT_LEN",
    "CHEQUE_STRUCT_FMT",
    "SESSION_INIT_STRUCT_FMT",
    "FRAUD_STRUCT_FMT",
    "pack_cheque",
    "unpack_cheque",
    "validate_cheque_header",
    "pack_session_init",
    "unpack_session_init",
    "validate_session_init_header",
    "pack_fraud_proof",
    "unpack_fraud_proof",
    "Cheque",
    "CslsCheque",
    "FraudProof",
    "ProcessResult",
]
