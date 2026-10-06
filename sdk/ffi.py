# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Causal-Slash Protocol: Native C11 FFI Layer (sdk/ffi.py)
Provides zero-latency ctypes bindings to libcausal_slash.so and libbloodhound.so.
Defines binary-exact C structures, memory layouts, and function signatures.
Strictly contains NO business logic or wallet classes.
"""

from __future__ import annotations

import atexit
import ctypes
import os
import subprocess
from typing import Any, Optional, Union

# ---------------------------------------------------------------------------
# Path Resolution & Shared Library Discovery
# ---------------------------------------------------------------------------
_SDK_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_SDK_DIR)

_SO_PATHS = [
    os.path.join(_SDK_DIR, "libcausal_slash.so"),
    os.path.join(_PROJECT_ROOT, "libcausal_slash.so"),
]

_BLOODHOUND_SO_PATHS = [
    os.path.join(_SDK_DIR, "libbloodhound.so"),
    os.path.join(_PROJECT_ROOT, "libbloodhound.so"),
]

# ---------------------------------------------------------------------------
# C-Structure Memory Layouts (Matching src/causal_daemon.h & src/schnorr_bloodhound.h)
# ---------------------------------------------------------------------------

class _CslsChequePkt(ctypes.Structure):
    """Packed 151-byte C11 cheque wire envelope."""
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

# Architectural & compatibility aliases
CausalPacket = _CslsChequePkt
CslsChequePkt = _CslsChequePkt


class EOTSKey(ctypes.Structure):
    """Exact-Once-Time-Signature (EOTS) key pair structure."""
    _pack_ = 1
    _fields_ = [
        ("sk", ctypes.c_uint8 * 32),
        ("pk", ctypes.c_uint8 * 33),
    ]


class _CslsFraudPkt(ctypes.Structure):
    """Packed 380-byte cryptographic equivocation fraud proof."""
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

CslsFraudPkt = _CslsFraudPkt


class _CslsSessionInitPkt(ctypes.Structure):
    """Packed 95-byte Session MAC handshake initialization envelope."""
    _pack_ = 1
    _fields_ = [
        ("magic", ctypes.c_uint32),
        ("type", ctypes.c_uint8),
        ("agent_pk", ctypes.c_uint8 * 33),
        ("vendor_pk", ctypes.c_uint8 * 33),
        ("session_nonce", ctypes.c_uint64),
        ("auth_mac", ctypes.c_uint8 * 16),
    ]

SessionState = _CslsSessionInitPkt
CslsSessionInitPkt = _CslsSessionInitPkt


class _CslsAgentCtx(ctypes.Structure):
    """Native C11 agent runtime context layout."""
    _fields_ = [
        ("sk", ctypes.c_uint8 * 32),
        ("pk", ctypes.c_uint8 * 33),
        ("_pad", ctypes.c_uint8 * 7),
        ("height", ctypes.c_uint64),
        ("watermark_boundary", ctypes.c_uint64),
        ("wal_fatal", ctypes.c_int),
        ("renew_requested", ctypes.c_int),
        ("cumulative_sent", ctypes.c_uint64),
        ("channels", ctypes.c_byte * 128),
        ("wal_path", ctypes.c_char * 256),
        ("wal_fd", ctypes.c_int),
    ]

CslsAgentCtx = _CslsAgentCtx


class _CslsHistoryEntry(ctypes.Structure):
    """Native history slot for replay and equivocation detection."""
    _fields_ = [
        ("agent_pk", ctypes.c_uint8 * 33),
        ("height", ctypes.c_uint64),
        ("amount", ctypes.c_uint64),
        ("challenge_e", ctypes.c_uint8 * 32),
        ("sig_s", ctypes.c_uint8 * 32),
        ("occupied", ctypes.c_bool),
    ]


class _CslsVendorCtx(ctypes.Structure):
    """Native C11 vendor runtime context layout (~8.38 MB)."""
    _fields_ = [
        ("sk", ctypes.c_uint8 * 32),
        ("pk", ctypes.c_uint8 * 33),
        ("_pad", ctypes.c_uint8 * 7),
        ("last_height", ctypes.c_uint64),
        ("cleared_amount", ctypes.c_uint64),
        ("accumulated_amount", ctypes.c_uint64),
        ("max_exposure_delta_v", ctypes.c_uint64),
        ("slot_seed", ctypes.c_uint64),
        ("enforce_mac", ctypes.c_int),
        ("channels", ctypes.c_byte * 128),
    ]

CslsVendorCtx = _CslsVendorCtx


class csls_channel_state_t(ctypes.Structure):
    """Per-peer channel state slot."""
    _pack_ = 1
    _fields_ = [
        ("peer_pk", ctypes.c_uint8 * 33),
        ("height", ctypes.c_uint64),
        ("cumulative_amt", ctypes.c_uint64),
        ("cleared_amt", ctypes.c_uint64),
        ("occupied", ctypes.c_bool),
    ]

ChannelState = csls_channel_state_t


class csls_channel_table_t(ctypes.Structure):
    """Dynamic O(1) multi-channel hash table header."""
    _fields_ = [
        ("count", ctypes.c_uint32),
        ("capacity", ctypes.c_uint32),
        ("channels", ctypes.POINTER(csls_channel_state_t)),
    ]

ChannelTable = csls_channel_table_t


class BloodhoundPayload(ctypes.Structure):
    """Bloodhound watchtower exploit payload (Base L2 commit-reveal slash)."""
    _fields_ = [
        ("extracted_sk", ctypes.c_uint8 * 32),
        ("commit_salt", ctypes.c_uint8 * 32),
        ("commit_hash", ctypes.c_uint8 * 32),
        ("target_agent", ctypes.c_uint8 * 20),
        ("collision_height", ctypes.c_uint64),
    ]


# ---------------------------------------------------------------------------
# Opaque Heap-Allocated Handles
# ---------------------------------------------------------------------------

class _AgentCtxHandle(ctypes.c_void_p):
    """
    Opaque handle to heap-allocated C11 csls_agent_ctx_t.
    Guarantees zero-copy access to cryptographic keys and state counters.
    """
    @property
    def height(self) -> int:
        if not self.value:
            return 0
        return ctypes.c_uint64.from_address(self.value + 72).value

    @height.setter
    def height(self, val: int) -> None:
        if self.value:
            ctypes.c_uint64.from_address(self.value + 72).value = val

    @property
    def cumulative_sent(self) -> int:
        if not self.value:
            return 0
        return ctypes.c_uint64.from_address(self.value + 96).value

    @cumulative_sent.setter
    def cumulative_sent(self, val: int) -> None:
        if self.value:
            ctypes.c_uint64.from_address(self.value + 96).value = val

    @property
    def sk(self) -> bytes:
        if not self.value:
            return b""
        return bytes((ctypes.c_uint8 * 32).from_address(self.value))

    @property
    def pk(self) -> bytes:
        if not self.value:
            return b""
        return bytes((ctypes.c_uint8 * 33).from_address(self.value + 32))

AgentCtxHandle = _AgentCtxHandle


class _VendorCtxHandle(ctypes.c_void_p):
    """
    Opaque handle to heap-allocated C11 csls_vendor_ctx_t (~8.38 MB).
    Guarantees safe C-heap allocation preventing Python heap corruption.
    """
    @property
    def last_height(self) -> int:
        if not self.value:
            return 0
        return ctypes.c_uint64.from_address(self.value + 72).value

    @last_height.setter
    def last_height(self, val: int) -> None:
        if self.value:
            ctypes.c_uint64.from_address(self.value + 72).value = val

    @property
    def cleared_amount(self) -> int:
        if not self.value:
            return 0
        return ctypes.c_uint64.from_address(self.value + 80).value

    @cleared_amount.setter
    def cleared_amount(self, val: int) -> None:
        if self.value:
            ctypes.c_uint64.from_address(self.value + 80).value = val

    @property
    def accumulated_amount(self) -> int:
        if not self.value:
            return 0
        return ctypes.c_uint64.from_address(self.value + 88).value

    @accumulated_amount.setter
    def accumulated_amount(self, val: int) -> None:
        if self.value:
            ctypes.c_uint64.from_address(self.value + 88).value = val

    @property
    def max_exposure_delta_v(self) -> int:
        if not self.value:
            return 0
        return ctypes.c_uint64.from_address(self.value + 96).value

    @property
    def sk(self) -> bytes:
        if not self.value:
            return b""
        return bytes((ctypes.c_uint8 * 32).from_address(self.value))

    @property
    def pk(self) -> bytes:
        if not self.value:
            return b""
        return bytes((ctypes.c_uint8 * 33).from_address(self.value + 32))

VendorCtxHandle = _VendorCtxHandle


# ---------------------------------------------------------------------------
# Fallback Pure Python Stub (When C Library is Unavailable)
# ---------------------------------------------------------------------------

class _LibPurePythonStub:
    """Fallback stub when native C11 shared library is unavailable."""
    def csls_crypto_global_cleanup(self) -> None:
        pass

    def csls_crypto_global_init(self) -> int:
        return 0

    def csls_extract_private_key(self, c1_ref: Any, c2_ref: Any, out_sk: Any) -> int:
        from .crypto import SECP256K1_Q
        c1 = c1_ref._obj if hasattr(c1_ref, "_obj") else c1_ref
        c2 = c2_ref._obj if hasattr(c2_ref, "_obj") else c2_ref
        if c1.height != c2.height:
            return -2
        if bytes(c1.agent_pk) != bytes(c2.agent_pk):
            return -6
        if bytes(c1.vendor_pk) != bytes(c2.vendor_pk):
            return -7
        if bytes(c1.challenge_e) == bytes(c2.challenge_e):
            return -3
        s1 = int.from_bytes(bytes(c1.sig_s), "big")
        s2 = int.from_bytes(bytes(c2.sig_s), "big")
        e1 = int.from_bytes(bytes(c1.challenge_e), "big")
        e2 = int.from_bytes(bytes(c2.challenge_e), "big")
        delta_s = (s1 - s2) % SECP256K1_Q
        delta_e = (e1 - e2) % SECP256K1_Q
        inv_delta_e = pow(delta_e, -1, SECP256K1_Q)
        extracted = ((delta_s * inv_delta_e) % SECP256K1_Q).to_bytes(32, "big")
        for i in range(32):
            out_sk[i] = extracted[i]
        return 0


# ---------------------------------------------------------------------------
# Shared Library Loaders
# ---------------------------------------------------------------------------

def _load_c_lib() -> Union[ctypes.CDLL, _LibPurePythonStub]:
    """Loads libcausal_slash.so or returns _LibPurePythonStub."""
    if os.environ.get("CSLS_FORCE_PYTHON", "").lower() in ("1", "true", "yes"):
        return _LibPurePythonStub()
    for path in _SO_PATHS:
        if os.path.exists(path):
            try:
                return ctypes.CDLL(path)
            except OSError:
                pass
    try:
        cmd = ["make", "-C", _PROJECT_ROOT, "libcausal_slash.so"]
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if os.path.exists(_SO_PATHS[0]):
            return ctypes.CDLL(_SO_PATHS[0])
    except Exception:
        pass
    return _LibPurePythonStub()

load_c_lib = _load_c_lib


def _load_bloodhound_lib() -> Optional[ctypes.CDLL]:
    """Loads libbloodhound.so if available."""
    if os.environ.get("CSLS_FORCE_PYTHON", "").lower() in ("1", "true", "yes"):
        return None
    for path in _BLOODHOUND_SO_PATHS:
        if os.path.exists(path):
            try:
                lib = ctypes.CDLL(path)
                # Bloodhound carries separate OpenSSL crypto globals
                if hasattr(lib, "csls_crypto_global_init"):
                    lib.csls_crypto_global_init.restype = ctypes.c_int
                    lib.csls_crypto_global_init.argtypes = []
                    lib.csls_crypto_global_init()
                return lib
            except OSError:
                pass
    try:
        cmd = ["make", "-C", _PROJECT_ROOT, "sdk/libbloodhound.so"]
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if os.path.exists(_BLOODHOUND_SO_PATHS[0]):
            lib = ctypes.CDLL(_BLOODHOUND_SO_PATHS[0])
            if hasattr(lib, "csls_crypto_global_init"):
                lib.csls_crypto_global_init.restype = ctypes.c_int
                lib.csls_crypto_global_init.argtypes = []
                lib.csls_crypto_global_init()
            return lib
    except Exception:
        pass
    return None

load_bloodhound_lib = _load_bloodhound_lib


# ---------------------------------------------------------------------------
# Module Initialization & Function Prototype Binding
# ---------------------------------------------------------------------------

_LIB = _load_c_lib()
_IS_NATIVE = isinstance(_LIB, ctypes.CDLL)

_LIB_BLOODHOUND = _load_bloodhound_lib()

if _IS_NATIVE:
    _LIB.csls_crypto_global_init.restype = ctypes.c_int
    _LIB.csls_crypto_global_init.argtypes = []

    _LIB.csls_crypto_global_cleanup.restype = None
    _LIB.csls_crypto_global_cleanup.argtypes = []

    _LIB.csls_agent_new.restype = ctypes.c_void_p
    _LIB.csls_agent_new.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_char_p,
    ]

    _LIB.csls_agent_free.restype = None
    _LIB.csls_agent_free.argtypes = [ctypes.c_void_p]

    _LIB.csls_vendor_new.restype = ctypes.c_void_p
    _LIB.csls_vendor_new.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_uint64,
    ]

    _LIB.csls_vendor_free.restype = None
    _LIB.csls_vendor_free.argtypes = [ctypes.c_void_p]

    _LIB.csls_agent_init.restype = ctypes.c_int
    _LIB.csls_agent_init.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_char_p,
    ]

    _LIB.csls_agent_destroy.restype = None
    _LIB.csls_agent_destroy.argtypes = [ctypes.c_void_p]

    _LIB.csls_agent_sign_cheque.restype = ctypes.c_int
    _LIB.csls_agent_sign_cheque.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_uint64,
        ctypes.POINTER(_CslsChequePkt),
    ]

    _LIB.csls_vendor_init.restype = ctypes.c_int
    _LIB.csls_vendor_init.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_uint64,
    ]

    _LIB.csls_vendor_destroy.restype = None
    _LIB.csls_vendor_destroy.argtypes = [ctypes.c_void_p]

    _LIB.csls_vendor_process_cheque.restype = ctypes.c_int
    _LIB.csls_vendor_process_cheque.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_CslsChequePkt),
        ctypes.POINTER(_CslsFraudPkt),
    ]

    _LIB.csls_vendor_advance_cleared.restype = ctypes.c_int
    _LIB.csls_vendor_advance_cleared.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_uint64,
    ]

    _LIB.csls_vendor_get_channel_state.restype = ctypes.c_int
    _LIB.csls_vendor_get_channel_state.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_uint64),
    ]

    _LIB.csls_agent_get_channel_state.restype = ctypes.c_int
    _LIB.csls_agent_get_channel_state.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_uint64),
    ]

    # Session MAC C bindings
    _LIB.csls_agent_session_begin.restype = ctypes.c_int
    _LIB.csls_agent_session_begin.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint8 * 33),
        ctypes.POINTER(_CslsSessionInitPkt),
    ]

    _LIB.csls_agent_sign_cheque_mac.restype = ctypes.c_int
    _LIB.csls_agent_sign_cheque_mac.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint8 * 33),
        ctypes.c_uint64,
        ctypes.POINTER(_CslsChequePkt),
        ctypes.POINTER(ctypes.c_uint8 * 16),
    ]

    _LIB.csls_vendor_enable_mac.restype = ctypes.c_int
    _LIB.csls_vendor_enable_mac.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
    ]

    _LIB.csls_vendor_session_init.restype = ctypes.c_int
    _LIB.csls_vendor_session_init.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_CslsSessionInitPkt),
    ]

    _LIB.csls_vendor_process_cheque_mac.restype = ctypes.c_int
    _LIB.csls_vendor_process_cheque_mac.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_CslsChequePkt),
        ctypes.POINTER(ctypes.c_uint8 * 16),
        ctypes.POINTER(_CslsFraudPkt),
    ]

    # Ensure global crypto is initialized once and cleaned up on Python exit
    if _LIB.csls_crypto_global_init() != 0:
        raise RuntimeError("Failed to initialize Causal-Slash OpenSSL secp256k1 crypto engine")
    atexit.register(_LIB.csls_crypto_global_cleanup)

if _LIB_BLOODHOUND is not None:
    _LIB_BLOODHOUND.bloodhound_new.restype = ctypes.c_void_p
    _LIB_BLOODHOUND.bloodhound_new.argtypes = [ctypes.c_char_p]

    _LIB_BLOODHOUND.bloodhound_free.restype = None
    _LIB_BLOODHOUND.bloodhound_free.argtypes = [ctypes.c_void_p]

    _LIB_BLOODHOUND.bloodhound_inspect_packet.restype = ctypes.c_int
    _LIB_BLOODHOUND.bloodhound_inspect_packet.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(BloodhoundPayload),
    ]

__all__ = [
    "_LIB",
    "_IS_NATIVE",
    "_LIB_BLOODHOUND",
    "_load_c_lib",
    "_load_bloodhound_lib",
    "load_c_lib",
    "load_bloodhound_lib",
    "_SDK_DIR",
    "_PROJECT_ROOT",
    "_SO_PATHS",
    "_BLOODHOUND_SO_PATHS",
    "_CslsChequePkt",
    "_CslsFraudPkt",
    "_CslsSessionInitPkt",
    "_CslsAgentCtx",
    "_CslsVendorCtx",
    "_CslsHistoryEntry",
    "csls_channel_state_t",
    "csls_channel_table_t",
    "BloodhoundPayload",
    "CausalPacket",
    "CslsChequePkt",
    "EOTSKey",
    "CslsFraudPkt",
    "SessionState",
    "CslsSessionInitPkt",
    "CslsAgentCtx",
    "CslsVendorCtx",
    "ChannelState",
    "ChannelTable",
    "_AgentCtxHandle",
    "_VendorCtxHandle",
    "AgentCtxHandle",
    "VendorCtxHandle",
    "_LibPurePythonStub",
]
