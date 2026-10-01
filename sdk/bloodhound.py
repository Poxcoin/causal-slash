# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Causal-Slash Protocol: Bloodhound Watchtower FFI Loader.

Python ctypes binding to the C11 watchtower (src/schnorr_bloodhound.c) built as
sdk/libbloodhound.so. The daemon inspects 151-byte EOTS cheques on the wire,
detects same-height equivocation in O(1), algebraically extracts the offender's
private key, and emits a commit_salt/commit_hash pair that is bitwise-compatible
with PerformanceCollateralVault.commitFraudProof (Base L2).

IMPORTANT: libbloodhound.so is linked from its own copy of the C core, so it
carries SEPARATE static OpenSSL crypto globals. Callers MUST let this module
run csls_crypto_global_init() on THIS handle (done automatically at load).
"""

from __future__ import annotations

import ctypes
import os
import subprocess

_SDK_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_SDK_DIR)
_SO_PATH = os.path.join(_SDK_DIR, "libbloodhound.so")

# bloodhound_exploit_payload_t (default alignment, NOT packed):
# offsets 0 / 32 / 64 / 96, collision_height at 120 (4B pad after target_agent)
class BloodhoundPayload(ctypes.Structure):
    _fields_ = [
        ("extracted_sk", ctypes.c_uint8 * 32),
        ("commit_salt", ctypes.c_uint8 * 32),
        ("commit_hash", ctypes.c_uint8 * 32),
        ("target_agent", ctypes.c_uint8 * 20),
        ("collision_height", ctypes.c_uint64),
    ]


class BloodhoundWatchdog:
    """
    Wire-path equivocation trap. Feed every observed 151-byte cheque through
    inspect(); a return code of 1 means an equivocation was captured and the
    payload carries everything needed for the on-chain commit-reveal slash.
    """

    def __init__(self, hunter_address: bytes):
        if len(hunter_address) != 20:
            raise ValueError("hunter_address must be exactly 20 bytes (EVM address)")
        self._lib = _load_lib()
        self._hunter = bytes(hunter_address)
        self._lib.bloodhound_new.restype = ctypes.c_void_p
        self._lib.bloodhound_new.argtypes = [ctypes.c_char_p]
        self._ctx = self._lib.bloodhound_new(self._hunter)
        if not self._ctx:
            raise RuntimeError("bloodhound_new failed to allocate watchtower context")
        self._lib.bloodhound_inspect_packet.restype = ctypes.c_int
        self._lib.bloodhound_inspect_packet.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(BloodhoundPayload),
        ]
        self.packets_inspected = 0
        self.equivocations_captured = 0

    def inspect(self, cheque_bytes: bytes) -> tuple[int, BloodhoundPayload]:
        """
        Returns (capture_code, payload). capture_code: 1 = equivocation captured,
        0 = clean packet recorded, -1 = malformed packet.
        """
        if len(cheque_bytes) != 151:
            raise ValueError(f"expected 151-byte cheque, got {len(cheque_bytes)}")
        pkt_buf = (ctypes.c_uint8 * 151).from_buffer_copy(cheque_bytes)
        payload = BloodhoundPayload()
        rc = self._lib.bloodhound_inspect_packet(
            ctypes.c_void_p(self._ctx), pkt_buf, ctypes.byref(payload)
        )
        self.packets_inspected += 1
        if rc == 1:
            self.equivocations_captured += 1
        return rc, payload

    def close(self) -> None:
        if getattr(self, "_ctx", None):
            self._lib.bloodhound_free(ctypes.c_void_p(self._ctx))
            self._ctx = None

    def __enter__(self) -> "BloodhoundWatchdog":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


_LIB_CACHE = None


def _load_lib() -> ctypes.CDLL:
    global _LIB_CACHE
    if _LIB_CACHE is not None:
        return _LIB_CACHE
    if not os.path.exists(_SO_PATH):
        subprocess.check_call(
            ["make", "-C", _PROJECT_ROOT, "sdk/libbloodhound.so"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    lib = ctypes.CDLL(_SO_PATH)
    lib.csls_crypto_global_init.restype = ctypes.c_int
    lib.csls_crypto_global_init.argtypes = []
    if lib.csls_crypto_global_init() != 0:
        raise RuntimeError("csls_crypto_global_init failed for libbloodhound.so")
    lib.bloodhound_free.restype = None
    lib.bloodhound_free.argtypes = [ctypes.c_void_p]
    _LIB_CACHE = lib
    return lib


# Layout hard guard: catches silent ABI drift between C header and this binding.
assert ctypes.sizeof(BloodhoundPayload) == 128, (
    f"BloodhoundPayload layout drift: {ctypes.sizeof(BloodhoundPayload)} != 128"
)
