# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Causal-Slash Protocol: Agent Wallet, Vendor Node & P2P Debt Clearing (sdk/wallet.py)
Provides:
- CausalAgentWallet: Sovereign AI Agent Wallet for zero-gas streaming micro-payments.
- CausalVendorNode: Counterparty verification gate with credit exposure enforcement.
- DebtCycleMesh: In-memory high-frequency Kirchhoff cycle netting engine.
"""

from __future__ import annotations

import ctypes
import hashlib
import math
import os
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Deque, Dict, List, Optional, Set, Tuple, Union

try:
    from .crypto import (
        SECP256K1_Q,
        _PyAgentCtx,
        _PyVendorCtx,
        _derive_k,
        _ecdh_x,
        _mac128,
        _parse_bytes,
        _session_auth,
        _session_kdf,
        derive_public_key,
    )
    from .ffi import (
        _IS_NATIVE,
        _LIB,
        _AgentCtxHandle,
        _CslsChequePkt,
        _CslsFraudPkt,
        _CslsSessionInitPkt,
        _VendorCtxHandle,
    )
    from .packet import (
        CSLS_ERR_BAD_MAC,
        CSLS_ERR_EXPOSURE_CAP,
        CSLS_ERR_FORGED_HASH,
        CSLS_ERR_FRAUD,
        CSLS_ERR_NO_SESSION,
        CSLS_ERR_OUT_OF_ORDER,
        CSLS_ERR_REPLAY,
        CSLS_ERR_WAL_FATAL,
        CSLS_MAGIC,
        CSLS_OK,
        CSLS_PKT_CHEQUE,
        CSLS_PKT_FRAUD,
        CSLS_PKT_SESSION_INIT,
        Cheque,
        CslsCheque,
        FraudProof,
        ProcessResult,
    )
except (ImportError, ValueError):
    from crypto import (
        SECP256K1_Q,
        _PyAgentCtx,
        _PyVendorCtx,
        _derive_k,
        _ecdh_x,
        _mac128,
        _parse_bytes,
        _session_auth,
        _session_kdf,
        derive_public_key,
    )
    from ffi import (
        _IS_NATIVE,
        _LIB,
        _AgentCtxHandle,
        _CslsChequePkt,
        _CslsFraudPkt,
        _CslsSessionInitPkt,
        _VendorCtxHandle,
    )
    from packet import (
        CSLS_ERR_BAD_MAC,
        CSLS_ERR_EXPOSURE_CAP,
        CSLS_ERR_FORGED_HASH,
        CSLS_ERR_FRAUD,
        CSLS_ERR_NO_SESSION,
        CSLS_ERR_OUT_OF_ORDER,
        CSLS_ERR_REPLAY,
        CSLS_ERR_WAL_FATAL,
        CSLS_MAGIC,
        CSLS_OK,
        CSLS_PKT_CHEQUE,
        CSLS_PKT_FRAUD,
        CSLS_PKT_SESSION_INIT,
        Cheque,
        CslsCheque,
        FraudProof,
        ProcessResult,
    )


class CausalAgentWallet:
    """
    Sovereign AI Agent Wallet for ultra-fast, zero-gas micro-payments.
    Maintains an O(1) multi-channel table isolating state per peer_pk
    to guarantee strictly monotonic per-vendor height counters and cumulative amounts.
    Allocated directly on the C11 heap via csls_agent_new / csls_agent_free.
    """
    def __init__(
        self,
        secret_key: Optional[Union[str, bytes]] = None,
        wal_path: Optional[str] = None,
        agent_private_key: Optional[Union[str, bytes]] = None,
    ):
        self._lock = threading.RLock()
        self._closed = False
        if secret_key is None and agent_private_key is not None:
            secret_key = agent_private_key
        if secret_key is None:
            self._sk_bytes = os.urandom(32)
        else:
            self._sk_bytes = _parse_bytes(secret_key, 32)

        self._wal_path = wal_path
        if _IS_NATIVE:
            sk_arr = (ctypes.c_uint8 * 32)(*self._sk_bytes)
            wal_c = wal_path.encode() if wal_path else None
            raw_ctx = _LIB.csls_agent_new(sk_arr, wal_c)
            if not raw_ctx:
                raise RuntimeError("csls_agent_new returned NULL: allocation failed")
            self._ctx = _AgentCtxHandle(raw_ctx)
        else:
            pk = derive_public_key(self._sk_bytes, compressed=True)
            self._ctx = _PyAgentCtx(self._sk_bytes, pk)
        self._master_ctx = self._ctx

    @property
    def public_key(self) -> bytes:
        return bytes(self._ctx.pk)

    @property
    def public_key_hex(self) -> str:
        return "0x" + self.public_key.hex()

    @property
    def height(self) -> int:
        with self._lock:
            return self._ctx.height

    @property
    def total_sent_usdc(self) -> float:
        with self._lock:
            return self._ctx.cumulative_sent / 1e6

    def get_channel_height(self, vendor_pk: Union[str, bytes]) -> int:
        v_bytes = _parse_bytes(vendor_pk, 33)
        with self._lock:
            if _IS_NATIVE and isinstance(self._ctx, _AgentCtxHandle):
                v_arr = (ctypes.c_uint8 * 33)(*v_bytes)
                h = ctypes.c_uint64(0)
                cum = ctypes.c_uint64(0)
                rc = _LIB.csls_agent_get_channel_state(self._ctx, v_arr, ctypes.byref(h), ctypes.byref(cum))
                if rc == 0:
                    return h.value
                return 0
            else:
                return self._ctx.channels.get(v_bytes, (0, 0))[0]

    def get_channel_cumulative(self, vendor_pk: Union[str, bytes]) -> int:
        v_bytes = _parse_bytes(vendor_pk, 33)
        with self._lock:
            if _IS_NATIVE and isinstance(self._ctx, _AgentCtxHandle):
                v_arr = (ctypes.c_uint8 * 33)(*v_bytes)
                h = ctypes.c_uint64(0)
                cum = ctypes.c_uint64(0)
                rc = _LIB.csls_agent_get_channel_state(self._ctx, v_arr, ctypes.byref(h), ctypes.byref(cum))
                if rc == 0:
                    return cum.value
                return 0
            else:
                return self._ctx.channels.get(v_bytes, (0, 0))[1]

    def create_session(self, vendor_pk: Union[str, bytes]) -> bytes:
        """
        Begins a Session MAC handshake with a vendor.
        Returns a 95-byte session_init packet containing ECDH authentication tag.
        """
        v_bytes = _parse_bytes(vendor_pk, 33)
        with self._lock:
            if _IS_NATIVE and isinstance(self._ctx, _AgentCtxHandle):
                v_arr = (ctypes.c_uint8 * 33)(*v_bytes)
                init_pkt = _CslsSessionInitPkt()
                rc = _LIB.csls_agent_session_begin(self._ctx, v_arr, ctypes.byref(init_pkt))
                if rc != 0:
                    raise RuntimeError(f"csls_agent_session_begin failed with code {rc}")
                return bytes(init_pkt)
            else:
                ecdh_x_coord = _ecdh_x(self._sk_bytes, v_bytes)
                nonce = int.from_bytes(os.urandom(8), "big")
                auth_mac = _session_auth(ecdh_x_coord, self.public_key, v_bytes, nonce)
                key = _session_kdf(ecdh_x_coord, nonce)
                self._ctx.sessions[v_bytes] = key
                init_pkt = _CslsSessionInitPkt()
                init_pkt.magic = CSLS_MAGIC
                init_pkt.type = CSLS_PKT_SESSION_INIT
                for i in range(33):
                    init_pkt.agent_pk[i] = self.public_key[i]
                    init_pkt.vendor_pk[i] = v_bytes[i]
                init_pkt.session_nonce = nonce
                for i in range(16):
                    init_pkt.auth_mac[i] = auth_mac[i]
                return bytes(init_pkt)

    def open_secure_session(self, vendor_node: "CausalVendorNode") -> bool:
        """
        Establishes an authenticated Session MAC channel with a locally running
        vendor node (C2 gate). Wire cheques omit the Schnorr point R, so vendors
        that mandate Session MAC (the secure default) reject every cheque from a
        channel that has not completed this handshake. Returns True on success.
        """
        return vendor_node.init_session(self.create_session(vendor_node.public_key))

    def sign_cheque(self, vendor_pk: Union[str, bytes], amount_usdc: float, session_mac: bool = False) -> Cheque:
        """
        Signs a micro-payment cheque for `amount_usdc` isolated to vendor_pk channel.
        Tracks per-vendor sequence numbers and cumulative amounts via csls_channel_table_t.
        If session_mac=True, produces a 167-byte wire packet with 16-byte SipHash-2-4 MAC tag.
        Execution takes ~3-5 microseconds in native C.
        """
        if not isinstance(amount_usdc, (int, float)):
            raise TypeError(f"amount_usdc must be numeric, got {type(amount_usdc).__name__}")
        if math.isnan(amount_usdc) or math.isinf(amount_usdc):
            raise ValueError(f"amount_usdc must be finite, got {amount_usdc}")
        if amount_usdc <= 0:
            raise ValueError(f"amount_usdc must be strictly positive, got {amount_usdc}")

        v_bytes = _parse_bytes(vendor_pk, 33)
        delta_micro = int(round(amount_usdc * 1e6))
        if delta_micro > 0xFFFFFFFFFFFFFFFF:
            raise OverflowError("amount_usdc exceeds uint64_t micro-USDC range")

        with self._lock:
            if _IS_NATIVE and isinstance(self._ctx, _AgentCtxHandle):
                v_arr = (ctypes.c_uint8 * 33)(*v_bytes)
                c_pkt = _CslsChequePkt()
                if session_mac:
                    mac_arr = (ctypes.c_uint8 * 16)()
                    res = _LIB.csls_agent_sign_cheque_mac(
                        self._ctx, v_arr, delta_micro, ctypes.byref(c_pkt), mac_arr
                    )
                    if res != 0:
                        raise RuntimeError(f"csls_agent_sign_cheque_mac failed with code {res}")
                    return Cheque.from_c_pkt(c_pkt, mac=bytes(mac_arr))
                else:
                    res = _LIB.csls_agent_sign_cheque(
                        self._ctx, v_arr, delta_micro, ctypes.byref(c_pkt)
                    )
                    if res != 0:
                        raise RuntimeError(f"csls_agent_sign_cheque failed with code {res}")
                    return Cheque.from_c_pkt(c_pkt)
            else:
                if session_mac and v_bytes not in self._ctx.sessions:
                    raise RuntimeError(f"csls_agent_sign_cheque_mac failed with code {CSLS_ERR_NO_SESSION}")
                h = self._ctx.height
                self._ctx.height += 1
                prev_h, prev_cum = self._ctx.channels.get(v_bytes, (0, 0))
                cum_amt = prev_cum + delta_micro
                self._ctx.channels[v_bytes] = (h, cum_amt)
                self._ctx.cumulative_sent += delta_micro

                k = _derive_k(self._sk_bytes, v_bytes, h)
                preimage = self.public_key + v_bytes + h.to_bytes(8, "big") + cum_amt.to_bytes(8, "big")
                e_bytes = hashlib.sha256(preimage).digest()
                e = int.from_bytes(e_bytes, "big") % SECP256K1_Q
                sk_int = int.from_bytes(self._sk_bytes, "big")
                s = (k + e * sk_int) % SECP256K1_Q

                c_pkt = _CslsChequePkt()
                c_pkt.magic = CSLS_MAGIC
                c_pkt.type = CSLS_PKT_CHEQUE
                for i in range(33):
                    c_pkt.agent_pk[i] = self.public_key[i]
                    c_pkt.vendor_pk[i] = v_bytes[i]
                c_pkt.height = h
                c_pkt.cumulative_amt = cum_amt
                challenge_e_bytes = e.to_bytes(32, "big")
                sig_s_bytes = s.to_bytes(32, "big")
                for i in range(32):
                    c_pkt.challenge_e[i] = challenge_e_bytes[i]
                    c_pkt.sig_s[i] = sig_s_bytes[i]

                if session_mac:
                    skey = self._ctx.sessions[v_bytes]
                    mac_tag = _mac128(skey[:16], bytes(c_pkt))
                    return Cheque.from_c_pkt(c_pkt, mac=mac_tag)
                else:
                    return Cheque.from_c_pkt(c_pkt)

    def session(
        self,
        vendor_pk: Union[str, bytes],
        budget_usdc: float = 10.0,
        price_per_call: float = 0.0005,
        subagent_session: Optional[Any] = None,
        mesh: Optional[Any] = None,
        session_mac: bool = False,
    ):
        """Creates a Pythonic synchronous context manager for streaming micropayments."""
        try:
            from .session import CausalSession
        except (ImportError, ValueError):
            from session import CausalSession
        return CausalSession(
            wallet=self,
            vendor_pk=vendor_pk,
            budget_usdc=budget_usdc,
            price_per_call=price_per_call,
            subagent_session=subagent_session,
            mesh=mesh,
            session_mac=session_mac,
        )

    def async_session(
        self,
        vendor_pk: Union[str, bytes],
        budget_usdc: float = 10.0,
        price_per_call: float = 0.0005,
        subagent_session: Optional[Any] = None,
        mesh: Optional[Any] = None,
        session_mac: bool = False,
    ):
        """Creates a Pythonic asynchronous context manager for streaming micropayments."""
        try:
            from .session import AsyncCausalSession
        except (ImportError, ValueError):
            from session import AsyncCausalSession
        return AsyncCausalSession(
            wallet=self,
            vendor_pk=vendor_pk,
            budget_usdc=budget_usdc,
            price_per_call=price_per_call,
            subagent_session=subagent_session,
            mesh=mesh,
            session_mac=session_mac,
        )

    def __enter__(self) -> CausalAgentWallet:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def close(self):
        with self._lock:
            if not getattr(self, "_closed", False):
                self._closed = True
                if hasattr(self, "_ctx") and self._ctx:
                    if _IS_NATIVE and isinstance(self._ctx, _AgentCtxHandle) and self._ctx.value:
                        _LIB.csls_agent_free(self._ctx)
                        self._ctx = _AgentCtxHandle(None)

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


class CausalVendorNode:
    """
    Sovereign Vendor Node for microsecond cheque verification and equivocation trapping.
    Maintains an O(1) multi-channel table isolating state per agent_pk,
    guaranteeing independent credit exposure limits (delta_v) and monotonic sequence tracking.
    Allocated directly on the C11 heap via csls_vendor_new / csls_vendor_free.
    """
    def __init__(
        self,
        secret_key: Optional[Union[str, bytes]] = None,
        delta_v_usdc: float = 1.0,
        max_channels: int = 65536,
        enforce_mac: bool = True,
    ):
        if not isinstance(delta_v_usdc, (int, float)):
            raise TypeError(f"delta_v_usdc must be numeric, got {type(delta_v_usdc).__name__}")
        if math.isnan(delta_v_usdc) or math.isinf(delta_v_usdc):
            raise ValueError(f"delta_v_usdc must be finite, got {delta_v_usdc}")
        if delta_v_usdc <= 0:
            raise ValueError(f"delta_v_usdc must be strictly positive, got {delta_v_usdc}")

        self._lock = threading.RLock()
        self._closed = False
        self._max_channels = max_channels
        self._enforce_mac = enforce_mac
        if secret_key is None:
            self._sk_bytes = os.urandom(32)
        else:
            self._sk_bytes = _parse_bytes(secret_key, 32)

        self._delta_v_micro = int(round(delta_v_usdc * 1e6))
        if _IS_NATIVE:
            sk_arr = (ctypes.c_uint8 * 32)(*self._sk_bytes)
            raw_ctx = _LIB.csls_vendor_new(sk_arr, self._delta_v_micro)
            if not raw_ctx:
                raise RuntimeError("csls_vendor_new returned NULL: allocation failed")
            self._ctx = _VendorCtxHandle(raw_ctx)
            _LIB.csls_vendor_enable_mac(self._ctx, 1 if enforce_mac else 0)
        else:
            pk = derive_public_key(self._sk_bytes, compressed=True)
            self._ctx = _PyVendorCtx(self._sk_bytes, pk, self._delta_v_micro)
            self._ctx.enforce_mac = 1 if enforce_mac else 0
        self._master_ctx = self._ctx
        self._channel_accumulated: Dict[bytes, int] = {}

    @property
    def public_key(self) -> bytes:
        return bytes(self._ctx.pk)

    @property
    def public_key_hex(self) -> str:
        return "0x" + self.public_key.hex()

    @property
    def accumulated_usdc(self) -> float:
        with self._lock:
            if not self._channel_accumulated:
                return self._ctx.accumulated_amount / 1e6
            return sum(self._channel_accumulated.values()) / 1e6

    @property
    def cleared_usdc(self) -> float:
        with self._lock:
            return self._ctx.cleared_amount / 1e6

    @property
    def last_height(self) -> int:
        with self._lock:
            return self._ctx.last_height

    def enable_mac(self, enable: bool = True) -> None:
        """Enables or disables mandatory Session MAC enforcement (C2 gate)."""
        with self._lock:
            self._enforce_mac = enable
            if _IS_NATIVE and isinstance(self._ctx, _VendorCtxHandle):
                rc = _LIB.csls_vendor_enable_mac(self._ctx, 1 if enable else 0)
                if rc != 0:
                    raise RuntimeError(f"csls_vendor_enable_mac failed with code {rc}")
            else:
                self._ctx.enforce_mac = 1 if enable else 0

    def init_session(self, session_init_pkt: Union[bytes, _CslsSessionInitPkt]) -> bool:
        """
        Initializes an authenticated Session MAC session with an agent from a 95-byte session_init packet.
        """
        if isinstance(session_init_pkt, bytes):
            if len(session_init_pkt) != ctypes.sizeof(_CslsSessionInitPkt):
                raise ValueError(f"Expected {ctypes.sizeof(_CslsSessionInitPkt)} bytes, got {len(session_init_pkt)}")
            c_init = _CslsSessionInitPkt.from_buffer_copy(session_init_pkt)
        else:
            c_init = session_init_pkt

        with self._lock:
            if _IS_NATIVE and isinstance(self._ctx, _VendorCtxHandle):
                rc = _LIB.csls_vendor_session_init(self._ctx, ctypes.byref(c_init))
                return rc == 0
            else:
                agent_pk = bytes(c_init.agent_pk)
                vendor_pk = bytes(c_init.vendor_pk)
                if vendor_pk != self.public_key:
                    return False
                ecdh_x_coord = _ecdh_x(self._sk_bytes, agent_pk)
                nonce = c_init.session_nonce
                expected_auth = _session_auth(ecdh_x_coord, agent_pk, vendor_pk, nonce)
                if bytes(c_init.auth_mac) != expected_auth:
                    return False
                key = _session_kdf(ecdh_x_coord, nonce)
                self._ctx.sessions[agent_pk] = key
                return True

    def get_channel_accumulated(self, agent_pk: Union[str, bytes]) -> int:
        a_bytes = _parse_bytes(agent_pk, 33)
        with self._lock:
            if a_bytes in self._channel_accumulated:
                return self._channel_accumulated[a_bytes]
            if _IS_NATIVE and isinstance(self._ctx, _VendorCtxHandle):
                a_arr = (ctypes.c_uint8 * 33)(*a_bytes)
                h = ctypes.c_uint64(0)
                accum = ctypes.c_uint64(0)
                cleared = ctypes.c_uint64(0)
                rc = _LIB.csls_vendor_get_channel_state(self._ctx, a_arr, ctypes.byref(h), ctypes.byref(accum), ctypes.byref(cleared))
                if rc == 0:
                    return accum.value
                return 0
            else:
                return self._ctx.channels.get(a_bytes, (0, 0, 0))[1]

    def get_channel_height(self, agent_pk: Union[str, bytes]) -> int:
        a_bytes = _parse_bytes(agent_pk, 33)
        with self._lock:
            if _IS_NATIVE and isinstance(self._ctx, _VendorCtxHandle):
                a_arr = (ctypes.c_uint8 * 33)(*a_bytes)
                h = ctypes.c_uint64(0)
                accum = ctypes.c_uint64(0)
                cleared = ctypes.c_uint64(0)
                rc = _LIB.csls_vendor_get_channel_state(self._ctx, a_arr, ctypes.byref(h), ctypes.byref(accum), ctypes.byref(cleared))
                if rc == 0:
                    return h.value
                return 0
            else:
                return self._ctx.channels.get(a_bytes, (0, 0, 0))[0]

    def get_channel_cleared(self, agent_pk: Union[str, bytes]) -> int:
        a_bytes = _parse_bytes(agent_pk, 33)
        with self._lock:
            if _IS_NATIVE and isinstance(self._ctx, _VendorCtxHandle):
                a_arr = (ctypes.c_uint8 * 33)(*a_bytes)
                h = ctypes.c_uint64(0)
                accum = ctypes.c_uint64(0)
                cleared = ctypes.c_uint64(0)
                rc = _LIB.csls_vendor_get_channel_state(self._ctx, a_arr, ctypes.byref(h), ctypes.byref(accum), ctypes.byref(cleared))
                if rc == 0:
                    return cleared.value
                return 0
            else:
                return self._ctx.channels.get(a_bytes, (0, 0, 0))[2]

    def advance_cleared(self, agent_pk: Optional[Union[str, bytes]] = None, cleared_usdc: float = 0.0) -> None:
        """Advances cleared_amount for an agent or globally, freeing the delta_v exposure buffer."""
        if not isinstance(cleared_usdc, (int, float)):
            raise TypeError(f"cleared_usdc must be numeric, got {type(cleared_usdc).__name__}")
        if math.isnan(cleared_usdc) or math.isinf(cleared_usdc) or cleared_usdc < 0:
            raise ValueError(f"cleared_usdc must be non-negative and finite, got {cleared_usdc}")
        cleared_micro = int(round(cleared_usdc * 1e6))
        with self._lock:
            if self._closed:
                raise RuntimeError("Vendor node is closed")
            if _IS_NATIVE and isinstance(self._ctx, _VendorCtxHandle):
                if agent_pk is not None:
                    a_bytes = _parse_bytes(agent_pk, 33)
                    a_arr = (ctypes.c_uint8 * 33)(*a_bytes)
                    res = _LIB.csls_vendor_advance_cleared(self._ctx, a_arr, cleared_micro)
                else:
                    res = _LIB.csls_vendor_advance_cleared(self._ctx, None, cleared_micro)
                if res != 0:
                    raise RuntimeError(f"csls_vendor_advance_cleared failed with code {res}")
            else:
                if agent_pk is not None:
                    a_bytes = _parse_bytes(agent_pk, 33)
                    h, accum, prev_cleared = self._ctx.channels.get(a_bytes, (0, 0, 0))
                    self._ctx.channels[a_bytes] = (h, accum, prev_cleared + cleared_micro)
                else:
                    self._ctx.cleared_amount += cleared_micro

    def process_cheque(self, cheque: Union[Cheque, bytes]) -> ProcessResult:
        """
        Processes an incoming streaming micro-cheque using isolated per-agent channel context.
        Validates protocol framing, monotonic height progression, and enforces local credit
        exposure buffer (delta_v USDC) per agent channel.
        Supports both 151-byte legacy packets and 167-byte Session MAC packets.
        """
        if isinstance(cheque, Cheque):
            raw = cheque.raw_packet
        else:
            raw = cheque

        pkt_len = len(raw)
        expected_plain = ctypes.sizeof(_CslsChequePkt)
        expected_mac = expected_plain + 16

        if pkt_len != expected_plain and pkt_len != expected_mac:
            return ProcessResult(
                status_code=-1,
                accepted=False,
                accumulated_usdc=self.accumulated_usdc,
                error_message=f"Invalid packet size: expected {expected_plain} or {expected_mac} bytes, got {pkt_len}",
            )

        c_pkt = _CslsChequePkt.from_buffer_copy(raw[:expected_plain])
        c_fraud = _CslsFraudPkt()
        agent_pk = bytes(c_pkt.agent_pk)

        with self._lock:
            if agent_pk not in self._channel_accumulated:
                if len(self._channel_accumulated) >= self._max_channels:
                    return ProcessResult(
                        status_code=-10,
                        accepted=False,
                        accumulated_usdc=self.accumulated_usdc,
                        error_message="MAX_CHANNELS_CAPACITY_REACHED: Vendor channel table full",
                    )

            if _IS_NATIVE and isinstance(self._ctx, _VendorCtxHandle):
                if pkt_len == expected_mac:
                    mac_bytes = raw[expected_plain:expected_mac]
                    mac_arr = (ctypes.c_uint8 * 16)(*mac_bytes)
                    res = _LIB.csls_vendor_process_cheque_mac(
                        self._ctx, ctypes.byref(c_pkt), mac_arr, ctypes.byref(c_fraud)
                    )
                else:
                    res = _LIB.csls_vendor_process_cheque(
                        self._ctx, ctypes.byref(c_pkt), ctypes.byref(c_fraud)
                    )
            else:
                if self._ctx.enforce_mac:
                    if pkt_len != expected_mac or agent_pk not in self._ctx.sessions:
                        res = CSLS_ERR_BAD_MAC
                    else:
                        skey = self._ctx.sessions[agent_pk]
                        tag = _mac128(skey[:16], raw[:expected_plain])
                        if raw[expected_plain:expected_mac] != tag:
                            res = CSLS_ERR_BAD_MAC
                        else:
                            res = None
                else:
                    res = None

                if res is None:
                    hist_key = (agent_pk, c_pkt.height)
                    if hist_key in self._ctx.history:
                        prev_amt, prev_e, prev_s = self._ctx.history[hist_key]
                        if prev_e != bytes(c_pkt.challenge_e):
                            if hist_key in self._ctx.disputed:
                                res = CSLS_ERR_FRAUD
                            else:
                                self._ctx.disputed.add(hist_key)
                                s1 = int.from_bytes(prev_s, "big")
                                s2 = int.from_bytes(bytes(c_pkt.sig_s), "big")
                                e1 = int.from_bytes(prev_e, "big")
                                e2 = int.from_bytes(bytes(c_pkt.challenge_e), "big")
                                delta_s = (s1 - s2) % SECP256K1_Q
                                delta_e = (e1 - e2) % SECP256K1_Q
                                inv_delta_e = pow(delta_e, -1, SECP256K1_Q)
                                extracted_sk = ((delta_s * inv_delta_e) % SECP256K1_Q).to_bytes(32, "big")

                                c_fraud.magic = CSLS_MAGIC
                                c_fraud.type = CSLS_PKT_FRAUD
                                for i in range(33):
                                    c_fraud.offender_pk[i] = agent_pk[i]
                                c_fraud.collision_h = c_pkt.height
                                for i in range(32):
                                    c_fraud.extracted_sk[i] = extracted_sk[i]
                                res = CSLS_ERR_FRAUD
                        else:
                            res = CSLS_ERR_REPLAY
                    else:
                        last_h, accumulated, cleared = self._ctx.channels.get(agent_pk, (0, 0, 0))
                        if c_pkt.cumulative_amt < accumulated:
                            res = -11
                        else:
                            unconfirmed = c_pkt.cumulative_amt - cleared if c_pkt.cumulative_amt >= cleared else 0
                            if unconfirmed > self._ctx.max_exposure_delta_v:
                                res = CSLS_ERR_EXPOSURE_CAP
                            elif last_h > 0 and c_pkt.height <= last_h:
                                res = CSLS_ERR_OUT_OF_ORDER
                            else:
                                preimage = agent_pk + bytes(c_pkt.vendor_pk) + c_pkt.height.to_bytes(8, "big") + c_pkt.cumulative_amt.to_bytes(8, "big")
                                expected_e = (int.from_bytes(hashlib.sha256(preimage).digest(), "big") % SECP256K1_Q).to_bytes(32, "big")
                                if expected_e != bytes(c_pkt.challenge_e):
                                    res = CSLS_ERR_FORGED_HASH
                                else:
                                    self._ctx.history[hist_key] = (c_pkt.cumulative_amt, bytes(c_pkt.challenge_e), bytes(c_pkt.sig_s))
                                    self._ctx.channels[agent_pk] = (c_pkt.height, c_pkt.cumulative_amt, cleared)
                                    self._ctx.last_height = c_pkt.height
                                    res = CSLS_OK

            if res == CSLS_OK:
                self._channel_accumulated[agent_pk] = c_pkt.cumulative_amt
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
                CSLS_ERR_BAD_MAC: "INVALID_OR_MISSING_SESSION_MAC",
                CSLS_ERR_NO_SESSION: "NO_ACTIVE_MAC_SESSION",
                CSLS_ERR_WAL_FATAL: "WAL_CORRUPT_FAIL_CLOSED",
                -11: "DECREASING_AMOUNT_ATTACK",
            }
            msg = error_map.get(res, f"UNKNOWN_ERROR_{res}")
            return ProcessResult(
                status_code=res,
                accepted=False,
                accumulated_usdc=self.accumulated_usdc,
                error_message=msg,
            )

    def __enter__(self) -> CausalVendorNode:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def close(self):
        with self._lock:
            if not getattr(self, "_closed", False):
                self._closed = True
                if hasattr(self, "_ctx") and self._ctx:
                    if _IS_NATIVE and isinstance(self._ctx, _VendorCtxHandle) and self._ctx.value:
                        _LIB.csls_vendor_free(self._ctx)
                        self._ctx = _VendorCtxHandle(None)

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


# -----------------------------------------------------------------------------
# DebtCycleMesh: High-Frequency In-Memory Debt Clearing & Kirchhoff Cycle Reduction
# -----------------------------------------------------------------------------

@dataclass
class CycleEliminationRecord:
    cycle: List[bytes]
    bottleneck_amount_micro_usdc: int
    cycle_length: int
    cleared_volume_micro_usdc: int
    timestamp: float


@dataclass
class NettingSummary:
    gross_obligations_count: int
    gross_volume_micro_usdc: int
    net_obligations_count: int
    net_volume_micro_usdc: int
    cycles_eliminated_count: int
    total_cleared_micro_usdc: int
    volume_compression_ratio: float
    tx_compression_ratio: float


class DebtCycleMesh:
    """
    In-memory high-frequency debt mesh and P2P cycle clearing engine.
    Implements Kirchhoff Cycle Elimination for autonomous agent swarms,
    canceling closed loops of reciprocal micro-debts in RAM with thread-safe concurrency.

    Mathematical Invariants Enforced:
    1. Conservation of Net Balance: b'(u) == b(u) for all agents u in V (Theorem 2).
    2. Strict Monotonic Debt Reduction: W(T(G)) = W(G) - k * Delta_C (Theorem 3).
    3. Compression: >= 99% reduction of on-chain settlement transactions and volume
       on high-density cyclical workloads.
    """

    def __init__(self, auto_bilateral_netting: bool = True):
        self._lock = threading.RLock()
        self._auto_bilateral = auto_bilateral_netting
        self._adj: Dict[bytes, Dict[bytes, int]] = {}
        self._nodes: Set[bytes] = set()
        self._channel_cumulative: Dict[Tuple[bytes, bytes], int] = {}
        self._gross_tx_count: int = 0
        self._gross_volume: int = 0
        self._total_cleared: int = 0
        self._cycles_eliminated: int = 0
        self._history: Deque[CycleEliminationRecord] = deque(maxlen=10000)

    @staticmethod
    def _to_bytes(val: Union[bytes, str]) -> bytes:
        if isinstance(val, bytes):
            return val
        if isinstance(val, str):
            if val.startswith("0x") or val.startswith("0X"):
                return bytes.fromhex(val[2:])
            try:
                return bytes.fromhex(val)
            except ValueError:
                return val.encode("utf-8")
        return bytes(val)

    def add_obligation(
        self,
        debtor: Union[bytes, str],
        creditor: Union[bytes, str],
        amount_micro_usdc: int,
    ) -> int:
        """
        Records a micro-debt obligation where debtor owes creditor amount_micro_usdc.
        Thread-safe. Performs immediate bilateral netting if enabled.
        Returns the resulting net edge weight (debtor -> creditor).
        """
        if amount_micro_usdc <= 0:
            raise ValueError(f"Obligation amount must be positive, got {amount_micro_usdc}")

        u = self._to_bytes(debtor)
        v = self._to_bytes(creditor)
        if u == v:
            raise ValueError("Self-obligation not permitted (debtor == creditor)")

        with self._lock:
            self._nodes.add(u)
            self._nodes.add(v)
            self._gross_tx_count += 1
            self._gross_volume += amount_micro_usdc

            if self._auto_bilateral:
                reverse_debt = self._adj.get(v, {}).get(u, 0)
                if reverse_debt > 0:
                    if reverse_debt >= amount_micro_usdc:
                        new_reverse = reverse_debt - amount_micro_usdc
                        if new_reverse == 0:
                            del self._adj[v][u]
                            if not self._adj[v]:
                                del self._adj[v]
                        else:
                            self._adj[v][u] = new_reverse
                        cleared = amount_micro_usdc * 2
                        self._total_cleared += cleared
                        return 0
                    else:
                        cleared = reverse_debt * 2
                        self._total_cleared += cleared
                        del self._adj[v][u]
                        if not self._adj[v]:
                            del self._adj[v]
                        remaining = amount_micro_usdc - reverse_debt
                        existing = self._adj.get(u, {}).get(v, 0)
                        total_uv = existing + remaining
                        if u not in self._adj:
                            self._adj[u] = {}
                        self._adj[u][v] = total_uv
                        return total_uv

            if u not in self._adj:
                self._adj[u] = {}
            total = self._adj[u].get(v, 0) + amount_micro_usdc
            self._adj[u][v] = total
            return total

    def record_cheque(self, cheque: CslsCheque) -> int:
        """
        Ingests a CslsCheque from an active L4 streaming channel.
        Extracts incremental micro-debt from the monotonic cumulative amount and updates the mesh.
        """
        with self._lock:
            u = bytes(cheque.agent_pk)
            v = bytes(cheque.vendor_pk)
            pair = (u, v)
            prev_amt = self._channel_cumulative.get(pair, 0)
            curr_amt = cheque.cumulative_amt
            if curr_amt < prev_amt:
                raise ValueError(
                    f"Cheque cumulative amount {curr_amt} < previous {prev_amt}"
                )
            delta = curr_amt - prev_amt
            if delta == 0:
                return 0
            self._channel_cumulative[pair] = curr_amt
            return self.add_obligation(u, v, delta)

    def get_net_balance(self, agent: Union[bytes, str]) -> int:
        """
        Computes divergence balance b(u) = sum(w(in)) - sum(w(out)).
        Positive: net creditor. Negative: net debtor.
        """
        u = self._to_bytes(agent)
        with self._lock:
            in_flow = 0
            out_flow = 0
            for creditor, amount in self._adj.get(u, {}).items():
                out_flow += amount
            for debtor, targets in self._adj.items():
                if u in targets:
                    in_flow += targets[u]
            return in_flow - out_flow

    def get_all_net_balances(self) -> Dict[bytes, int]:
        """
        Returns net divergence balances b(u) for all nodes in the mesh.
        Enforces Kirchhoff Flow Invariant: sum(b(u)) == 0.
        """
        with self._lock:
            balances: Dict[bytes, int] = {node: 0 for node in self._nodes}
            for u, targets in self._adj.items():
                for v, amt in targets.items():
                    balances[u] -= amt
                    balances[v] += amt
            total_div = sum(balances.values())
            if total_div != 0:
                raise RuntimeError(
                    f"Kirchhoff invariant violation: sum(b) = {total_div} != 0"
                )
            return balances

    def find_tarjan_cycle(self) -> Optional[List[bytes]]:
        """
        Tarjan-based directed cycle detection using on-stack back-edge identification.
        Returns a simple directed cycle [v0, v1, ..., vk, v0] or None if acyclic.
        """
        with self._lock:
            visited: Set[bytes] = set()
            on_stack: Set[bytes] = set()
            parent: Dict[bytes, bytes] = {}

            for start_node in list(self._adj.keys()):
                if start_node in visited:
                    continue

                call_stack = [(start_node, iter(list(self._adj.get(start_node, {}).keys())))]
                visited.add(start_node)
                on_stack.add(start_node)

                while call_stack:
                    u, neighbors = call_stack[-1]
                    try:
                        v = next(neighbors)
                        if self._adj.get(u, {}).get(v, 0) <= 0:
                            continue

                        if v in on_stack:
                            cycle = [v]
                            curr = u
                            while curr != v:
                                cycle.append(curr)
                                curr = parent.get(curr, v)
                            cycle.append(v)
                            cycle.reverse()
                            return cycle

                        if v not in visited:
                            visited.add(v)
                            on_stack.add(v)
                            parent[v] = u
                            call_stack.append((v, iter(list(self._adj.get(v, {}).keys()))))
                    except StopIteration:
                        on_stack.discard(u)
                        call_stack.pop()

            return None

    def find_cycle(self) -> Optional[List[bytes]]:
        """Finds a directed cycle using Tarjan back-edge search under self._lock."""
        return self.find_tarjan_cycle()

    def reduce_kirchhoff_cycles(
        self, max_cycles: Optional[int] = None
    ) -> Tuple[int, int]:
        """
        Executes iterative Kirchhoff Cycle Elimination.
        Returns (cycles_eliminated_count, total_micro_usdc_cleared).
        """
        with self._lock:
            eliminated_count = 0
            cleared_volume = 0

            while max_cycles is None or eliminated_count < max_cycles:
                cycle = self.find_cycle()
                if not cycle:
                    break

                k = len(cycle) - 1
                if k < 2:
                    break

                bottleneck = min(
                    self._adj[cycle[i]][cycle[i + 1]] for i in range(k)
                )

                if bottleneck <= 0:
                    break

                for i in range(k):
                    u = cycle[i]
                    v = cycle[i + 1]
                    new_weight = self._adj[u][v] - bottleneck
                    if new_weight <= 0:
                        del self._adj[u][v]
                        if not self._adj[u]:
                            del self._adj[u]
                    else:
                        self._adj[u][v] = new_weight

                cycle_cleared = k * bottleneck
                cleared_volume += cycle_cleared
                self._total_cleared += cycle_cleared
                eliminated_count += 1
                self._cycles_eliminated += 1

                self._history.append(
                    CycleEliminationRecord(
                        cycle=cycle,
                        bottleneck_amount_micro_usdc=bottleneck,
                        cycle_length=k,
                        cleared_volume_micro_usdc=cycle_cleared,
                        timestamp=time.time(),
                    )
                )

            return eliminated_count, cleared_volume

    def get_summary(self) -> NettingSummary:
        """Returns summary statistics for the debt mesh including compression ratios."""
        with self._lock:
            net_tx_count = sum(len(targets) for targets in self._adj.values())
            net_volume = sum(
                sum(targets.values()) for targets in self._adj.values()
            )

            gross_vol = self._gross_volume
            gross_tx = self._gross_tx_count

            vol_compression = (
                1.0 - (net_volume / gross_vol) if gross_vol > 0 else 1.0
            )
            tx_compression = (
                1.0 - (net_tx_count / gross_tx) if gross_tx > 0 else 1.0
            )

            return NettingSummary(
                gross_obligations_count=gross_tx,
                gross_volume_micro_usdc=gross_vol,
                net_obligations_count=net_tx_count,
                net_volume_micro_usdc=net_volume,
                cycles_eliminated_count=self._cycles_eliminated,
                total_cleared_micro_usdc=self._total_cleared,
                volume_compression_ratio=max(0.0, vol_compression),
                tx_compression_ratio=max(0.0, tx_compression),
            )

    def generate_clearing_settlements(self) -> List[Tuple[bytes, bytes, int]]:
        """
        Generates minimal on-chain settlement transfers pairing net debtors with net creditors.
        Reduces N nodes to at most N - 1 settlement transactions.
        """
        with self._lock:
            balances = self.get_all_net_balances()
            debtors: List[List[Union[bytes, int]]] = [
                [node, -amt] for node, amt in balances.items() if amt < 0
            ]
            creditors: List[List[Union[bytes, int]]] = [
                [node, amt] for node, amt in balances.items() if amt > 0
            ]

            debtors.sort(key=lambda x: int(x[1]), reverse=True)
            creditors.sort(key=lambda x: int(x[1]), reverse=True)

            settlements: List[Tuple[bytes, bytes, int]] = []
            d_idx = 0
            c_idx = 0

            while d_idx < len(debtors) and c_idx < len(creditors):
                debtor_node, d_amount = debtors[d_idx]
                creditor_node, c_amount = creditors[c_idx]
                transfer = min(int(d_amount), int(c_amount))
                if transfer > 0:
                    settlements.append((bytes(debtor_node), bytes(creditor_node), transfer))
                    debtors[d_idx][1] = int(d_amount) - transfer
                    creditors[c_idx][1] = int(c_amount) - transfer

                if debtors[d_idx][1] == 0:
                    d_idx += 1
                if creditors[c_idx][1] == 0:
                    c_idx += 1

            return settlements

    @property
    def is_dag(self) -> bool:
        """Returns True if the current debt graph is acyclic (DAG)."""
        return self.find_cycle() is None

    @property
    def total_system_debt(self) -> int:
        """Returns current total outstanding debt W(G) = sum(w(u, v))."""
        with self._lock:
            return sum(sum(targets.values()) for targets in self._adj.values())

    @property
    def active_edges_count(self) -> int:
        """Returns number of active directed debt edges."""
        with self._lock:
            return sum(len(targets) for targets in self._adj.values())

    @property
    def active_nodes_count(self) -> int:
        """Returns number of unique active nodes."""
        with self._lock:
            return len(self._nodes)

    def clear(self) -> None:
        """Clears all mesh state."""
        with self._lock:
            self._adj.clear()
            self._nodes.clear()
            self._channel_cumulative.clear()
            self._gross_tx_count = 0
            self._gross_volume = 0
            self._total_cleared = 0
            self._cycles_eliminated = 0
            self._history.clear()


__all__ = [
    "CausalAgentWallet",
    "CausalVendorNode",
    "CycleEliminationRecord",
    "NettingSummary",
    "DebtCycleMesh",
]
