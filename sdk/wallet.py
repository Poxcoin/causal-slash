# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Causal-Slash Protocol: Sovereign Agent Wallet & P2P Debt Clearing (sdk/wallet.py)
Provides:
- CausalAgentWallet: Sovereign AI Agent Wallet for zero-gas streaming micro-payments (send & receive).
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
    Maintains O(1) multi-channel state isolating per-peer credit exposure and monotonic sequences.
    Supports both outgoing payment signing (as payer) and incoming cheque verification (as payee).
    Allocated directly on the C11 heap via csls_agent_new / csls_vendor_new.
    """
    def __init__(
        self,
        secret_key: Optional[Union[str, bytes]] = None,
        wal_path: Optional[str] = None,
        agent_private_key: Optional[Union[str, bytes]] = None,
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
        if secret_key is None and agent_private_key is not None:
            secret_key = agent_private_key
        if secret_key is None:
            self._sk_bytes = os.urandom(32)
        else:
            self._sk_bytes = _parse_bytes(secret_key, 32)

        self._delta_v_micro = int(round(delta_v_usdc * 1e6))
        self._wal_path = wal_path

        if _IS_NATIVE:
            sk_arr = (ctypes.c_uint8 * 32)(*self._sk_bytes)
            wal_c = wal_path.encode() if wal_path else None
            raw_agent_ctx = _LIB.csls_agent_new(sk_arr, wal_c)
            if not raw_agent_ctx:
                raise RuntimeError("csls_agent_new returned NULL: allocation failed")
            self._agent_ctx = _AgentCtxHandle(raw_agent_ctx)

            raw_vendor_ctx = _LIB.csls_vendor_new(sk_arr, self._delta_v_micro)
            if not raw_vendor_ctx:
                _LIB.csls_agent_free(self._agent_ctx)
                raise RuntimeError("csls_vendor_new returned NULL: allocation failed")
            self._recv_ctx = _VendorCtxHandle(raw_vendor_ctx)
            _LIB.csls_vendor_enable_mac(self._recv_ctx, 1 if enforce_mac else 0)
        else:
            pk = derive_public_key(self._sk_bytes, compressed=True)
            self._agent_ctx = _PyAgentCtx(self._sk_bytes, pk)
            self._recv_ctx = _PyVendorCtx(self._sk_bytes, pk, self._delta_v_micro)
            self._recv_ctx.enforce_mac = 1 if enforce_mac else 0

        self._ctx = self._agent_ctx
        self._master_ctx = self._agent_ctx
        self._channel_accumulated: Dict[bytes, int] = {}

    @property
    def public_key(self) -> bytes:
        return bytes(self._agent_ctx.pk)

    @property
    def public_key_hex(self) -> str:
        return "0x" + self.public_key.hex()

    @property
    def height(self) -> int:
        with self._lock:
            return self._agent_ctx.height

    @property
    def total_sent_usdc(self) -> float:
        with self._lock:
            return self._agent_ctx.cumulative_sent / 1e6

    @property
    def accumulated_usdc(self) -> float:
        with self._lock:
            if not self._channel_accumulated:
                return self._recv_ctx.accumulated_amount / 1e6
            return sum(self._channel_accumulated.values()) / 1e6

    @property
    def cleared_usdc(self) -> float:
        with self._lock:
            return self._recv_ctx.cleared_amount / 1e6

    @property
    def last_height(self) -> int:
        with self._lock:
            return self._recv_ctx.last_height

    @property
    def max_exposure_delta_v(self) -> int:
        with self._lock:
            return getattr(self._recv_ctx, "max_exposure_delta_v", self._delta_v_micro)

    def __getattr__(self, name: str) -> Any:
        if name in ("_recv_ctx", "_agent_ctx", "_ctx", "_lock"):
            raise AttributeError(name)
        if hasattr(self, "_recv_ctx") and hasattr(self._recv_ctx, name):
            return getattr(self._recv_ctx, name)
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")

    def enable_mac(self, enable: bool = True) -> None:
        """Enables or disables mandatory Session MAC enforcement (C2 gate) for incoming cheques."""
        with self._lock:
            self._enforce_mac = enable
            if _IS_NATIVE and isinstance(self._recv_ctx, _VendorCtxHandle):
                rc = _LIB.csls_vendor_enable_mac(self._recv_ctx, 1 if enable else 0)
                if rc != 0:
                    raise RuntimeError(f"csls_vendor_enable_mac failed with code {rc}")
            else:
                self._recv_ctx.enforce_mac = 1 if enable else 0

    def get_outgoing_channel_height(self, vendor_pk: Union[str, bytes]) -> int:
        v_bytes = _parse_bytes(vendor_pk, 33)
        with self._lock:
            if _IS_NATIVE and isinstance(self._agent_ctx, _AgentCtxHandle):
                v_arr = (ctypes.c_uint8 * 33)(*v_bytes)
                h = ctypes.c_uint64(0)
                cum = ctypes.c_uint64(0)
                rc = _LIB.csls_agent_get_channel_state(self._agent_ctx, v_arr, ctypes.byref(h), ctypes.byref(cum))
                if rc == 0:
                    return h.value
                return 0
            else:
                return self._agent_ctx.channels.get(v_bytes, (0, 0))[0]

    def get_channel_cumulative(self, vendor_pk: Union[str, bytes]) -> int:
        v_bytes = _parse_bytes(vendor_pk, 33)
        with self._lock:
            if _IS_NATIVE and isinstance(self._agent_ctx, _AgentCtxHandle):
                v_arr = (ctypes.c_uint8 * 33)(*v_bytes)
                h = ctypes.c_uint64(0)
                cum = ctypes.c_uint64(0)
                rc = _LIB.csls_agent_get_channel_state(self._agent_ctx, v_arr, ctypes.byref(h), ctypes.byref(cum))
                if rc == 0:
                    return cum.value
                return 0
            else:
                return self._agent_ctx.channels.get(v_bytes, (0, 0))[1]

    def get_incoming_channel_height(self, agent_pk: Union[str, bytes]) -> int:
        a_bytes = _parse_bytes(agent_pk, 33)
        with self._lock:
            if _IS_NATIVE and isinstance(self._recv_ctx, _VendorCtxHandle):
                a_arr = (ctypes.c_uint8 * 33)(*a_bytes)
                h = ctypes.c_uint64(0)
                accum = ctypes.c_uint64(0)
                cleared = ctypes.c_uint64(0)
                rc = _LIB.csls_vendor_get_channel_state(self._recv_ctx, a_arr, ctypes.byref(h), ctypes.byref(accum), ctypes.byref(cleared))
                if rc == 0:
                    return h.value
                return 0
            else:
                return self._recv_ctx.channels.get(a_bytes, (0, 0, 0))[0]

    def get_channel_accumulated(self, agent_pk: Union[str, bytes]) -> int:
        a_bytes = _parse_bytes(agent_pk, 33)
        with self._lock:
            if a_bytes in self._channel_accumulated:
                return self._channel_accumulated[a_bytes]
            if _IS_NATIVE and isinstance(self._recv_ctx, _VendorCtxHandle):
                a_arr = (ctypes.c_uint8 * 33)(*a_bytes)
                h = ctypes.c_uint64(0)
                accum = ctypes.c_uint64(0)
                cleared = ctypes.c_uint64(0)
                rc = _LIB.csls_vendor_get_channel_state(self._recv_ctx, a_arr, ctypes.byref(h), ctypes.byref(accum), ctypes.byref(cleared))
                if rc == 0:
                    return accum.value
                return 0
            else:
                return self._recv_ctx.channels.get(a_bytes, (0, 0, 0))[1]

    def get_channel_cleared(self, agent_pk: Union[str, bytes]) -> int:
        a_bytes = _parse_bytes(agent_pk, 33)
        with self._lock:
            if _IS_NATIVE and isinstance(self._recv_ctx, _VendorCtxHandle):
                a_arr = (ctypes.c_uint8 * 33)(*a_bytes)
                h = ctypes.c_uint64(0)
                accum = ctypes.c_uint64(0)
                cleared = ctypes.c_uint64(0)
                rc = _LIB.csls_vendor_get_channel_state(self._recv_ctx, a_arr, ctypes.byref(h), ctypes.byref(accum), ctypes.byref(cleared))
                if rc == 0:
                    return cleared.value
                return 0
            else:
                return self._recv_ctx.channels.get(a_bytes, (0, 0, 0))[2]

    def get_channel_height(self, peer_pk: Union[str, bytes]) -> int:
        """Returns channel height for peer: checks outgoing first, then incoming."""
        out_h = self.get_outgoing_channel_height(peer_pk)
        if out_h > 0:
            return out_h
        return self.get_incoming_channel_height(peer_pk)

    def advance_cleared(self, agent_pk: Optional[Union[str, bytes]] = None, cleared_usdc: float = 0.0) -> None:
        """Advances cleared_amount for an agent or globally, freeing the delta_v exposure buffer."""
        if not isinstance(cleared_usdc, (int, float)):
            raise TypeError(f"cleared_usdc must be numeric, got {type(cleared_usdc).__name__}")
        if math.isnan(cleared_usdc) or math.isinf(cleared_usdc) or cleared_usdc < 0:
            raise ValueError(f"cleared_usdc must be non-negative and finite, got {cleared_usdc}")
        cleared_micro = int(round(cleared_usdc * 1e6))
        with self._lock:
            if self._closed:
                raise RuntimeError("Wallet is closed")
            if _IS_NATIVE and isinstance(self._recv_ctx, _VendorCtxHandle):
                if agent_pk is not None:
                    a_bytes = _parse_bytes(agent_pk, 33)
                    a_arr = (ctypes.c_uint8 * 33)(*a_bytes)
                    res = _LIB.csls_vendor_advance_cleared(self._recv_ctx, a_arr, cleared_micro)
                else:
                    res = _LIB.csls_vendor_advance_cleared(self._recv_ctx, None, cleared_micro)
                if res != 0:
                    raise RuntimeError(f"csls_vendor_advance_cleared failed with code {res}")
            else:
                if agent_pk is not None:
                    a_bytes = _parse_bytes(agent_pk, 33)
                    h, accum, prev_cleared = self._recv_ctx.channels.get(a_bytes, (0, 0, 0))
                    self._recv_ctx.channels[a_bytes] = (h, accum, prev_cleared + cleared_micro)
                else:
                    self._recv_ctx.cleared_amount += cleared_micro

    def create_session(self, vendor_pk: Union[str, bytes]) -> bytes:
        """
        Begins a Session MAC handshake with a counterparty.
        Returns a 95-byte session_init packet containing ECDH authentication tag.
        """
        v_bytes = _parse_bytes(vendor_pk, 33)
        with self._lock:
            if _IS_NATIVE and isinstance(self._agent_ctx, _AgentCtxHandle):
                v_arr = (ctypes.c_uint8 * 33)(*v_bytes)
                init_pkt = _CslsSessionInitPkt()
                rc = _LIB.csls_agent_session_begin(self._agent_ctx, v_arr, ctypes.byref(init_pkt))
                if rc != 0:
                    raise RuntimeError(f"csls_agent_session_begin failed with code {rc}")
                return bytes(init_pkt)
            else:
                ecdh_x_coord = _ecdh_x(self._sk_bytes, v_bytes)
                nonce = int.from_bytes(os.urandom(8), "big")
                auth_mac = _session_auth(ecdh_x_coord, self.public_key, v_bytes, nonce)
                key = _session_kdf(ecdh_x_coord, nonce)
                self._agent_ctx.sessions[v_bytes] = key
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

    def init_session(self, session_init_pkt: Union[bytes, _CslsSessionInitPkt]) -> bool:
        """
        Initializes an authenticated Session MAC session with an incoming agent from a 95-byte session_init packet.
        """
        if isinstance(session_init_pkt, bytes):
            if len(session_init_pkt) != ctypes.sizeof(_CslsSessionInitPkt):
                raise ValueError(f"Expected {ctypes.sizeof(_CslsSessionInitPkt)} bytes, got {len(session_init_pkt)}")
            c_init = _CslsSessionInitPkt.from_buffer_copy(session_init_pkt)
        else:
            c_init = session_init_pkt

        with self._lock:
            if _IS_NATIVE and isinstance(self._recv_ctx, _VendorCtxHandle):
                rc = _LIB.csls_vendor_session_init(self._recv_ctx, ctypes.byref(c_init))
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
                self._recv_ctx.sessions[agent_pk] = key
                return True

    def open_secure_session(self, peer: Any) -> bool:
        """
        Establishes an authenticated Session MAC channel with a peer agent (C2 gate).
        Returns True on success.
        """
        if hasattr(peer, "init_session") and hasattr(peer, "public_key"):
            return peer.init_session(self.create_session(peer.public_key))
        elif isinstance(peer, (bytes, str)):
            peer_bytes = _parse_bytes(peer, 33)
            pkt = self.create_session(peer_bytes)
            return len(pkt) == ctypes.sizeof(_CslsSessionInitPkt)
        return False

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
            if _IS_NATIVE and isinstance(self._agent_ctx, _AgentCtxHandle):
                v_arr = (ctypes.c_uint8 * 33)(*v_bytes)
                c_pkt = _CslsChequePkt()
                if session_mac:
                    mac_arr = (ctypes.c_uint8 * 16)()
                    res = _LIB.csls_agent_sign_cheque_mac(
                        self._agent_ctx, v_arr, delta_micro, ctypes.byref(c_pkt), mac_arr
                    )
                    if res != 0:
                        raise RuntimeError(f"csls_agent_sign_cheque_mac failed with code {res}")
                    return Cheque.from_c_pkt(c_pkt, mac=bytes(mac_arr))
                else:
                    res = _LIB.csls_agent_sign_cheque(
                        self._agent_ctx, v_arr, delta_micro, ctypes.byref(c_pkt)
                    )
                    if res != 0:
                        raise RuntimeError(f"csls_agent_sign_cheque failed with code {res}")
                    return Cheque.from_c_pkt(c_pkt)
            else:
                if session_mac and v_bytes not in self._agent_ctx.sessions:
                    raise RuntimeError(f"csls_agent_sign_cheque_mac failed with code {CSLS_ERR_NO_SESSION}")
                h = self._agent_ctx.height
                self._agent_ctx.height += 1
                prev_h, prev_cum = self._agent_ctx.channels.get(v_bytes, (0, 0))
                cum_amt = prev_cum + delta_micro
                self._agent_ctx.channels[v_bytes] = (h, cum_amt)
                self._agent_ctx.cumulative_sent += delta_micro

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
                    skey = self._agent_ctx.sessions[v_bytes]
                    mac_tag = _mac128(skey[:16], bytes(c_pkt))
                    return Cheque.from_c_pkt(c_pkt, mac=mac_tag)
                else:
                    return Cheque.from_c_pkt(c_pkt)

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
                        error_message="MAX_CHANNELS_CAPACITY_REACHED: Channel table full",
                    )

            if _IS_NATIVE and isinstance(self._recv_ctx, _VendorCtxHandle):
                if pkt_len == expected_mac:
                    mac_bytes = raw[expected_plain:expected_mac]
                    mac_arr = (ctypes.c_uint8 * 16)(*mac_bytes)
                    res = _LIB.csls_vendor_process_cheque_mac(
                        self._recv_ctx, ctypes.byref(c_pkt), mac_arr, ctypes.byref(c_fraud)
                    )
                else:
                    res = _LIB.csls_vendor_process_cheque(
                        self._recv_ctx, ctypes.byref(c_pkt), ctypes.byref(c_fraud)
                    )
            else:
                if self._recv_ctx.enforce_mac:
                    if pkt_len != expected_mac or agent_pk not in self._recv_ctx.sessions:
                        res = CSLS_ERR_BAD_MAC
                    else:
                        skey = self._recv_ctx.sessions[agent_pk]
                        tag = _mac128(skey[:16], raw[:expected_plain])
                        if raw[expected_plain:expected_mac] != tag:
                            res = CSLS_ERR_BAD_MAC
                        else:
                            res = None
                else:
                    res = None

                if res is None:
                    hist_key = (agent_pk, c_pkt.height)
                    if hist_key in self._recv_ctx.history:
                        prev_amt, prev_e, prev_s = self._recv_ctx.history[hist_key]
                        if prev_e != bytes(c_pkt.challenge_e):
                            if hist_key in self._recv_ctx.disputed:
                                res = CSLS_ERR_FRAUD
                            else:
                                self._recv_ctx.disputed.add(hist_key)
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
                        last_h, accumulated, cleared = self._recv_ctx.channels.get(agent_pk, (0, 0, 0))
                        if c_pkt.cumulative_amt < accumulated:
                            res = -11
                        else:
                            unconfirmed = c_pkt.cumulative_amt - cleared if c_pkt.cumulative_amt >= cleared else 0
                            if unconfirmed > self._recv_ctx.max_exposure_delta_v:
                                res = CSLS_ERR_EXPOSURE_CAP
                            elif last_h > 0 and c_pkt.height <= last_h:
                                res = CSLS_ERR_OUT_OF_ORDER
                            else:
                                preimage = agent_pk + bytes(c_pkt.vendor_pk) + c_pkt.height.to_bytes(8, "big") + c_pkt.cumulative_amt.to_bytes(8, "big")
                                expected_e = (int.from_bytes(hashlib.sha256(preimage).digest(), "big") % SECP256K1_Q).to_bytes(32, "big")
                                if expected_e != bytes(c_pkt.challenge_e):
                                    res = CSLS_ERR_FORGED_HASH
                                else:
                                    self._recv_ctx.history[hist_key] = (c_pkt.cumulative_amt, bytes(c_pkt.challenge_e), bytes(c_pkt.sig_s))
                                    self._recv_ctx.channels[agent_pk] = (c_pkt.height, c_pkt.cumulative_amt, cleared)
                                    self._recv_ctx.last_height = c_pkt.height
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
                if hasattr(self, "_agent_ctx") and self._agent_ctx:
                    if _IS_NATIVE and isinstance(self._agent_ctx, _AgentCtxHandle) and self._agent_ctx.value:
                        _LIB.csls_agent_free(self._agent_ctx)
                        self._agent_ctx = _AgentCtxHandle(None)
                if hasattr(self, "_recv_ctx") and self._recv_ctx:
                    if _IS_NATIVE and isinstance(self._recv_ctx, _VendorCtxHandle) and self._recv_ctx.value:
                        _LIB.csls_vendor_free(self._recv_ctx)
                        self._recv_ctx = _VendorCtxHandle(None)

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


# Backward compatibility alias
CausalVendorNode = CausalAgentWallet


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


try:
    from .debt_cycle_mesh import DebtCycleMesh
except (ImportError, ValueError):
    from debt_cycle_mesh import DebtCycleMesh

__all__ = [
    "CausalAgentWallet",
    "CausalVendorNode",
    "CycleEliminationRecord",
    "NettingSummary",
    "DebtCycleMesh",
]
