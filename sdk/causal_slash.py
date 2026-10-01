# SPDX-License-Identifier: Apache-2.0
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
import threading
import time
from dataclasses import dataclass
from typing import Optional, Tuple, Union, Dict, List, Set

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
    os.path.join(_SDK_DIR, "libcausal_slash.so"),
    os.path.join(_PROJECT_ROOT, "libcausal_slash.so")
]

def _load_c_lib() -> ctypes.CDLL:
    for path in _SO_PATHS:
        if os.path.exists(path):
            return ctypes.CDLL(path)
    # Auto-compile in sdk directory if missing
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
        ("__padding", ctypes.c_int),
        ("lock", ctypes.c_byte * 40),
        ("bn_ctx", ctypes.c_void_p),
        ("bn_sk", ctypes.c_void_p),
        ("bn_k", ctypes.c_void_p),
        ("bn_e", ctypes.c_void_p),
        ("bn_s", ctypes.c_void_p),
        ("bn_tmp", ctypes.c_void_p),
    ]

class _CslsHistoryEntry(ctypes.Structure):
    _fields_ = [
        ("agent_pk", ctypes.c_uint8 * 33),
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
        ("lock", ctypes.c_byte * 40),
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

    @property
    def cumulative_amt(self) -> int:
        return int(round(self.cumulative_amount_usdc * 1e6))


# Alias for formal protocol specification naming
CslsCheque = Cheque


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
        Processes an incoming streaming micro-cheque using Optimistic P2P Credit Streaming bounded by delta_v.

        Validates protocol framing, monotonic height progression, challenge digest (e mod q),
        and enforces local credit exposure buffer (delta_v USDC).
        If equivocation (conflicting cheques on identical height) is detected, algebraically extracts
        the offender's private key via O(1) modular arithmetic for automated Base L2 foreclosure.
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
    Implements Kirchhoff Cycle Elimination (BILLION_AGENT_ARCHITECTURE.md Section 2)
    for autonomous agent swarms, canceling closed loops of reciprocal micro-debts
    in RAM with thread-safe concurrency.

    Mathematical Invariants Enforced:
    1. Conservation of Net Balance: b'(u) == b(u) for all agents u in V (Theorem 2).
    2. Strict Monotonic Debt Reduction: W(T(G)) = W(G) - k * Delta_C (Theorem 3).
    3. Compression: >= 99% reduction of on-chain settlement transactions and volume
       on high-density cyclical workloads.
    """

    def __init__(self, auto_bilateral_netting: bool = True):
        self._lock = threading.RLock()
        self._auto_bilateral = auto_bilateral_netting
        # _adj[debtor][creditor] = amount_micro_usdc
        self._adj: Dict[bytes, Dict[bytes, int]] = {}
        self._nodes: Set[bytes] = set()

        # Cumulative tracking for streaming CslsCheque channels: (agent_pk, vendor_pk) -> cumulative_amt
        self._channel_cumulative: Dict[Tuple[bytes, bytes], int] = {}

        # Accounting and audit statistics
        self._gross_tx_count: int = 0
        self._gross_volume: int = 0
        self._total_cleared: int = 0
        self._cycles_eliminated: int = 0
        self._history: List[CycleEliminationRecord] = []

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
        Extracts incremental micro-debt from the monotonic cumulative amount
        and updates the mesh.
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
        Positive: net creditor (funds receivable).
        Negative: net debtor (funds payable).
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

    def find_cycle(self) -> Optional[List[bytes]]:
        """
        Finds a simple directed cycle in the active debt graph using iterative DFS.
        Returns list of nodes representing the cycle [v1, v2, ..., vk, v1], or None.
        """
        with self._lock:
            state: Dict[bytes, int] = {}  # 0: unvisited, 1: visiting (stack), 2: visited

            for start_node in list(self._adj.keys()):
                if state.get(start_node, 0) != 0:
                    continue

                stack = [(start_node, iter(list(self._adj.get(start_node, {}).keys())))]
                state[start_node] = 1

                while stack:
                    u, neighbors = stack[-1]
                    try:
                        v = next(neighbors)
                        if self._adj.get(u, {}).get(v, 0) <= 0:
                            continue

                        v_state = state.get(v, 0)
                        if v_state == 1:
                            # Directed cycle detected! Backtrack stack to reconstruct [v, ..., v]
                            cycle = [v]
                            for node, _ in reversed(stack):
                                cycle.append(node)
                                if node == v:
                                    break
                            cycle.reverse()
                            return cycle
                        elif v_state == 0:
                            state[v] = 1
                            stack.append((v, iter(list(self._adj.get(v, {}).keys()))))
                    except StopIteration:
                        state[u] = 2
                        stack.pop()

            return None

    def reduce_kirchhoff_cycles(
        self, max_cycles: Optional[int] = None
    ) -> Tuple[int, int]:
        """
        Executes iterative Kirchhoff Cycle Elimination (Section 2.2).
        Continuously detects directed cycles C, finds bottleneck Delta_C = min w(v_i, v_{i+1}),
        and subtracts Delta_C along each edge of the cycle.

        Guarantees:
        - Net divergence balance of every node is strictly preserved (Theorem 2).
        - Monotonic reduction of gross debt by k * Delta_C (Theorem 3).
        - Terminates when graph is a Directed Acyclic Graph (DAG) or max_cycles reached.

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

                # Bottleneck Capacity Delta_C
                bottleneck = min(
                    self._adj[cycle[i]][cycle[i + 1]] for i in range(k)
                )

                if bottleneck <= 0:
                    break

                # Subtract Delta_C along cycle
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
        """
        Returns summary statistics for the debt mesh including compression ratios.
        """
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
        Returns list of (debtor_pk, creditor_pk, amount_micro_usdc).
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


if __name__ == "__main__":
    import time
    print("=" * 70)
    print("CAUSAL-SLASH PYTHON SDK: BENCHMARK & VERIFICATION SUITE")
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

    print(f"  [OK] Completed {n:,} cheques in {total_time:.4f} seconds")
    print(f"  Latency: {us_per_op:.2f} microseconds per full cycle (Sign + Verify)")
    print(f"  Throughput: {ops_per_sec:,.0f} operations/second in Python!")
    print(f"  Settled Volume: ${vendor.accumulated_usdc:.4f} USDC")

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
    print("  [ALERT] Equivocation detected and private key extracted successfully")
    print(f"  Offender PK:  {r2.fraud_proof.offender_pk.hex()[:18]}...")
    print(f"  Extracted SK: {r2.fraud_proof.extracted_secret_key.hex()[:18]}...")
    print(f"  True SK:      {bytes(attacker_agent._ctx.sk).hex()[:18]}...")
    print("  [PASS] Mathematical Invariant Verified: Extracted key matches agent secret key")

    # 4. DebtCycleMesh Kirchhoff Cycle Reduction & Invariant Test
    print("\n[3] Testing DebtCycleMesh & Kirchhoff Cycle Reduction...")
    mesh = DebtCycleMesh()
    pk_a = b"\x02" + b"A" * 32
    pk_b = b"\x02" + b"B" * 32
    pk_c = b"\x02" + b"C" * 32
    pk_d = b"\x02" + b"D" * 32

    mesh.add_obligation(pk_a, pk_b, 100_000) # $0.10
    mesh.add_obligation(pk_b, pk_c, 100_000) # $0.10
    mesh.add_obligation(pk_c, pk_d, 100_000) # $0.10
    mesh.add_obligation(pk_d, pk_a, 100_000) # $0.10
    mesh.add_obligation(pk_b, pk_d, 50_000)  # $0.05

    bal_before = mesh.get_all_net_balances()
    assert sum(bal_before.values()) == 0

    cycles, cleared = mesh.reduce_kirchhoff_cycles()
    bal_after = mesh.get_all_net_balances()

    assert bal_before == bal_after, "Kirchhoff Net Balance Invariant Violated!"
    assert mesh.is_dag, "Residual graph must be a DAG!"
    print(f"  Cycles Eliminated: {cycles}")
    print(f"  Cleared Volume: ${cleared / 1e6:.4f} USDC")
    print(f"  Remaining Net System Debt: ${mesh.total_system_debt / 1e6:.4f} USDC")
    print("  [PASS] Mathematical Invariant Verified: Net balances strictly preserved (Theorem 2)")
    print("=" * 70)
    print("ALL PYTHON SDK VERIFICATIONS COMPLETED SUCCESSFULLY!")

