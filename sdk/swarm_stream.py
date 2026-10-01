# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Causal-Slash Protocol: Swarm Stream Coordinator.

Schedules multi-agent cheque streaming against the C11 engine while respecting
its two hard constraints discovered in adversarial design review:

  1. ONE GLOBAL last_height per vendor node: accepted cheques at a vendor node
     must have strictly increasing heights across ALL payers.
  2. NON-DECREASING cumulative_amt per vendor node across all payers (the
     engine rejects a cumulative lower than its last accepted value), plus a
     lifetime exposure cap delta_v (cleared_amount never grows in this engine).

The coordinator therefore assigns a single GLOBAL monotonic height lane to the
whole swarm (every cheque gets a unique global height) and callers are expected
to keep payer cumulative trajectories aligned per payee node (uniform amounts
per round). Ledger bookkeeping is exact integer micro-USDC.

Single-threaded by design: the height lane is ctypes state shared with the C
engine and must not be raced.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from causal_slash import CausalAgentWallet, CausalVendorNode, Cheque

ChequeStatusError = RuntimeError


@dataclass
class ChannelStats:
    paid_micro: int = 0
    received_micro: int = 0
    cheques_sent: int = 0
    cheques_received: int = 0
    last_height: int = 0


@dataclass
class StreamCoordinator:
    """Global height lanes + integer ledger over the native C engine."""

    wallets: Dict[str, CausalAgentWallet] = field(default_factory=dict)
    payee_nodes: Dict[bytes, CausalVendorNode] = field(default_factory=dict)
    ledger: Dict[Tuple[bytes, bytes], int] = field(default_factory=dict)
    channel_stats: Dict[Tuple[bytes, bytes], ChannelStats] = field(default_factory=dict)
    _last_cum_by_payer: Dict[bytes, int] = field(default_factory=dict)
    next_height: int = 1
    total_streamed_micro: int = 0
    total_cheques: int = 0

    def register_wallet(self, name: str, wallet: CausalAgentWallet) -> None:
        if name in self.wallets:
            raise ValueError(f"wallet '{name}' already registered")
        self.wallets[name] = wallet

    def register_payee(self, node: CausalVendorNode) -> bytes:
        pk = node.public_key
        if pk in self.payee_nodes:
            raise ValueError("payee node already registered")
        self.payee_nodes[pk] = node
        return pk

    # ------------------------------------------------------------------ core

    def stream(
        self,
        payer_wallet: CausalAgentWallet,
        payee_node: CausalVendorNode,
        amount_micro: int,
        lane_height: Optional[int] = None,
        purpose: str = "",
    ) -> Cheque:
        """
        Signs one cheque at a swarm-globally unique height and delivers it to
        the payee node. Returns the accepted Cheque; raises on ANY rejection.
        """
        if amount_micro <= 0:
            raise ValueError("amount_micro must be positive")

        height = lane_height if lane_height is not None else self.next_height
        if height < self.next_height:
            raise ValueError(
                f"lane height {height} violates global monotonicity "
                f"(next free: {self.next_height})")
        # Rewind-precondition: the engine initializes the counter at 1 and
        # post-increments, so used heights are 1 .. ctx.height-1. Signing at
        # `height` requires parking the counter exactly there; anything below
        # the current counter would reuse an already-signed (sk, height) pair.
        if height < payer_wallet._ctx.height:
            raise ValueError(
                f"lane height {height} would rewind payer below "
                f"ctx.height={payer_wallet._ctx.height}")

        # Engine post-increments: parking the counter at `height` makes the
        # next fetch_add return exactly `height`.
        payer_wallet._ctx.height = height
        cheque = payer_wallet.sign_cheque(payee_node.public_key, amount_micro / 1e6)
        if cheque.height != height:
            raise AssertionError(f"engine signed height {cheque.height}, expected {height}")

        result = payee_node.process_cheque(cheque)
        if not result.accepted:
            raise ChequeStatusError(
                f"cheque h={height} rejected by vendor: "
                f"code={result.status_code} msg={result.error_message}")

        payer_pk, payee_pk = payer_wallet.public_key, payee_node.public_key
        self._last_cum_by_payer[payer_pk] = int.from_bytes(
            cheque.raw_packet[79:87], "little")
        key = (payer_pk, payee_pk)
        stats = self.channel_stats.setdefault(key, ChannelStats())
        stats.paid_micro += amount_micro
        stats.cheques_sent += 1
        stats.last_height = height
        self.channel_stats.setdefault((payee_pk, payer_pk), ChannelStats())
        recv_stats = self.channel_stats[(payee_pk, payer_pk)]
        recv_stats.received_micro += amount_micro
        recv_stats.cheques_received += 1
        recv_stats.last_height = height
        self.ledger[key] = self.ledger.get(key, 0) + amount_micro
        self.next_height = height + 1
        self.total_streamed_micro += amount_micro
        self.total_cheques += 1
        return cheque

    def sign_only(
        self, payer_wallet: CausalAgentWallet, vendor_pk: bytes,
        amount_micro: int, lane_height: int,
    ) -> Cheque:
        """
        Signs a cheque at an explicit height WITHOUT delivering it (offline
        signature path, e.g. for wire-level capture demos). Advances the
        coordinator's global lane so the height can never be reused.
        """
        if lane_height < self.next_height:
            raise ValueError("lane height violates global monotonicity")
        if lane_height < payer_wallet._ctx.height:
            raise ValueError("lane height would rewind payer")
        # Engine post-increments: parking at `lane_height` signs exactly there.
        payer_wallet._ctx.height = lane_height
        cheque = payer_wallet.sign_cheque(vendor_pk, amount_micro / 1e6)
        if cheque.height != lane_height:
            raise AssertionError("engine height mismatch")
        self.next_height = lane_height + 1
        return cheque

    def deliver(self, payee_node: CausalVendorNode, cheque: Cheque,
                amount_micro: Optional[int] = None):
        """
        Delivers a previously signed (offline) cheque; records on acceptance.
        The ledger amount is DERIVED from the cheque's own cumulative delta
        (never trusted from the caller), keeping the Kirchhoff graph honest.
        """
        result = payee_node.process_cheque(cheque)
        if not result.accepted:
            raise ChequeStatusError(
                f"offline cheque h={cheque.height} rejected: "
                f"code={result.status_code} msg={result.error_message}")
        raw_cum = int.from_bytes(cheque.raw_packet[79:87], "little")
        last = self._last_cum_by_payer.get(cheque.agent_pk, 0)
        derived_amount = raw_cum - last
        if derived_amount <= 0:
            raise ValueError("offline cheque cumulative delta must be positive")
        if amount_micro is not None and amount_micro != derived_amount:
            raise ValueError(
                f"declared amount {amount_micro} != cheque cumulative delta {derived_amount}")
        self._last_cum_by_payer[cheque.agent_pk] = raw_cum
        key = (cheque.agent_pk, payee_node.public_key)
        stats = self.channel_stats.setdefault(key, ChannelStats())
        stats.paid_micro += derived_amount
        stats.cheques_sent += 1
        stats.last_height = cheque.height
        recv_stats = self.channel_stats.setdefault((payee_node.public_key, cheque.agent_pk),
                                                   ChannelStats())
        recv_stats.received_micro += derived_amount
        recv_stats.cheques_received += 1
        recv_stats.last_height = cheque.height
        self.ledger[key] = self.ledger.get(key, 0) + derived_amount
        self.total_streamed_micro += derived_amount
        self.total_cheques += 1
        return result

    # --------------------------------------------------------------- queries

    def edges(self) -> Dict[Tuple[bytes, bytes], int]:
        return dict(self.ledger)

    def clear_edge(self, payer: bytes, payee: bytes, amount_micro: int) -> None:
        key = (payer, payee)
        remaining = self.ledger.get(key, 0) - amount_micro
        if remaining < 0:
            raise ValueError("settlement exceeds outstanding edge")
        self.ledger[key] = remaining
        if remaining == 0:
            del self.ledger[key]

    def channel_balance(self, payer_pk: bytes, payee_pk: bytes) -> ChannelStats:
        return self.channel_stats.get((payer_pk, payee_pk), ChannelStats())
