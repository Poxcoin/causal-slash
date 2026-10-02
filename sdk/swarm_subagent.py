# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Swarm Subagent Delegation & Quota Isolation (Axiom 1).
Prevents Master Key leakage to untrusted/ephemeral agent runtimes (LangChain/CrewAI).

Guarantees:
1. sub_sk is cryptographically derived via HMAC-SHA256(master_sk, "causal:subagent:{subagent_id}").
2. The master secret key (master_sk) NEVER leaves the host secure memory perimeter.
3. Subagents operate strictly within an allocated micro-USDC quota against the master bond.
4. Any equivocation or slashing penalizes only the subagent's quota; the master bond remains intact!
5. Circuit Breaker: Configurable spend-rate limiting prevents LLM runaway loops from burning deposits.
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Tuple


class SubagentQuotaExceededError(Exception):
    """Raised when a subagent exceeds its allocated micro-USDC spending quota."""
    pass


class SpendRateLimitExceededError(Exception):
    """Raised when the spend rate (USDC/min) exceeds the configured Circuit Breaker threshold."""
    pass


def _derive_secp256k1_pubkey(secret_key: bytes) -> bytes:
    """
    Derives an honest 33-byte compressed secp256k1 public key PK = sk · G
    via the C11 libcausal_slash.so engine (OpenSSL EC_POINT_mul).

    This replaces the broken SHA-256 hash stub that produced random bytes
    not on the secp256k1 curve (y² = x³ + 7), which broke verification
    on Base L2 and the C11 core.
    """
    from .causal_slash import _LIB

    sk_arr = (ctypes.c_uint8 * 32)(*secret_key)
    raw_ctx = _LIB.csls_agent_new(sk_arr, None)
    if not raw_ctx:
        raise RuntimeError(
            "csls_agent_new returned NULL: failed to derive secp256k1 public key"
        )
    try:
        pk = bytes((ctypes.c_uint8 * 33).from_address(raw_ctx + 32))
    finally:
        _LIB.csls_agent_free(raw_ctx)
    return pk


@dataclass(slots=True)
class SubagentSession:
    subagent_id: str
    sub_sk: bytes
    sub_pk: bytes
    quota_micro_usdc: int
    spent_micro_usdc: int = 0
    reserved_micro_usdc: int = 0
    max_spend_rate_usdc_per_min: float = 2.0
    _spend_log: Deque[Tuple[float, int]] = field(
        default_factory=deque, repr=False
    )

    def _record_spend(self, amount_micro: int) -> None:
        """Records a spend event with timestamp for sliding window tracking."""
        self._spend_log.append((time.monotonic(), amount_micro))

    def _prune_spend_window(self, now: float) -> None:
        """Removes spend records older than 60 seconds from the sliding window."""
        cutoff = now - 60.0
        while self._spend_log and self._spend_log[0][0] < cutoff:
            self._spend_log.popleft()

    def _current_spend_rate_micro(self) -> int:
        """Returns total micro-USDC spent in the last 60-second sliding window."""
        now = time.monotonic()
        self._prune_spend_window(now)
        return sum(amt for _, amt in self._spend_log)

    def check_spend_rate(self, amount_micro: int) -> None:
        """
        Circuit Breaker: Checks if adding amount_micro would exceed the
        configured max_spend_rate_usdc_per_min within the 60-second sliding window.
        Raises SpendRateLimitExceededError if the limit would be exceeded.
        """
        rate_limit_micro = int(self.max_spend_rate_usdc_per_min * 1_000_000)
        current_window_spend = self._current_spend_rate_micro()
        if current_window_spend + amount_micro > rate_limit_micro:
            raise SpendRateLimitExceededError(
                f"Rate limit exceeded: max ${self.max_spend_rate_usdc_per_min}/min"
            )

    def check_and_reserve(self, amount_micro: int) -> None:
        """Verifies spending does not exceed the subagent's allocated quota and reserves it."""
        if self.spent_micro_usdc + self.reserved_micro_usdc + amount_micro > self.quota_micro_usdc:
            remaining = max(0, self.quota_micro_usdc - (self.spent_micro_usdc + self.reserved_micro_usdc))
            raise SubagentQuotaExceededError(
                f"Subagent '{self.subagent_id}' exceeded quota! "
                f"Requested: {amount_micro} micro-USDC, Remaining: {remaining} micro-USDC"
            )
        self.reserved_micro_usdc += amount_micro

    def release_reserve(self, amount_micro: int) -> None:
        """Releases uncommitted reserve if an operation fails or times out."""
        self.reserved_micro_usdc = max(0, self.reserved_micro_usdc - amount_micro)

    def commit_spend(self, amount_micro: int) -> None:
        """Records finalized spending, deducts from reserve, and logs it to the sliding window."""
        self.reserved_micro_usdc = max(0, self.reserved_micro_usdc - amount_micro)
        self.spent_micro_usdc += amount_micro
        self._record_spend(amount_micro)

    @property
    def remaining_quota(self) -> int:
        return max(0, self.quota_micro_usdc - (self.spent_micro_usdc + self.reserved_micro_usdc))


class SwarmDelegationVault:
    """
    Manages master bond delegation and spawns isolated subagent sessions.
    The master_sk remains strictly isolated in memory.
    """

    def __init__(
        self,
        master_sk: Optional[bytes] = None,
        master_bond_usdc: float = 100.0,
    ):
        if master_sk is None:
            master_sk = b"\x42" * 32
        if len(master_sk) != 32:
            raise ValueError("master_sk must be exactly 32 bytes")
        self._master_sk = master_sk
        self.master_bond_usdc = master_bond_usdc
        self._sessions: Dict[str, SubagentSession] = {}

    def spawn_subagent(
        self,
        subagent_id: str,
        quota_micro_usdc: Optional[int] = None,
        quota_usdc: Optional[float] = None,
        max_spend_rate_usdc_per_min: float = 2.0,
    ) -> SubagentSession:
        """
        Derives an isolated subagent keypair:
        sub_sk = HMAC-SHA256(master_sk, f"causal:subagent:{subagent_id}")
        sub_pk = sub_sk · G (honest secp256k1 point multiplication via C11 engine)
        """
        if subagent_id in self._sessions:
            return self._sessions[subagent_id]

        if quota_micro_usdc is None:
            if quota_usdc is not None:
                quota_micro_usdc = int(round(quota_usdc * 1e6))
            else:
                quota_micro_usdc = 1_000_000

        derived_sk = hmac.new(
            self._master_sk,
            f"causal:subagent:{subagent_id}".encode("utf-8"),
            hashlib.sha256,
        ).digest()

        # Honest 33-byte compressed secp256k1 public key: PK = sub_sk · G
        # via C11 libcausal_slash.so (OpenSSL EC_POINT_mul)
        derived_pk = _derive_secp256k1_pubkey(derived_sk)

        session = SubagentSession(
            subagent_id=subagent_id,
            sub_sk=derived_sk,
            sub_pk=derived_pk,
            quota_micro_usdc=quota_micro_usdc,
            max_spend_rate_usdc_per_min=max_spend_rate_usdc_per_min,
        )
        self._sessions[subagent_id] = session
        return session

    def get_session(self, subagent_id: str) -> Optional[SubagentSession]:
        return self._sessions.get(subagent_id)
