# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Pythonic Context Managers: CausalSession & AsyncCausalSession.

Enables seamless, robust lifecycle management for streaming micro-payments:
- Automatic per-channel height tracking and cumulative accounting
- Local budget reservation and credit exposure guardrails
- Integrated Circuit Breaker spend-rate protection
- Auto-flush and reconciliation with DebtCycleMesh on clean exit
- Graceful rollback of uncommitted reserves on exceptions
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any, Optional, Union

if TYPE_CHECKING:
    from .causal_slash import CausalAgentWallet, Cheque, DebtCycleMesh
    from .swarm_subagent import SubagentSession

logger = logging.getLogger("causal_slash.session")


class BudgetExceededError(RuntimeError):
    """Raised when payment exceeds configured session budget."""
    pass


class CausalSession:
    """
    Synchronous context manager for streaming micro-settlement sessions.
    
    Usage:
        with wallet.session(vendor_pk, budget_usdc=5.0, price_per_call=0.0005) as session:
            cheque = session.pay()
    """

    def __init__(
        self,
        wallet: CausalAgentWallet,
        vendor_pk: Union[str, bytes],
        budget_usdc: float = 10.0,
        price_per_call: float = 0.0005,
        subagent_session: Optional[SubagentSession] = None,
        mesh: Optional[DebtCycleMesh] = None,
        session_mac: bool = False,
    ):
        self.wallet = wallet
        self.vendor_pk = vendor_pk
        self.budget_usdc = budget_usdc
        self.price_per_call = price_per_call
        self.subagent_session = subagent_session
        self.mesh = mesh
        self.session_mac = session_mac

        self.spent_usdc: float = 0.0
        self.cheques_issued: int = 0
        self._is_active: bool = False
        self._pending_reservation_micro: int = 0

    @property
    def remaining_budget_usdc(self) -> float:
        return max(0.0, self.budget_usdc - self.spent_usdc)

    def pay(self, amount_usdc: Optional[float] = None) -> Cheque:
        """
        Issues a signed micro-cheque within the active session.
        Validates budget, checks Circuit Breaker, updates local spent total,
        and records to DebtCycleMesh if configured.
        """
        if not self._is_active:
            raise RuntimeError("Cannot pay: CausalSession is not active (use within context manager)")

        amt = amount_usdc if amount_usdc is not None else self.price_per_call
        amt_micro = int(round(amt * 1e6))

        if self.spent_usdc + amt > self.budget_usdc + 1e-9:
            raise BudgetExceededError(
                f"Session budget exceeded: attempted to spend ${amt:.6f}, "
                f"only ${self.remaining_budget_usdc:.6f} remaining of ${self.budget_usdc:.6f}"
            )

        # 1. Circuit Breaker & Subagent Quota Validation
        if self.subagent_session is not None:
            self.subagent_session.check_spend_rate(amt_micro)
            self.subagent_session.check_and_reserve(amt_micro)
            self._pending_reservation_micro += amt_micro

        # 2. Sign cryptographic micro-cheque
        try:
            cheque = self.wallet.sign_cheque(
                self.vendor_pk,
                amount_usdc=amt,
                session_mac=self.session_mac,
            )
        except Exception:
            # Rollback reservation on signature failure
            if self.subagent_session is not None and self._pending_reservation_micro > 0:
                self._pending_reservation_micro -= amt_micro
            raise

        # 3. Commit spend
        if self.subagent_session is not None:
            self.subagent_session.commit_spend(amt_micro)
            self._pending_reservation_micro -= amt_micro

        self.spent_usdc += amt
        self.cheques_issued += 1

        # 4. Ingest into in-memory mesh if attached
        if self.mesh is not None:
            self.mesh.record_cheque(cheque)

        logger.debug(
            "CausalSession payment issued: h=%d, delta=$%.6f, total_spent=$%.6f",
            cheque.height, amt, self.spent_usdc
        )
        return cheque

    def __enter__(self) -> CausalSession:
        self._is_active = True
        logger.debug("CausalSession started with budget=$%.4f USDC", self.budget_usdc)
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self._is_active = False

        # Cleanup uncommitted reserves if exception occurred
        if exc_type is not None:
            logger.warning(
                "CausalSession closed with exception: %s. Rolling back uncommitted reservations.",
                exc_val
            )
            self._pending_reservation_micro = 0

        # Auto-reconcile / reduce cycles in mesh if attached
        if self.mesh is not None:
            try:
                self.mesh.reduce_kirchhoff_cycles()
            except Exception as e:
                logger.error("Error during automatic mesh cycle reduction on session exit: %s", e)

        logger.debug(
            "CausalSession cleanly terminated: issued %d cheques, total spent $%.6f USDC",
            self.cheques_issued, self.spent_usdc
        )


class AsyncCausalSession:
    """
    Asynchronous context manager for streaming micro-settlement sessions.
    
    Usage:
        async with wallet.async_session(vendor_pk, budget_usdc=10.0, price_per_call=0.0005) as session:
            cheque = await session.pay()
    """

    def __init__(
        self,
        wallet: CausalAgentWallet,
        vendor_pk: Union[str, bytes],
        budget_usdc: float = 10.0,
        price_per_call: float = 0.0005,
        subagent_session: Optional[SubagentSession] = None,
        mesh: Optional[DebtCycleMesh] = None,
        session_mac: bool = False,
    ):
        self._sync_session = CausalSession(
            wallet=wallet,
            vendor_pk=vendor_pk,
            budget_usdc=budget_usdc,
            price_per_call=price_per_call,
            subagent_session=subagent_session,
            mesh=mesh,
            session_mac=session_mac,
        )

    @property
    def spent_usdc(self) -> float:
        return self._sync_session.spent_usdc

    @property
    def cheques_issued(self) -> int:
        return self._sync_session.cheques_issued

    @property
    def remaining_budget_usdc(self) -> float:
        return self._sync_session.remaining_budget_usdc

    async def pay(self, amount_usdc: Optional[float] = None) -> Cheque:
        # Offload synchronous crypto signature to executor to prevent event-loop blocking
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._sync_session.pay, amount_usdc)

    async def __aenter__(self) -> AsyncCausalSession:
        self._sync_session.__enter__()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self._sync_session.__exit__(exc_type, exc_val, exc_tb)
