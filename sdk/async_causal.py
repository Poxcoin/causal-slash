# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
AsyncIO Channel Actor & Concurrency Guard for Causal-Slash Protocol.
Enforces strict FIFO cheque serialization per peer and shields critical state
updates against asyncio.CancelledError.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Callable, Coroutine, Dict, Optional

from .channel_store import SqliteChannelStore
from .swarm_subagent import SubagentSession, SwarmDelegationVault, SpendRateLimitExceededError

logger = logging.getLogger("causal_slash.async_causal")


class CausalQueueFullError(RuntimeError):
    """Raised when the channel actor FIFO queue exceeds its backpressure limit."""
    pass


@dataclass(slots=True)
class PaymentRequest:
    amount_micro: int
    dispatch_fn: Callable[[int, int], Coroutine[Any, Any, Any]]
    future: asyncio.Future


class AsyncChannelActor:
    """
    Dedicated FIFO actor for an individual counterparty channel (peer_pk).
    Prevents race conditions on monotonic height counters and guarantees
    atomic 2-phase reservation before network dispatch.
    Implements backpressure via max_queue_size to prevent OOM memory exhaustion.
    """

    def __init__(
        self,
        peer_pk: bytes,
        store: SqliteChannelStore,
        max_queue_size: int = 10000,
    ):
        self.peer_pk = peer_pk
        self.store = store
        self.max_queue_size = max_queue_size
        self.queue: asyncio.Queue[Optional[PaymentRequest]] = asyncio.Queue(maxsize=max_queue_size)
        self._worker_task: Optional[asyncio.Task] = None
        self._running = False

    def start(self) -> None:
        if not self._running:
            self._running = True
            self._worker_task = asyncio.create_task(self._worker_loop())

    async def stop(self) -> None:
        if self._running:
            self._running = False
            try:
                await self.queue.put(None)
            except Exception:
                pass
            if self._worker_task:
                await self._worker_task
                self._worker_task = None

    async def submit(
        self,
        amount_micro: int,
        dispatch_fn: Callable[[int, int], Coroutine[Any, Any, Any]],
    ) -> Any:
        """Enqueues a payment request into the channel FIFO actor with backpressure protection."""
        if self.queue.full():
            raise CausalQueueFullError(
                f"Channel actor queue full ({self.queue.qsize()}/{self.max_queue_size}): "
                f"backpressure limit exceeded for peer 0x{self.peer_pk.hex()[:10]}..."
            )
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        req = PaymentRequest(
            amount_micro=amount_micro, dispatch_fn=dispatch_fn, future=future
        )
        try:
            self.queue.put_nowait(req)
        except asyncio.QueueFull:
            raise CausalQueueFullError(
                f"Channel actor queue full ({self.max_queue_size}): backpressure limit exceeded"
            )
        return await future

    async def _worker_loop(self) -> None:
        while self._running:
            req = await self.queue.get()
            if req is None:
                break

            try:
                # Task 2: Skip execution if the caller cancelled or timed out before processing
                if req.future.cancelled():
                    logger.debug(
                        "PaymentRequest cancelled by client prior to execution; skipping height reservation"
                    )
                    continue

                # Wrap critical reservation -> dispatch -> commit in asyncio.shield
                # to prevent cancellation desynchronization
                result = await asyncio.shield(
                    self._execute_payment(req.amount_micro, req.dispatch_fn)
                )
                if not req.future.cancelled():
                    req.future.set_result(result)
            except Exception as exc:
                if not req.future.cancelled():
                    req.future.set_exception(exc)
            finally:
                self.queue.task_done()

    async def _execute_payment(
        self,
        amount_micro: int,
        dispatch_fn: Callable[[int, int], Coroutine[Any, Any, Any]],
    ) -> Any:
        # Phase 1: Durably reserve height in SQLite WAL with Fail-Forward Leap-Ahead
        reserved_h = self.store.reserve_height(self.peer_pk)

        channel = self.store.get_channel(self.peer_pk)
        current_cum = channel.cumulative_amt if channel else 0
        new_cum = current_cum + amount_micro

        # Phase 2: Execute network dispatch (raw TCP / EOTS cheque streaming)
        result = await dispatch_fn(reserved_h, new_cum)

        # Phase 3: Durably commit after dispatch confirmation
        self.store.commit_cheque(
            self.peer_pk, height=reserved_h, cumulative_amt=new_cum
        )
        return result


class AsyncCausalClient:
    """
    High-level AsyncIO client managing swarm delegation and per-peer channel actors.
    """

    def __init__(
        self,
        master_sk: bytes,
        store: SqliteChannelStore,
        max_queue_size: int = 10000,
    ):
        self.vault = SwarmDelegationVault(master_sk)
        self.store = store
        self.max_queue_size = max_queue_size
        self._actors: Dict[bytes, AsyncChannelActor] = {}

    @classmethod
    async def create(
        cls,
        master_sk: bytes,
        db_dir: str = "./channels_state",
        max_queue_size: int = 10000,
    ) -> AsyncCausalClient:
        store = SqliteChannelStore(db_dir)
        store.open()
        return cls(master_sk, store, max_queue_size=max_queue_size)

    def spawn_subagent(
        self, subagent_id: str, quota_micro_usdc: int
    ) -> SubagentSession:
        return self.vault.spawn_subagent(subagent_id, quota_micro_usdc)

    def _get_or_create_actor(self, peer_pk: bytes) -> AsyncChannelActor:
        if peer_pk not in self._actors:
            actor = AsyncChannelActor(
                peer_pk, self.store, max_queue_size=self.max_queue_size
            )
            actor.start()
            self._actors[peer_pk] = actor
        return self._actors[peer_pk]

    async def pay_and_stream(
        self,
        session: SubagentSession,
        peer_pk: bytes,
        amount_micro: int,
        dispatch_fn: Callable[[int, int], Coroutine[Any, Any, Any]],
    ) -> Any:
        """
        Executes an isolated subagent payment:
        1. Validates spend rate via Circuit Breaker (prevents LLM runaway loops).
        2. Validates and reserves subagent quota (Axiom 1).
        3. Serializes payment through the peer's FIFO ChannelActor.
        4. Commits spending in the session, or releases reservation on error/cancellation.
        """
        session.check_spend_rate(amount_micro)
        session.check_and_reserve(amount_micro)
        actor = self._get_or_create_actor(peer_pk)
        try:
            res = await actor.submit(amount_micro, dispatch_fn)
            session.commit_spend(amount_micro)
            return res
        except (Exception, asyncio.CancelledError):
            session.release_reserve(amount_micro)
            raise

    async def close(self) -> None:
        for actor in self._actors.values():
            await actor.stop()
        self._actors.clear()
        self.store.close()
