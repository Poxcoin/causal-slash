# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Seamless LangChain & LangGraph integration for Causal-Slash Protocol.
Enables AI Agents to autonomously pay for tools, APIs, and token inference
with zero prepay and O(1) EOTS collateral security.
"""

from __future__ import annotations

import asyncio
import functools
import logging
from typing import Any, Callable, Dict, Optional

try:
    from ..async_causal import AsyncCausalClient
    from ..swarm_subagent import SubagentSession
except (ImportError, ValueError):
    from async_causal import AsyncCausalClient
    from swarm_subagent import SubagentSession

logger = logging.getLogger("causal_slash.integrations.langchain")

# Optional LangChain imports with graceful degradation
try:
    from langchain_core.callbacks.base import AsyncCallbackHandler
    from langchain_core.tools import BaseTool, tool
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    class AsyncCallbackHandler:  # type: ignore
        pass
    class BaseTool:  # type: ignore
        pass
    def tool(*args, **kwargs):  # type: ignore
        def dec(fn):
            return fn
        return dec


def causal_paid_tool(
    client: AsyncCausalClient,
    session: SubagentSession,
    vendor_pk: bytes,
    cost_micro_usdc: int,
    dispatch_fn: Optional[Callable[[int, int], Any]] = None,
):
    """
    Decorator converting any function into a Causal-Slash paid tool.
    Prior to tool execution, the subagent settles a micro-cheque against the vendor.
    """
    def decorator(fn: Callable[..., Any]):
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            async def _default_dispatch(h: int, cum: int):
                logger.debug(
                    "Paid tool executed: h=%d, cum=%d micro-USDC for vendor %s",
                    h, cum, vendor_pk.hex()[:12] if isinstance(vendor_pk, bytes) else vendor_pk
                )
                return True

            active_dispatch = dispatch_fn if dispatch_fn is not None else _default_dispatch
            # Settle payment with subagent quota isolation (Axiom 1)
            await client.pay_and_stream(
                session=session,
                peer_pk=vendor_pk,
                amount_micro=cost_micro_usdc,
                dispatch_fn=active_dispatch,
            )
            return await fn(*args, **kwargs)

        if LANGCHAIN_AVAILABLE:
            return tool(wrapper)
        return wrapper

    return decorator


class CausalPaidTool:
    """
    Object-oriented wrapper for paid tools in LangChain/CrewAI.
    """

    def __init__(
        self,
        name: str,
        description: str,
        func: Callable[..., Any],
        client: AsyncCausalClient,
        session: SubagentSession,
        vendor_pk: bytes,
        cost_micro_usdc: int,
        dispatch_fn: Optional[Callable[[int, int], Any]] = None,
    ):
        self.name = name
        self.description = description
        self.func = func
        self.client = client
        self.session = session
        self.vendor_pk = vendor_pk
        self.cost_micro_usdc = cost_micro_usdc
        self.dispatch_fn = dispatch_fn

    async def ainvoke(self, input_data: Any, **kwargs: Any) -> Any:
        async def _default_dispatch(h: int, cum: int):
            return True

        active_dispatch = self.dispatch_fn if self.dispatch_fn is not None else _default_dispatch
        await self.client.pay_and_stream(
            session=self.session,
            peer_pk=self.vendor_pk,
            amount_micro=self.cost_micro_usdc,
            dispatch_fn=active_dispatch,
        )
        if asyncio.iscoroutinefunction(self.func):
            return await self.func(input_data, **kwargs)
        return self.func(input_data, **kwargs)


class AsyncCausalPaymentCallback(AsyncCallbackHandler):
    """
    LangChain callback handler: automatically settles streaming micro-cheques
    per tool execution or token batch.
    """

    def __init__(
        self,
        client: AsyncCausalClient,
        session: SubagentSession,
        vendor_pk: bytes,
        rate_per_call_micro: int = 100,
        dispatch_fn: Optional[Callable[[int, int], Any]] = None,
    ):
        super().__init__()
        self.client = client
        self.session = session
        self.vendor_pk = vendor_pk
        self.rate_per_call_micro = rate_per_call_micro
        self.dispatch_fn = dispatch_fn

    async def on_tool_start(
        self, serialized: Dict[str, Any], input_str: str, **kwargs: Any
    ) -> None:
        async def _default_dispatch(h: int, cum: int):
            return True

        active_dispatch = self.dispatch_fn if self.dispatch_fn is not None else _default_dispatch
        await self.client.pay_and_stream(
            session=self.session,
            peer_pk=self.vendor_pk,
            amount_micro=self.rate_per_call_micro,
            dispatch_fn=active_dispatch,
        )
