# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Universal AI Agent Decorators: @causal_paid and @causal_paid_tool.

Enables any AI function or agent tool (LangChain, CrewAI, AutoGen, Pydantic-AI)
to require real-time cryptographic CSLS micro-payments:
- Automatic Circuit Breaker spend-rate protection
- Subagent quota verification and reservation
- Works transparently with both sync and async functions
- Supports direct peer-to-peer vendor node verification
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import logging
from typing import TYPE_CHECKING, Any, Callable, Dict, Optional, Union

if TYPE_CHECKING:
    from ..causal_slash import CausalAgentWallet, CausalVendorNode, Cheque, DebtCycleMesh
    from ..swarm_subagent import SubagentSession

logger = logging.getLogger("causal_slash.integrations.decorators")


def causal_paid(
    price_usdc: float = 0.001,
    vendor_pk: Optional[Union[str, bytes]] = None,
    wallet: Optional[CausalAgentWallet] = None,
    vendor_node: Optional[CausalVendorNode] = None,
    subagent_session: Optional[SubagentSession] = None,
    mesh: Optional[DebtCycleMesh] = None,
    session_mac: bool = False,
):
    """
    Universal decorator requiring a CSLS streaming micro-payment prior to function execution.
    
    Can be applied to synchronous or asynchronous functions, tool handlers, and agent methods.
    
    Usage:
        @causal_paid(price_usdc=0.002, vendor_pk=vendor.public_key, wallet=my_wallet)
        async def heavy_scrape_tool(url: str) -> str:
            return await scrape(url)
    """
    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        price_micro = int(round(price_usdc * 1e6))

        def _execute_payment(
            active_wallet: Optional[CausalAgentWallet],
            active_vendor_pk: Optional[Union[str, bytes]],
            active_subagent: Optional[SubagentSession],
            active_vendor_node: Optional[CausalVendorNode],
            active_mesh: Optional[DebtCycleMesh],
        ) -> Optional[Cheque]:
            if active_wallet is None:
                raise ValueError("Causal-Slash payment failed: No wallet provided for @causal_paid function")

            v_pk = active_vendor_pk
            if v_pk is None and active_vendor_node is not None:
                v_pk = active_vendor_node.public_key
            if v_pk is None:
                raise ValueError("Causal-Slash payment failed: No vendor_pk provided for @causal_paid function")

            # 1. Quota & Circuit Breaker Check
            if active_subagent is not None:
                active_subagent.check_spend_rate(price_micro)
                active_subagent.check_and_reserve(price_micro)

            # 2. Sign cryptographic cheque
            try:
                cheque = active_wallet.sign_cheque(
                    v_pk,
                    amount_usdc=price_usdc,
                    session_mac=session_mac,
                )
            except Exception:
                if active_subagent is not None:
                    # Cancel uncommitted reservation
                    pass
                raise

            # 3. Commit spend
            if active_subagent is not None:
                active_subagent.commit_spend(price_micro)

            # 4. Peer node local delivery if vendor_node is attached
            if active_vendor_node is not None:
                res = active_vendor_node.process_cheque(cheque)
                if not res.accepted:
                    raise RuntimeError(f"Cheque rejected by vendor: {res.error_message}")

            # 5. Ingest into DebtCycleMesh if attached
            if active_mesh is not None:
                active_mesh.record_cheque(cheque)

            logger.debug(
                "Paid function '%s' settled: h=%d ($%.6f USDC)",
                fn.__name__, cheque.height, price_usdc
            )
            return cheque

        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                # Extract dynamic overrides from kwargs if passed
                dyn_wallet = kwargs.pop("csls_wallet", wallet)
                dyn_vendor_pk = kwargs.pop("csls_vendor_pk", vendor_pk)
                dyn_subagent = kwargs.pop("csls_subagent", subagent_session)
                dyn_vendor_node = kwargs.pop("csls_vendor_node", vendor_node)
                dyn_mesh = kwargs.pop("csls_mesh", mesh)

                loop = asyncio.get_running_loop()
                cheque = await loop.run_in_executor(
                    None,
                    _execute_payment,
                    dyn_wallet,
                    dyn_vendor_pk,
                    dyn_subagent,
                    dyn_vendor_node,
                    dyn_mesh,
                )

                result = await fn(*args, **kwargs)
                if isinstance(result, dict) and cheque is not None:
                    result["_csls_cheque_height"] = cheque.height
                return result

            async_wrapper._is_causal_paid = True  # type: ignore
            async_wrapper._csls_price = price_usdc  # type: ignore
            try:
                async_wrapper.__signature__ = inspect.signature(fn)  # type: ignore
            except (ValueError, TypeError):
                pass
            return async_wrapper

        else:
            @functools.wraps(fn)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                dyn_wallet = kwargs.pop("csls_wallet", wallet)
                dyn_vendor_pk = kwargs.pop("csls_vendor_pk", vendor_pk)
                dyn_subagent = kwargs.pop("csls_subagent", subagent_session)
                dyn_vendor_node = kwargs.pop("csls_vendor_node", vendor_node)
                dyn_mesh = kwargs.pop("csls_mesh", mesh)

                cheque = _execute_payment(
                    dyn_wallet,
                    dyn_vendor_pk,
                    dyn_subagent,
                    dyn_vendor_node,
                    dyn_mesh,
                )

                result = fn(*args, **kwargs)
                if isinstance(result, dict) and cheque is not None:
                    result["_csls_cheque_height"] = cheque.height
                return result

            sync_wrapper._is_causal_paid = True  # type: ignore
            sync_wrapper._csls_price = price_usdc  # type: ignore
            try:
                sync_wrapper.__signature__ = inspect.signature(fn)  # type: ignore
            except (ValueError, TypeError):
                pass
            return sync_wrapper

    return decorator


# Alias for explicit AI Tool naming convention
causal_paid_tool = causal_paid
