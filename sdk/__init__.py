# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Causal-Slash Protocol: Python SDK & Integrations (v0.3.0).
Zero-prepay streaming micropayments for autonomous AI agents on Base L2.
"""

from .causal_slash import (
    CausalAgentWallet,
    CausalVendorNode,
    Cheque,
    CslsCheque,
    ProcessResult,
    FraudProof,
    CSLS_MAGIC,
    CSLS_OK,
    CSLS_ERR_EXPOSURE_CAP,
    CSLS_ERR_FRAUD,
    CSLS_ERR_REPLAY,
    CSLS_ERR_OUT_OF_ORDER,
    CSLS_ERR_FORGED_HASH,
    CSLS_ERR_BAD_MAC,
    CSLS_ERR_NO_SESSION,
    CSLS_ERR_WAL_FATAL,
)
from .debt_cycle_mesh import (
    DebtCycleMesh,
    NettingSummary,
    MutualCloseAct,
    MutualCloseReceipt,
    MutualCloseCertificate,
    DebtCycleMeshError,
)
from .causal_agentkit import CausalAgentKit
from .agentkit_provider import CausalSlashActionProvider
from .slash_proxy import SlashSidecarProxy
from .guardrails import EdgeSafetyGuardrail
from .channel_store import (
    SqliteChannelStore,
    ChannelRecord,
    ChannelStoreLockedError,
    ChannelStoreError,
)
from .swarm_subagent import (
    SwarmDelegationVault,
    SubagentSession,
    SubagentQuotaExceededError,
    SpendRateLimitExceededError,
)
from .onchain_settler import (
    BaseOnChainSettler,
    OnChainSettlementError,
    TransactionRevertedError,
    TransactionTimeoutError,
)
from .async_causal import (
    AsyncChannelActor,
    AsyncCausalClient,
    CausalQueueFullError,
)
from .session import (
    CausalSession,
    AsyncCausalSession,
    BudgetExceededError,
)
from .integrations.decorators import (
    causal_paid,
    causal_paid_tool,
)
from .integrations.langchain import (
    CausalPaidTool,
    AsyncCausalPaymentCallback,
)
from .telemetry import (
    CausalMetrics,
    get_metrics,
)

__all__ = [
    "CausalAgentWallet",
    "CausalVendorNode",
    "Cheque",
    "CslsCheque",
    "ProcessResult",
    "FraudProof",
    "DebtCycleMesh",
    "NettingSummary",
    "MutualCloseAct",
    "MutualCloseReceipt",
    "MutualCloseCertificate",
    "DebtCycleMeshError",
    "CausalAgentKit",
    "CausalSlashActionProvider",
    "SlashSidecarProxy",
    "EdgeSafetyGuardrail",
    "SqliteChannelStore",
    "ChannelRecord",
    "ChannelStoreLockedError",
    "ChannelStoreError",
    "SwarmDelegationVault",
    "SubagentSession",
    "SubagentQuotaExceededError",
    "SpendRateLimitExceededError",
    "BaseOnChainSettler",
    "OnChainSettlementError",
    "TransactionRevertedError",
    "TransactionTimeoutError",
    "AsyncChannelActor",
    "AsyncCausalClient",
    "CausalQueueFullError",
    "CausalSession",
    "AsyncCausalSession",
    "BudgetExceededError",
    "causal_paid",
    "causal_paid_tool",
    "CausalPaidTool",
    "AsyncCausalPaymentCallback",
    "CausalMetrics",
    "get_metrics",
    "CSLS_MAGIC",
    "CSLS_OK",
    "CSLS_ERR_EXPOSURE_CAP",
    "CSLS_ERR_FRAUD",
    "CSLS_ERR_REPLAY",
    "CSLS_ERR_OUT_OF_ORDER",
    "CSLS_ERR_FORGED_HASH",
    "CSLS_ERR_BAD_MAC",
    "CSLS_ERR_NO_SESSION",
    "CSLS_ERR_WAL_FATAL",
]

__version__ = "0.3.0"
