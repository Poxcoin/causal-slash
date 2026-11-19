# @elizaos/plugin-causal-slash
> ElizaOS Plugin for Causal-Slash Protocol - Streaming Per-Token M2M Micro-Settlement Backed by Base L2 Collateral Vaults

## Overview
`@elizaos/plugin-causal-slash` integrates Causal-Slash Protocol into autonomous agents built with ElizaOS (ai16z).

It enables agents to purchase remote frontier LLM inference, vector retrieval, and web intelligence on a true per-token streaming basis. Settlement occurs off-chain in RAM via monotonic 167-byte Session MAC micro-cheques backed by smart contract vaults on Base L2 (`PerformanceCollateralVault.sol`, `SwarmDelegationVault.sol`).

## Architectural Invariants
- Zero Web2 API Keys: Autonomous agents do not require SaaS API keys, pre-paid subscriptions, or centralized billing credentials.
- Pure Remote Sovereign Inference: Autonomous swarms stream payments to remote vendor nodes serving frontier inference and media APIs (Claude Opus 5.5, DeepSeek-V4-Pro, Gemini 4 Argon, Kling 4.0).
- True Per-Token Streaming: Settlement progresses with each generated token, bounded by an optimistic credit window $\Delta v$ ($1.00 USDC default).
- In-RAM Kirchhoff Debt Netting: Reciprocal multi-agent obligations cancel out off-chain via Tarjan Strongly Connected Components (SCC), with 99.9875% volume compression in the empirical benchmark reported in the root README.md and no on-chain gas for in-memory netting.
- Zero Emojis: Protocol telemetry and logs adhere to clean industrial text tags: `[OK]`, `[FAIL]`, `[INFO]`.

## Installation
```bash
npm install @elizaos/plugin-causal-slash
```

## Plugin Registration

```typescript
import { AgentRuntime } from "@elizaos/core";
import { causalSlashPlugin } from "@elizaos/plugin-causal-slash";

const runtime = new AgentRuntime({
  plugins: [causalSlashPlugin]
});
```

## Base Sepolia Contracts

Verified deployments on Base Sepolia (chain ID 84532; RPC `https://sepolia.base.org`):
- `PerformanceCollateralVault`: `0x8faAD06ef5937Ad1019CD49f5Dcab36181e266A5` (default service vault; implements `vaults(address)`).
- `SwarmDelegationVault`: `0x901c98Da847DD24ff23FcC37B6D1549A17F12253` (hierarchical swarm delegation).

The optional `vaultAddress` constructor argument on `CausalSettlementService` overrides the default. Set `BASE_RPC_URL` to the RPC endpoint for the vault's network when reading live collateral state.

## Included Actions

### 1. `STREAM_TOKEN_SETTLEMENT`
Signs a 167-byte Session MAC micro-cheque for generated prompt/completion tokens and verifies monotonic sequence progression ($h_{k+1} > h_k$).
- Similes: `STREAM_M2M_PAYMENT`, `PAY_FOR_TOKENS`, `SETTLE_REMOTE_COMPUTE`.

### 2. `RECONCILE_KIRCHHOFF_MESH`
Executes in-RAM cycle cancellation across multi-agent bilateral obligations, bypassing Base L2 gas fees while keeping all parties 100% solvent.
- Similes: `NET_MULTIAGENT_DEBT`, `CANCEL_DEBT_CYCLES`, `RUN_KIRCHHOFF_NETTING`.

### 3. `GET_CHANNEL_BALANCE`
Inspects active streaming sequence heights, cumulative micro-USDC spent, and remaining credit margin against a sovereign vendor node.

## State Provider: `cslsCollateralProvider`
Automatically feeds live Base L2 vault collateral metrics into the Eliza agent's prompt context:
- Agent secp256k1 public key
- Master bond locked on Base L2
- Free margin available
- 80/20 Morpho/Aave yield buffer distribution
- Axiom 1 Merkle subagent quota protection ($5 - $10 leaves)

## License
Apache-2.0
