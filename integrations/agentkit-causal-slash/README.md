# @causal-slash/agentkit-action-provider
> Coinbase AgentKit Native Action Provider for Causal-Slash Protocol (Base L2)

## Overview
`@causal-slash/agentkit-action-provider` equips autonomous AI agents orchestrating via Coinbase AgentKit with sovereign, zero-gas Machine-to-Machine (M2M) micro-payment clearing on Base L2.

Agents authenticate and clear compute solely via 167-byte Session MAC micro-cheques backed by on-chain collateral deposited in `SwarmDelegationVault.sol` and `PerformanceCollateralVault.sol`. Zero Web2 API keys, zero custodial credit credentials, and zero intermediate blockchain gas transactions.

## Core Architectural Invariants
- Zero Web2 API Keys: Client agents authenticate via compressed secp256k1 public keys and 167-byte Session MAC wire micro-cheques (`X-Causal-Cheque`).
- Remote Sovereign Frontier Compute: Autonomous swarms stream micro-settlement directly to remote vendor nodes serving frontier inference and media APIs (Claude Opus 5.5, DeepSeek-V4-Pro, Gemini 4 Argon, Kling 4.0, ElevenLabs).
- 1.62 Microsecond Local Cheque Verification: C11 vendor daemon verifies signature and monotonic height in RAM at wire speed (>590,000 ops/second per core).
- In-RAM Kirchhoff Debt Netting: Reciprocal multi-agent obligations (inference, vector memory, web scraping) cancel out off-chain via Tarjan Strongly Connected Components (SCC), with 99.9875% volume compression in the empirical benchmark reported in the root README.md.
- O(1) Schnorr EOTS Slashing: Double-signing equivocations mathematically extract the offending private key in 320 microseconds, foreclosing their Base L2 collateral bond instantly.

## Installation
```bash
npm install @causal-slash/agentkit-action-provider zod
```

## Quickstart

```typescript
import { AgentKit } from "@coinbase/agentkit";
import { CausalSlashActionProvider } from "@causal-slash/agentkit-action-provider";

// 1. Initialize ActionProvider with Base Sepolia vault connection
const cslsProvider = new CausalSlashActionProvider({
  vaultAddress: "0x8faAD06ef5937Ad1019CD49f5Dcab36181e266A5",
  baseRpcUrl: process.env.BASE_RPC_URL || "https://sepolia.base.org"
});

// 2. Register into Coinbase AgentKit instance
const agentKit = await AgentKit.from({
  actionProviders: [cslsProvider]
});

// 3. Autonomous agents can now invoke sovereign tools:
// - causal_create_channel
// - causal_sign_stream_cheque
// - causal_invoke_paid_inference
// - causal_inspect_vault_bond
```

## Base Sepolia Contracts

Verified deployments on Base Sepolia (chain ID 84532; RPC `https://sepolia.base.org`):
- `PerformanceCollateralVault`: `0x8faAD06ef5937Ad1019CD49f5Dcab36181e266A5` (default vault; implements `vaults(address)`).
- `SwarmDelegationVault`: `0x901c98Da847DD24ff23FcC37B6D1549A17F12253` (hierarchical swarm delegation).

Constructor options `vaultAddress` and `baseRpcUrl` remain configurable. When using another network, configure both for that network. `BASE_RPC_URL`, when set, overrides the RPC URL used by vault inspection.

## Exposed Actions

### 1. `causal_create_channel`
Establishes a 128-bit Session MAC channel with a target vendor node on Base L2.
- Parameters: `vendorAddress` (secp256k1 public key), `depositUsdc` (collateral allocation), `vendorEndpoint` (optional HTTP URL).

### 2. `causal_sign_stream_cheque`
Signs a monotonic 167-byte wire packet (`csls_cheque_wire_t`) carrying cumulative micro-USDC balance and SipHash-128 MAC tag.
- Parameters: `vendorAddress`, `amountUsdc`, `purpose`.
- Returns: `chequeHex` (334 hex characters), `height`, `cumulativeSentUsdc`, `gasCost` ("0 wei").

### 3. `causal_invoke_paid_inference`
Autonomous end-to-end execution: signs the 167-byte micro-cheque and delivers it inside the `X-Causal-Cheque` HTTP header to a sovereign remote vendor node.
- Parameters: `vendorAddress`, `endpointUrl`, `model`, `prompt`, `costUsdc`.
- Returns: Verified remote response, monotonic settlement height, cumulative settled balance, and zero gas confirmation.

### 4. `causal_inspect_vault_bond`
Reads the master bond, allocated exposure, and free margin live from the Base L2 vault over JSON-RPC. Fails fast when the RPC endpoint or vault is unreachable; never returns synthetic balances.

## Vendor-Side Verification (CslsVendorNode)

Agents that operate sovereign vendor nodes use `CslsVendorNode` from the same package: constant-time session MAC verification, the O(1) equivocation trap run before the exposure gate, monotonic height enforcement, delta_v exposure capping, challenge recomputation, and algebraic key extraction (`sk = (s1 - s2) * (e1 - e2)^(-1) mod q`) producing fraud proofs for on-chain foreclosure.

## Session Bootstrap (C2 Gate)

Before the first 167-byte wire cheque, the provider derives `session_key = HMAC-SHA256(ecdh_x, nonce_BE || "CSLS-MAC-v1")` from the static-static ECDH secret and delivers the 95-byte SESSION_INIT packet to the vendor (POST /v1/session when an endpoint is configured). A raw ECDH x-coordinate is not a valid session key; MAC-mandating vendors reject such cheques with -24.

## Wire Cheque Layout (167 Bytes)
| Field | Offset | Length | Description |
| :--- | :--- | :--- | :--- |
| `magic` | 0 | 4 B | Protocol Magic (0x43534C53) |
| `type` | 4 | 1 B | Packet Type (0x01 = CHEQUE) |
| `agent_pk` | 5 | 33 B | Compressed secp256k1 Public Key of Agent |
| `vendor_pk` | 38 | 33 B | Compressed secp256k1 Public Key of Vendor |
| `height` | 71 | 8 B | Monotonic sequence counter $h$ (LE uint64) |
| `cumulative_amt` | 79 | 8 B | Cumulative volume in micro-USDC (LE uint64) |
| `challenge_e` | 87 | 32 B | Challenge scalar $e \pmod q$ |
| `sig_s` | 119 | 32 B | Schnorr EOTS signature scalar $s \pmod q$ |
| `mac` | 151 | 16 B | SipHash-2-4 / 128-bit Session MAC |
| **Total** | | **167 B** | **Zero gas wire packet** |

## License
Apache-2.0
