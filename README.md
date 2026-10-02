# Causal-Slash Protocol

[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](LICENSE)
[![Client SDK: Apache-2.0](https://img.shields.io/badge/SDK-Apache--2.0-green.svg)](LICENSE)
[![Foundry Tests](https://img.shields.io/badge/Foundry_Tests-38%2F38_Passing-brightgreen?logo=solidity)](test/PerformanceCollateralVault.t.sol)
[![Base Sepolia](https://img.shields.io/badge/Base_Sepolia-0x33BD...775c-success?logo=ethereum)](https://sepolia.basescan.org/address/0x33BD2908a372cf6A533B75e79D3cAa754da8775c#code)
[![C11 Engine Latency](https://img.shields.io/badge/C11_Latency-2.52_%C2%B5s-blue)](src/causal_daemon.c)
[![Throughput](https://img.shields.io/badge/Throughput-396k_ops%2Fsec-orange)](src/causal_daemon.c)

> Sovereign high-frequency machine-to-machine streaming settlement on Base L2. Single shared bond, zero gas per request, sub-microsecond wire latency, ERC4626 yield-bearing collateral, and game-theoretic $O(1)$ Schnorr slashing.

---

## 1. System Overview

### What is Causal-Slash?
**Causal-Slash** is a high-throughput micro-settlement protocol operating directly at the L4 transport layer. It enables autonomous AI swarms, DePIN compute providers, and machine-to-machine services to stream payments per token or per API request with sub-microsecond execution latency and zero gas overhead during active streaming.

### Core Problem: Fragmented Liquidity & Idle Capital
In typical multi-agent architectures, an agent communicating with 50 external vendors (LLM providers, vector databases, web scrapers, GPU clusters) must deposit pre-funded balances into 50 separate centralized accounts:
* **$10 deposit × 50 vendors = $500 in locked idle capital** to execute cents worth of work.
* Funds remain in centralized custody on third-party servers with zero recovery upon counterparty downtime.
* Direct on-chain transactions are cost-prohibitive for continuous streaming, while bilateral state channels require dedicated liquidity locked per peer and suffer from route failures.

### The Solution: Single Shared Bond with Yield Streaming
Causal-Slash replaces fragmented deposits with a **single performance collateral bond on Base L2**:
1. **Zero-Gas Streaming:** The agent streams signed 151-byte binary micro-cheques peer-to-peer over raw TCP/QUIC sockets at ~2.5 µs local cryptographic latency.
2. **Yield-Streaming Collateral (ERC4626):** Unallocated margin in `PerformanceCollateralVault.sol` automatically generates yield in yield-bearing vaults (e.g. Morpho / Aave on Base) while maintaining an automated 20% liquid cash buffer for instant, zero-second unbonding.
3. **Economic Deterrence ($O(1)$ Slashing):** Equivocation (signing two conflicting cheques at the identical sequence height) algebraically reveals the agent's private key. Anyone can submit this mathematical proof to Base L2 to foreclose the bond, making double-spend attacks strictly negative-EV ($\mathbb{E}[\text{Payoff}] < 0$, $\text{ROI} \le -95\%$).

---

## 2. Protocol Architecture & Invariants

```mermaid
flowchart TD
    subgraph Base["Base L2 Settlement"]
        Vault["PerformanceCollateralVault.sol\n(Single Shared Bond)"]
        YieldPool["ERC4626 Yield Pool\n(Morpho / Aave on Base)"]
        SlashingEngine["Slashing Waterfall\n(Commit-Reveal Protection)"]
    end

    subgraph AgentMesh["Autonomous Agent Mesh"]
        AgentWallet["Agent Runtime\n(Monotonic Counter, Nonce Derivation)"]
        SlashProxy["SlashProxy Sidecar\n(OpenAI / Anthropic Interceptor)"]
    end

    subgraph Infrastructure["Resource Providers & MEV Searchers"]
        Vendor["Vendor Node (GPU / LLM / Data)\n(Hotpath Ring Buffer Verification)"]
        Bloodhound["Schnorr Bloodhound MEV Daemon\n(35 ns Equivocation Hunter)"]
    end

    Vault <-->|Auto-Rebalance & Harvest| YieldPool
    Vault -->|Anchors Collateral| AgentWallet
    AgentWallet -->|Local HTTP Requests| SlashProxy
    SlashProxy -->|151-Byte Binary Stream (~2.5 µs)| Vendor
    SlashProxy -.->|Broadcast / Wire Tap| Bloodhound
    Bloodhound -->|Commit & Reveal Fraud Proof| SlashingEngine
    SlashingEngine -->|15% Guaranteed Finder Bounty| Bloodhound
    SlashingEngine -->|Restitution for Damages| Vendor
```

### 2.1 Cryptographic Key Derivation & Challenge Formula
Let $\mathbb{G}$ be secp256k1 of prime order $q$ with base generator $G$. An agent locks collateral $B$ in `PerformanceCollateralVault.sol` on Base L2 and registers public key $PK = sk \cdot G$.

For sequential operational heights $h \in \mathbb{N}$:
$$k_h = \text{HMAC-SHA256}(sk, h) \pmod q$$

To stream a payment cheque for sequence height $h$ binding vendor, height, and cumulative micro-USDC:
$$e_h = \text{SHA256}(PK_{\text{agent}} \parallel PK_{\text{vendor}} \parallel h \parallel \text{cumAmount}) \pmod q$$
$$s_h = (k_h + e_h \cdot sk) \pmod q$$

### 2.2 Optimistic Bounded Credit ($\delta_v$) & Algebraic Key Extraction
1. **Hotpath Processing:** The vendor accepts incoming cheques within an unconfirmed local credit buffer $\delta_v \le \$1.00$ without blocking on elliptic curve scalar multiplications.
2. **Equivocation Detection:** If an agent signs two distinct cheques $M_1 \neq M_2$ at the identical height $h$:
   $$s_1 = k_h + e_1 \cdot sk \pmod q$$
   $$s_2 = k_h + e_2 \cdot sk \pmod q$$
   $$s_1 - s_2 = (e_1 - e_2) \cdot sk \pmod q$$
3. **$O(1)$ Algebraic Extraction:**
   $$sk = (s_1 - s_2) \cdot (e_1 - e_2)^{-1} \pmod q$$
   The recovered $sk$ is submitted to Base L2 via commit-reveal, foreclosing the agent's collateral bond.

### 2.3 Slashing Priority Waterfall
Foreclosed collateral is liquidated according to strict protocol invariants:
1. **15% Guaranteed Finder Bounty:** Paid to the searcher or vendor submitting the valid fraud proof.
2. **Restitution Pool (85%):** Quarantined to compensate honest vendors who suffered exposure.
3. **Residual Surplus Split (60% / 40%):**
   * 60% directed to the Protocol Insurance Reserve.
   * 40% directed to the Protocol Treasury.

---

## 3. Autonomous MEV Searcher: Schnorr Bloodhound

The protocol includes a high-performance MEV searcher daemon (`src/schnorr_bloodhound.c`) designed for independent arbitrageurs and searchers.

### Mechanics:
* **Microsecond Detection:** Uses a 65,536-entry lock-free hash ring to detect sequence collisions across network streams in ~35 nanoseconds.
* **Frontrunning Mitigation:** Constructs a standard Ethereum Keccak-256 commit-reveal payload (`commitFraudProof` $\to$ `revealAndSlash`), locking the 15% bounty to the searcher's address before revealing the extracted secret key on-chain.

### Building & Running the Bloodhound:
```bash
# Compile and run bloodhound under AddressSanitizer and UndefinedBehaviorSanitizer
make test-bloodhound
```

---

## 4. SlashProxy: Zero-Code Sidecar Integration

`SlashProxy` (`sdk/slash_proxy.py`) is a local reverse proxy that allows existing agent frameworks (such as Coinbase AgentKit, ElizaOS, CrewAI, AutoGen, and LangChain) to use Causal-Slash without modifying their core LLM client code.

### Integration Flow:
1. Start the proxy sidecar:
   ```bash
   python3 -c "
   from sdk.causal_slash import CausalAgentWallet
   from sdk.slash_proxy import SlashSidecarProxy

   wallet = CausalAgentWallet(agent_private_key=b'\\x77'*32)
   vendor_pk = b'\\x02' + b'\\x33'*32
   proxy = SlashSidecarProxy(wallet, vendor_pk, price_per_request_usdc=0.0005, bind_port=8999)
   proxy.start()
   print('SlashProxy listening on http://127.0.0.1:8999')
   import time; time.sleep(86400)
   "
   ```
2. Direct standard OpenAI / Anthropic client SDK calls to `http://127.0.0.1:8999`. The sidecar intercepts HTTP completion calls and translates them into streaming 151-byte CSLS binary cheques over L4.

---

## 5. Verified Empirical Benchmarks

Benchmarks executed on x86_64 Linux (AMD Ryzen / Intel Xeon environment):

| Metric | Causal-Slash (L4 Stream) | Direct Base L2 Tx | Centralized SaaS Billing | Bilateral State Channels |
|---|---|---|---|---|
| **Cryptographic Overhead** | **2.52 µs (Sign + Verify)** | ~1,200 µs (Node ECDSA) | None (API key hash) | ~500 µs (HTLC verification) |
| **Network Latency** | **Direct L4 TCP / QUIC** | RPC roundtrip to Sequencer | HTTPS REST / SSE | Multi-hop onion routing |
| **Intermediate Gas Fee** | **$0.000000 (Zero gas)** | $0.001 – $0.05 per TX | $0.00 (Custodial SaaS) | $0.0002 – $0.001 routing fee |
| **Capital Efficiency** | **1x Shared Bond (Base)** | 1x Balance | Nx Fragmented Balances | Nx Locked Liquidity |
| **Unbonding / Exit** | **0 Seconds (Instant)** | Immediate | Manual support request | 24 Hours – 7 Days |
| **Yield Generation** | **ERC4626 Automated Pool** | 0% (Idle balance) | 0% (Vendor balance) | 0% (Channel balance) |

### High-Frequency Quantile Distribution (`benchmarks/slashbench.py`):
```text
Cheque Verification Latency (Vendor Hotpath):
  p50 (median):  2.77 µs
  p95:           3.40 µs
  p99:           6.21 µs

Cheque Signing Latency (Agent Hotpath):
  p50 (median):  8.10 µs
  p95:          11.34 µs
  p99:          15.98 µs

End-to-End Cryptographic Throughput: 85,341 ops/sec (Python FFI) / 396,825 ops/sec (Pure C11)
```

---

## 6. On-Chain Verification & Test Matrix

The protocol is validated through a comprehensive multi-tier test suite with 100% pass rate:

### 1. Foundry Test Suites (38/38 Passing):
* `test/PerformanceCollateralVault.t.sol`: 20 unit, state-machine, and fuzzing invariant tests.
* `test/AdversarialExploits.t.sol`: 5 adversarial exploit tests (signature malleability, replay, self-slashing economics).
* `test/YieldStreamingCollateral.t.sol`: 4 ERC4626 yield-bearing collateral and liquidity buffer tests.
* `test/CompetitorGriefingAttacks.t.sol`: 5 MEV frontrunning and DoS griefing resistance tests.
* `test/ReliabilityInvariantsAudit.t.sol`: 4 unbonding race and haircut solvency tests.

### 2. C Core Memory & Concurrency Audits (ASan & UBSan):
* `make test`: High-frequency cryptographic engine, equivocation trap, and TCP loopback tests.
* `make test-asan`: Full memory sanitizer check ensuring zero memory leaks or buffer overflows.
* `make test-bloodhound`: MEV searcher Keccak-256 vector verification and equivocation extraction test.
* `make test-redteam`: Integer overflow, height wraparound, and packet corruption fuzzing.

### 3. Python SDK & Integration Tests:
* `python3 test/test_slash_proxy.py`: Verification of HTTP proxy sidecar and token accounting.
* `python3 benchmarks/slashbench.py`: Empirical p50, p95, and p99 profiling.

---

## 7. Repository Structure

```
├── contracts/                                # Solidity Smart Contracts (Base L2)
│   ├── PerformanceCollateralVault.sol        # Vault, ERC4626 Yield Pool & Slashing Engine (BUSL-1.1)
│   ├── MockERC4626Vault.sol                  # Mock ERC4626 yield-bearing vault for testing
│   └── MockUSDC.sol                          # Mock USDC (6 decimals)
├── src/                                      # C11 Sovereign Engine
│   ├── causal_daemon.c                       # Core cryptographic engine and wire daemon (BUSL-1.1)
│   ├── causal_daemon.h                       # Binary framing and C-FFI header (BUSL-1.1)
│   ├── schnorr_bloodhound.c                  # Autonomous MEV searcher engine (Apache-2.0)
│   └── schnorr_bloodhound.h                  # Bloodhound definitions (Apache-2.0)
├── sdk/                                      # Developer SDK & Sidecars (Apache-2.0)
│   ├── causal_slash.py                       # Python FFI bindings to C11 engine
│   └── slash_proxy.py                        # Zero-code reverse proxy sidecar for agent swarms
├── test/                                     # Comprehensive Test Suites
│   ├── PerformanceCollateralVault.t.sol      # Core vault unit and fuzz tests
│   ├── AdversarialExploits.t.sol             # Adversarial exploit test suite
│   ├── YieldStreamingCollateral.t.sol        # ERC4626 yield and buffer tests
│   ├── CompetitorGriefingAttacks.t.sol       # MEV griefing and race tests
│   ├── ReliabilityInvariantsAudit.t.sol      # Solvency and haircut invariant tests
│   ├── run_full_system_e2e_test.js           # 10-phase end-to-end on-chain test
│   ├── test_slash_proxy.py                   # Python proxy integration tests
│   └── c/                                    # C Sanitizer & Concurrency Audits
│       ├── test_schnorr_bloodhound.c         # MEV hound test
│       ├── test_redteam_exploit.c            # Malformed packet fuzzing
│       ├── test_competitor_griefing.c        # Griefing resilience audit
│       └── test_reliability_audit.c          # Concurrency and race tests
├── benchmarks/                               # Empirical Profiling
│   └── slashbench.py                         # High-frequency quantile latency profiler
├── examples/                                 # Executable Quickstarts
│   ├── quickstart_agent.py                   # Agent micro-payment quickstart
│   └── full_system_demo.py                   # End-to-end key extraction demo
├── scripts/                                  # Deployment Scripts & Receipts
│   ├── deploy_base_sepolia.js                # Base Sepolia contract deployer
│   ├── deploy_arbitrum_sepolia.js            # Arbitrum Sepolia contract deployer
│   └── deployment_receipt_*.json             # On-chain verified deployment receipts
├── Makefile                                  # Build and audit orchestration
├── LICENSE                                   # Dual Licensing Specification
└── README.md                                 # Technical Specification
```

---

## 8. Quickstart & Verification Commands

### 1. Execute EVM Solidity Test Suite:
```bash
forge test -vvv
```
Expected: `Ran 5 test suites: 38 tests passed, 0 failed, 0 skipped`

### 2. Run C11 Cryptographic Daemon & Socket Benchmarks:
```bash
make test
```
Expected: `Latency per End-to-End Cheque (Sign + Verify): ~2.52 µs`

### 3. Run MEV Schnorr Bloodhound Searcher:
```bash
make test-bloodhound
```
Expected: `All Schnorr Bloodhound Tests Successfully Passed`

### 4. Run Sidecar Proxy Tests & High-Frequency Profiler:
```bash
python3 test/test_slash_proxy.py
python3 benchmarks/slashbench.py
```

---

## 9. Deployed Contracts (Base Sepolia)

* **Network:** Base Sepolia (Chain ID `84532`)
* **Contract:** `PerformanceCollateralVault`
* **Address:** [`0x33BD2908a372cf6A533B75e79D3cAa754da8775c`](https://sepolia.basescan.org/address/0x33BD2908a372cf6A533B75e79D3cAa754da8775c#code)
* **Settlement Asset:** Base Sepolia USDC (`0x036CbD53842c5426634e7929541eC2318f3dCF7e`)

---

## 10. Licensing

The Causal-Slash Protocol repository utilizes a hybrid licensing model:
* **Core Protocol Infrastructure (`contracts/` and `src/causal_daemon.*`):** Licensed under the **Business Source License 1.1 (BUSL-1.1)**. Free for non-production use, testing, research, and testnet deployments. Converts to the **Apache License, Version 2.0** on **October 1, 2028**.
* **Client SDK, MEV Tools & Examples (`sdk/`, `src/schnorr_bloodhound.*`, `benchmarks/`, `examples/`):** Permanently licensed under the **Apache License, Version 2.0**. Free and open for commercial and non-commercial integration by any autonomous agent framework, MEV searcher, or application.

See [LICENSE](LICENSE) for complete legal terms.
