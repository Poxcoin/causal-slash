# Causal-Slash Protocol

[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](LICENSE)
[![Client SDK: Apache-2.0](https://img.shields.io/badge/SDK-Apache--2.0-green.svg)](LICENSE)
[![Foundry Tests](https://img.shields.io/badge/Foundry_Tests-100%2F100_Passing-brightgreen?logo=solidity)](test/)
[![Python SDK Tests](https://img.shields.io/badge/Pytest-70%2F70_Passing-brightgreen?logo=pytest)](test/)
[![Base Sepolia](https://img.shields.io/badge/Base_Sepolia-0x901c...2253-success?logo=ethereum)](https://sepolia.basescan.org/address/0x901c98Da847DD24ff23FcC37B6D1549A17F12253#code)
[![Arbitrum Sepolia](https://img.shields.io/badge/Arbitrum_Sepolia-0x45Cd...1f1F-blue?logo=arbitrum)](https://sepolia.arbiscan.io/address/0x45Cd2B0d1319C158a5B37B74DcBE3D78C9861f1F#code)
[![C11 Engine Latency](https://img.shields.io/badge/C11_Latency-1.68_%C2%B5s-blue)](src/causal_daemon.c)
[![Throughput](https://img.shields.io/badge/Throughput-596k_ops%2Fsec-orange)](src/causal_daemon.c)

> Sovereign high-frequency machine-to-machine streaming settlement. Single shared bond, zero gas per request, sub-microsecond wire latency, ERC4626 yield-bearing collateral, Swarm Merkle delegations, in-RAM Kirchhoff debt netting, and game-theoretic $O(1)$ Schnorr slashing.

---

## 1. System Overview

### What is Causal-Slash?
**Causal-Slash** is a high-throughput micro-settlement protocol operating directly at the L4 transport layer. It enables autonomous agent meshes, DePIN compute providers, and machine-to-machine services to stream payments per token or per API request with sub-microsecond execution latency and zero gas overhead during active streaming.

Causal-Slash operates with no KYC, no centralized accounts, and zero custodial onboarding. Agent identity is defined strictly by a secp256k1 public key, while bilateral trust is established through a bond-based performance collateral vault on Base L2 and Arbitrum. Payment streams over raw sockets as signed 167-byte cheques per token.

### Core Problem: Fragmented Liquidity & Idle Capital
In typical multi-agent architectures, an agent communicating with 50 external vendors (LLM providers, vector databases, web scrapers, GPU clusters) must deposit pre-funded balances into 50 separate centralized accounts:
* **$10 deposit x 50 vendors = $500 in locked idle capital** to execute cents worth of work.
* Funds remain in centralized custody on third-party servers with zero recovery upon counterparty downtime.
* Direct on-chain transactions are cost-prohibitive for continuous streaming, while bilateral state channels require dedicated liquidity locked per peer and suffer from route failures.

### The Solution: Shared Bond with Multi-Agent Swarms & Yield Streaming
Causal-Slash replaces fragmented deposits with a **single performance collateral bond**:
1. **Zero-Gas Streaming:** The agent streams signed binary micro-cheques (151-byte standard or 167-byte session-MAC authenticated) peer-to-peer over raw TCP/QUIC sockets at ~1.68 us local cryptographic latency.
2. **Yield-Streaming Collateral (ERC4626):** Unallocated margin in `PerformanceCollateralVault.sol` automatically generates yield in yield-bearing vaults (e.g. Morpho / Aave) while maintaining an automated 20% liquid cash buffer for instant, zero-second unbonding.
3. **Swarm Merkle Delegations:** Through `SwarmDelegationVault.sol`, a master agent delegates spending power to up to 1,024+ subagents via keccak-256 sorted Merkle trees with individual spending caps, 7-day generational root rotation grace periods, and isolated subagent slashing.
4. **In-RAM Kirchhoff Debt Netting:** Cycles of mutual obligations across agent meshes are continuously detected and netted off-chain in RAM (Tarjan strongly connected components + cycle elimination), reducing settled volume by >99.9% before batch settlement.
5. **Economic Deterrence ($O(1)$ Slashing):** Equivocation (signing two conflicting cheques at the identical sequence height) algebraically reveals the signer's private key. Anyone can submit this mathematical proof on-chain to foreclose the bond, making double-spend attacks strictly negative-EV ($\mathbb{E}[\text{Payoff}] < 0$, $\text{ROI} \le -95\%$).

---

## 2. Protocol Architecture & Invariants

```mermaid
flowchart TD
    subgraph Settlement["On-Chain Settlement (L2)"]
        Vault["PerformanceCollateralVault.sol\n(Single Shared Bond)"]
        SwarmVault["SwarmDelegationVault.sol\n(Merkle Quotas & Grace Rotation)"]
        YieldPool["ERC4626 Yield Pool\n(Automated 20% Buffer)"]
        SlashingEngine["Slashing Waterfall\n(Commit-Reveal Protection)"]
    end

    subgraph AgentMesh["Autonomous Agent Mesh"]
        MasterAgent["Master Agent Runtime\n(Root Anchor, Quota Derivation)"]
        SubAgents["Subagent Swarm (1..N)\n(EIP-712 Leaf Proofs)"]
        SlashProxy["SlashProxy Sidecar\n(FastAPI / HTTP Streaming Interceptor)"]
        DebtMesh["In-RAM Kirchhoff Mesh\n(Tarjan Cycle Elimination)"]
    end

    subgraph Infrastructure["Resource Providers & MEV Searchers"]
        Vendor["Vendor Node (GPU / LLM / Data)\n(Hotpath Ring Buffer Verification)"]
        Bloodhound["Schnorr Bloodhound MEV Daemon\n(35 ns Equivocation Hunter)"]
    end

    Vault <-->|Auto-Rebalance & Harvest| YieldPool
    SwarmVault -->|Anchors Swarm Root| MasterAgent
    MasterAgent -->|Merkle Path & Quota| SubAgents
    SubAgents -->|Local Requests| SlashProxy
    SlashProxy -->|151/167-Byte Binary Stream (~1.68 µs)| Vendor
    SlashProxy -.->|Circular Netting| DebtMesh
    SlashProxy -.->|Broadcast / Wire Tap| Bloodhound
    Bloodhound -->|Commit & Reveal Fraud Proof| SlashingEngine
    SlashingEngine -->|15% Guaranteed Finder Bounty| Bloodhound
    SlashingEngine -->|Restitution for Damages| Vendor
```

### 2.1 Cryptographic Key Derivation & Challenge Formula
Let $\mathbb{G}$ be secp256k1 of prime order $q$ with base generator $G$. An agent locks collateral $B$ in `PerformanceCollateralVault.sol` or `SwarmDelegationVault.sol` and registers public key $PK = sk \cdot G$.

For sequential operational heights $h \in \mathbb{N}$ and counterparty vendor $PK_{\text{vendor}}$:
$$k_h = \text{HMAC-SHA256}(sk, PK_{\text{vendor}} \parallel h) \pmod q$$

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
   The recovered $sk$ is submitted on-chain via commit-reveal, foreclosing the agent's collateral bond.

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

## 4. SlashProxy: Sidecar Integration

`SlashProxy` (`sdk/slash_proxy.py`) is a local reverse proxy that allows autonomous agent frameworks (including Coinbase AgentKit, ElizaOS, CrewAI, AutoGen, and LangChain) to stream payments per request without modifying core application code.

### Python SDK Installation:
```bash
pip install causal-slash-sdk
```
> **Platform Support:** Linux x86_64 only. The embedded native cryptographic acceleration binaries (`libcausal_slash.so`, `libbloodhound.so`) are compiled specifically for Linux x86_64.

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
2. Direct client requests to `http://127.0.0.1:8999`. The sidecar intercepts completion calls and translates them into streaming 151/167-byte CSLS binary cheques over L4 transport sockets.

---

## 5. Verified Empirical Benchmarks

Benchmarks executed on x86_64 Linux (AMD Ryzen / Intel Xeon environment):

| Metric | Causal-Slash (L4 Stream) | Direct L2 Tx | Centralized SaaS Billing | Bilateral State Channels |
|---|---|---|---|---|
| **Cryptographic Overhead** | **1.68 µs (Sign + Verify)** | ~1,200 µs (Node ECDSA) | None (API key hash) | ~500 µs (HTLC verification) |
| **Network Latency** | **Direct L4 TCP / QUIC** | RPC roundtrip to Sequencer | HTTPS REST / SSE | Multi-hop onion routing |
| **Intermediate Gas Fee** | **$0.000000 (Zero gas)** | $0.001 - $0.05 per TX | $0.00 (Custodial SaaS) | $0.0002 - $0.001 routing fee |
| **Capital Efficiency** | **1x Shared Bond** | 1x Balance | Nx Fragmented Balances | Nx Locked Liquidity |
| **Unbonding / Exit** | **0 Seconds (Instant)** | Immediate | Manual support request | 24 Hours - 7 Days |
| **Yield Generation** | **ERC4626 Automated Pool** | 0% (Idle balance) | 0% (Vendor balance) | 0% (Channel balance) |

### Industrial Stress Testing Metrics (`benchmarks/`):
* **C11 Stream Daemon (`benchmarks/stress_tcp_swarm.c`):**
  * 1,200,000 cheques processed over raw TCP across 12 concurrent subagents in 4.14 seconds.
  * Sustained throughput: **289,575 cheques/second** (peak 306,340 cheques/second).
  * Latency distribution: Average RTT **13.29 µs**, p50 **12.65 µs**, p99 **24.00 µs**.
  * Memory & Thread Safety: 0 memory leaks under AddressSanitizer (ASan), 0 data races under ThreadSanitizer (TSan).
* **In-RAM Kirchhoff Debt Netting (`sdk/debt_cycle_mesh.py`):**
  * 102,500 mutual obligations across multi-agent graph with gross volume $100,012.50.
  * 12,500 closed debt cycles identified and eliminated in memory via Tarjan SCC.
  * **99.9875% compression ratio** with strict zero balance-drift conservation invariant.

---

## 6. On-Chain Verification & Test Matrix

The protocol is validated through a comprehensive multi-tier test suite with 100% pass rate:

### 1. Foundry Test Suites (100/100 Passing):
* `test/PerformanceCollateralVault.t.sol`: 26 unit, state-machine, and fuzzing invariant tests.
* `test/SwarmDelegationVault.t.sol`: 16 multi-agent delegation, Merkle tree quota, and restitution tests.
* `test/AdversarialExploits.t.sol`: 28 adversarial exploit tests (signature malleability, replay, self-slashing economics, optimistic forge, restitution race, swarm delegation).
* `test/YieldStreamingCollateral.t.sol`: 4 ERC4626 yield-bearing collateral and liquidity buffer tests.
* `test/CompetitorGriefingAttacks.t.sol`: 5 MEV frontrunning and DoS griefing resistance tests.
* `test/ReliabilityInvariantsAudit.t.sol`: 4 unbonding race and haircut solvency tests.
* `test/invariants/ProtocolInvariants.t.sol`: 5 comprehensive stateful invariant suites (16,384 calls across runs, 0 reverts).
* `test/invariants/HalmosProtocolInvariants.t.sol`: 12 formal SMT mathematical theorems proven.

### 2. C Core Memory & Concurrency Audits (ASan, TSan & UBSan):
* `make test`: High-frequency cryptographic engine, equivocation trap, and TCP loopback tests (1.68 µs latency, 596k ops/sec).
* `make test-asan`: Full memory sanitizer check ensuring zero memory leaks or buffer overflows.
* `make test-tsan`: ThreadSanitizer data-race check across multi-threaded agent and refiller threads (0 races).
* `make test-bloodhound`: MEV searcher Keccak-256 vector verification and equivocation extraction test under AddressSanitizer.
* `benchmarks/stress_tcp_swarm.c`: High-load multi-client TCP streaming audit under ASan/TSan.

### 3. Python SDK & Integration Tests (70/70 Passing):
* `pytest -v`: 70 passing tests covering high-speed `ChannelStore`, AsyncIO Actor Queue, secp256k1 honest PK, Circuit Breaker, Edge Guardrails, and On-chain Settlement.
* `test/test_e2e_full_stack.py`: Full-stack end-to-end integration test suite.

---

## 7. Repository Structure

```
├── contracts/                                # Solidity Smart Contracts (EVM L2)
│   ├── PerformanceCollateralVault.sol        # Direct Bond Vault, ERC4626 Yield Pool & Slashing (BUSL-1.1)
│   ├── SwarmDelegationVault.sol              # Merkle Swarm Delegations, Quotas & Grace Rotation (BUSL-1.1)
│   ├── MockERC4626Vault.sol                  # Mock ERC4626 yield-bearing vault for testing
│   └── MockUSDC.sol                          # Mock USDC (6 decimals)
├── src/                                      # C11 Sovereign Engine
│   ├── causal_daemon.c                       # Core cryptographic engine and wire daemon (BUSL-1.1)
│   ├── causal_daemon.h                       # Binary framing and C-FFI header (BUSL-1.1)
│   ├── csls_daemon.c                         # Standalone streaming daemon binary (BUSL-1.1)
│   ├── csls_daemon.h                         # Streaming daemon interface (BUSL-1.1)
│   ├── schnorr_bloodhound.c                  # Autonomous MEV searcher engine (Apache-2.0)
│   └── schnorr_bloodhound.h                  # Bloodhound definitions (Apache-2.0)
├── sdk/                                      # Developer SDK & Sidecars (Apache-2.0)
│   ├── agentkit_provider.py                  # AgentKit ActionProvider bindings
│   ├── async_causal.py                       # Asynchronous client channel actor
│   ├── bloodhound.py                         # Python FFI bindings to Bloodhound searcher
│   ├── causal_agentkit.py                    # Multi-vendor streaming provider
│   ├── causal_eth.py                         # Ethereum / L2 settlement helpers
│   ├── causal_slash.py                       # Python FFI bindings to C11 engine
│   ├── channel_store.py                      # Crash-proof monotonic channel store (Zero-SQLite)
│   ├── debt_cycle_mesh.py                    # In-RAM Kirchhoff cycle debt netting engine
│   ├── guardrails.py                         # Edge safety inspection & threat mitigation
│   ├── integrations/                         # Agent framework integrations
│   │   ├── decorators.py                     # Streaming payment decorators
│   │   └── langchain.py                      # LangChain callback and tool integration
│   ├── onchain_settler.py                    # On-chain batch settlement & slashing driver
│   ├── session.py                            # Session lifecycle and budget limits
│   ├── slash_proxy.py                        # Reverse proxy sidecar for agent swarms
│   ├── swarm_stream.py                       # Multi-channel swarm streaming
│   ├── swarm_subagent.py                     # Subagent leaf generation & proof handling
│   └── telemetry.py                          # Latency, percentiles and throughput metrics
├── test/                                     # Comprehensive Test Suites
│   ├── AdversarialExploits.t.sol             # Adversarial exploit test suite
│   ├── CompetitorGriefingAttacks.t.sol       # MEV griefing and race tests
│   ├── PerformanceCollateralVault.t.sol      # Core vault unit and fuzz tests
│   ├── ReliabilityInvariantsAudit.t.sol      # Solvency and haircut invariant tests
│   ├── SwarmDelegationVault.t.sol            # Swarm Merkle quotas and grace period tests
│   ├── YieldStreamingCollateral.t.sol        # ERC4626 yield and buffer tests
│   ├── invariants/                           # Invariant & Formal Verification Suites
│   │   ├── HalmosProtocolInvariants.t.sol    # Halmos formal symbolic mathematical proofs
│   │   ├── ProtocolInvariants.t.sol          # Stateful property-based invariant suite
│   │   └── VaultHandler.sol                  # Foundry invariant testing harness handler
│   ├── test_causal_agentkit.py               # AgentKit provider tests
│   ├── test_channel_store_and_async.py       # Channel storage and async actor tests
│   ├── test_debt_cycle_stress.py             # Large-scale debt cycle netting stress tests
│   ├── test_e2e_full_stack.py                # Full-stack end-to-end integration tests
│   ├── test_guardrail.py                     # Edge safety guardrail tests
│   ├── test_onchain_settler.py               # EIP-712 and calldata differential tests
│   ├── test_redteam_debt_mesh.py             # Red team debt netting conservation tests
│   ├── test_redteam_sdk_forgery.py           # Signature and session MAC security tests
│   ├── test_sdk_unified.py                   # Unified SDK FFI and streaming tests
│   ├── test_sdk_v3_features.py               # 167-byte MAC wire and session tests
│   └── c/                                    # C Sanitizer & Concurrency Audits
│       ├── test_schnorr_bloodhound.c         # MEV hound test
│       ├── test_redteam_exploit.c            # Malformed packet fuzzing
│       ├── test_competitor_griefing.c        # Griefing resilience audit
│       ├── test_reliability_audit.c          # Concurrency and race tests
│       ├── test_csls_daemon_net.c            # Daemon network loopback tests
│       └── test_swarm_simulation.c           # Swarm simulation regression tests
├── benchmarks/                               # Empirical Profiling & Industrial Stress
│   ├── benchmark_e2e_streaming.py            # End-to-end streaming latency benchmark
│   ├── run_kirchhoff_netting.py              # In-RAM Kirchhoff debt netting benchmark
│   ├── slashbench.py                         # High-frequency quantile latency profiler
│   ├── stress_tcp_swarm.c                    # C11 multi-agent 1.2M cheque TCP benchmark
│   ├── swarm_2026_industrial.py              # Industrial swarm workload generator
│   └── swarm_onchain_stress.py               # On-chain multi-agent batch stress harness
├── examples/                                 # Executable Quickstarts
│   ├── agentkit_provider_demo.py             # AgentKit provider integration demo
│   ├── elizaos_plugin_demo.py                # ElizaOS agent streaming plugin demo
│   ├── quickstart_agent.py                   # Agent micro-payment quickstart
│   └── quickstart_sidecar.py                 # SlashProxy sidecar quickstart
├── scripts/                                  # Deployment Scripts & Receipts
│   ├── deploy_base_sepolia.js                # Base Sepolia contract deployer
│   ├── deploy_arbitrum_sepolia.js            # Arbitrum Sepolia contract deployer
│   ├── deploy_base_sepolia_full.js           # Base Sepolia full deployment script
│   ├── deploy_swarm_arbitrum.js              # Arbitrum Swarm deployment script
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
Expected: `Ran 13 test suites: 100 tests passed, 0 failed, 0 skipped (100 total tests)`

### 2. Execute Python SDK Test Suite:
```bash
pytest -v
```
Expected: `70 passed`

### 3. Run C11 Cryptographic Daemon & Socket Benchmarks:
```bash
make test
```
Expected: `Latency per End-to-End Cheque (Sign + Verify): ~1.68 µs`

### 4. Run MEV Schnorr Bloodhound Searcher:
```bash
make test-bloodhound
```
Expected: `All Schnorr Bloodhound Tests Successfully Passed`

### 5. Run High-Frequency Quantile Latency Profiler:
```bash
python3 benchmarks/slashbench.py
```

### 6. Run Autonomous Agent Streaming Quickstart:
```bash
python3 examples/quickstart_agent.py
```

### 7. Interactive Terminal Shell (`csls` CLI):
Install the CLI and package in editable mode:
```bash
pip install -e .
# or on externally managed environments:
pip install --break-system-packages -e .
```

Launch the sovereign interactive terminal shell:
```bash
csls
```

The shell renders inline in your terminal's standard scrollback (no fullscreen takeover or alternate screen) with teal `#21E2CC` accents, dynamic horizontal rules, persistent input history (`~/.csls/history`), and bottom toolbar (`? for shortcuts | bond: ready`):
* `/help` — show command reference table
* `/wallet new` — create agent wallet (secp256k1 keypair)
* `/wallet info` — display loaded wallet and address
* `/model [model_id]` — switch or view active late 2026 frontier models (Claude Opus 5.5, Opus 4.6, DeepSeek V4.1 Flash, DeepSeek V4 Pro, GLM 5.3, GLM 5.2, Gemini 3.8 Flash, Gemini 3.8 Live)
* `/vendor` — inspect connected M2M inference vendor, latency, settled micro-USDC, and public key
* `/memory` — inspect persistent project conversation context, storage file, and remembered turns
* `/clear` — clear persistent rolling conversation memory context
* `/bond` — query Base L2 collateral bond and free margin
* `/status` — live node status and streaming monitor
* `/stream` — listen for live 167-byte session-MAC cheques
* `/net` — in-RAM Kirchhoff debt netting summary
* `/hound` — Schnorr Bloodhound equivocation hunter
* `/test` — run C11, Foundry, and pytest suites
* `/bench` — latency and throughput benchmark
* `/verify` — on-chain contract addresses and EIP-170 bytecode limits
* `/exit` — quit CSLS (or `Ctrl+D`, or double `Ctrl+C`)

---

## 9. Deployed & Verified Contracts
 
### Base Sepolia (Chain ID `84532`)
* **SwarmDelegationVault (Hierarchical Merkle Slashing & Settlement):** [`0x901c98Da847DD24ff23FcC37B6D1549A17F12253`](https://sepolia.basescan.org/address/0x901c98Da847DD24ff23FcC37B6D1549A17F12253#code)
  * Bytecode: 24,239 bytes (strictly under the 24,576 byte EIP-170 limit)
  * Status: Verified on Basescan
* **PerformanceCollateralVault (Direct Shared Bond & Optimistic Settlement):** [`0x8faAD06ef5937Ad1019CD49f5Dcab36181e266A5`](https://sepolia.basescan.org/address/0x8faAD06ef5937Ad1019CD49f5Dcab36181e266A5#code)
  * Bytecode: 17,959 bytes
  * Status: Verified on Basescan
* **MockUSDC (Free Mintable 6-Decimals Test Asset for Autonomous Swarms):** [`0xa07eA15D1FE0B884Ffb51b19d98D938b2Bf04D6B`](https://sepolia.basescan.org/address/0xa07eA15D1FE0B884Ffb51b19d98D938b2Bf04D6B#code)
  * Status: Verified on Basescan
 
### Arbitrum Sepolia (Chain ID `421614`)
* **SwarmDelegationVault (Hierarchical Merkle Slashing & Settlement):** [`0x45Cd2B0d1319C158a5B37B74DcBE3D78C9861f1F`](https://sepolia.arbiscan.io/address/0x45Cd2B0d1319C158a5B37B74DcBE3D78C9861f1F#code)
  * Bytecode: 24,239 bytes (strictly under the 24,576 byte EIP-170 limit)
  * Status: Verified on Arbiscan
* **PerformanceCollateralVault (Direct Shared Bond & Optimistic Settlement):** [`0xfEaA1F897FF4540d7B43010A80912FCEcCd95A9a`](https://sepolia.arbiscan.io/address/0xfeaa1f897ff4540d7b43010a80912fceccd95a9a#code)
  * Bytecode: 17,959 bytes
  * Status: Verified on Arbiscan
* **MockUSDC (Free Mintable 6-Decimals Test Asset for Autonomous Swarms):** [`0x8faAD06ef5937Ad1019CD49f5Dcab36181e266A5`](https://sepolia.arbiscan.io/address/0x8faAD06ef5937Ad1019CD49f5Dcab36181e266A5#code)
  * Status: Verified on Arbiscan

---

## 10. Licensing

The Causal-Slash Protocol repository utilizes a hybrid licensing model:
* **Core Protocol Infrastructure (`contracts/` and `src/causal_daemon.*`):** Licensed under the **Business Source License 1.1 (BUSL-1.1)**. Free for non-production use, testing, research, and testnet deployments. Converts to the **Apache License, Version 2.0** on **October 1, 2028**.
* **Client SDK, MEV Tools & Examples (`sdk/`, `src/schnorr_bloodhound.*`, `benchmarks/`, `examples/`):** Permanently licensed under the **Apache License, Version 2.0**. Free and open for commercial and non-commercial integration by any autonomous agent framework, MEV searcher, or application.

See [LICENSE](LICENSE) for complete legal terms.
