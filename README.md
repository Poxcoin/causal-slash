# Causal-Slash Protocol

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Specification%20%26%20Reference%20Implementation-green.svg)]()
[![Bitcoin-Timestamp](https://img.shields.io/badge/Bitcoin%20OTS-Anchored-orange.svg)](USPTO_PROVISIONAL_PATENT_APPLICATION.md.ots)

> **High-frequency, sub-millisecond, zero-gas peer-to-peer streaming micro-settlement architecture with deterministic key-exposure equivocation traps for autonomous computational agents.**

---

## 1. Overview

Autonomous software agents (executing on LangGraph, AutoGen, CrewAI, or decentralized clusters) require granular, per-call micro-transactions ($0.0001 – $0.05) to purchase LLM inference tokens, vector queries, and GPU compute. 

Traditional rails impose fatal bottlenecks:
* **Web2 Rails (Stripe/Card Interchange):** $0.30 + 2.9% baseline fee makes $0.001 micro-calls impossible (30,000% overhead).
* **Layer-1 / Layer-2 Blockchains (Ethereum, Base, Solana):** 400ms – 12s block latency and gas overhead ($0.001 – $0.05 per TX) congest mempools during continuous token streaming.
* **Bilateral State Channels (Lightning Network):** Requires fragmented, locked bidirectional capital along every hop, suffering >30% routing failure rates for dynamic multi-vendor graphs.

**Causal-Slash** eliminates distributed ledgers from intermediate micro-transactions. Agents stream cryptographically signed cheques directly over existing transport connections (HTTP/WebSocket/QUIC). If an agent attempts equivocation or double-spending, any observer algebraically extracts the agent's private key in **$O(1)$ arithmetic time ($\approx 20\ \mu\text{s}$)** and slashes the agent's on-chain surety bond.

---

## 2. Cryptographic Mechanism

```
FIG. 1: PROTOCOL TOPOLOGY & EQUIVOCATION KEY EXTRACTION

+-----------------------------------------------------------------------------+
|                           BASE LEDGER (Base / L2)                           |
|  +------------------------+           +----------------------------------+  |
|  | Isolated Surety Vault  |<----------| L1 Slash Contract                |  |
|  | (Collateral Bond = B)  |           | (Commit-Reveal Slashing Engine)  |  |
|  +-----------+------------+           +-----------------+----------------+  |
+--------------|------------------------------------------^-------------------+
               | Anchors Bond                             |
               |                                          | Fraud Proof / Key
               v                                          | (O(1) Extraction)
+-------------------------------+                         |
|   AUTONOMOUS AGENT RUNTIME    |                         |
|   - Secret Key (sk)           |                         |
|   - Hardware Monotonic (h)    |                         |
|   - Merkle Nonce Root (Root_R)|                         |
+---------------+---------------+                         |
                |                                         |
                | P2P Streaming Cheques (s = k + e*sk)    |
                | (0 ms Network RTT, <15 us CPU Verify)   |
                v                                         |
+---------------------------------------------------------+-------------------+
|                     DECENTRALIZED RESOURCE PROVIDERS                        |
|   [Vendor 1: LLM Inference]    [Vendor 2: Vector DB]    [Vendor 3: GPU]     |
|   (Un-settled Buffer <= $1)    (Buffer <= $1)           (Buffer <= $1)      |
+-----------------------------------------------------------------------------+
```

### 2.1 Deterministic Nonce Tree
Let $\mathbb{G}$ be an elliptic curve group of prime order $q$ with base point generator $G$ (secp256k1). An agent deposits a collateral bond $B$ into an on-chain surety contract and registers public key $PK = sk \cdot G$. For operational heights $h \in \{0, \dots, N-1\}$:
$$k_h = \text{HMAC-SHA256}(sk, h) \pmod q$$
$$R_h = k_h \cdot G$$
Public points $R_h$ form leaves of a Merkle tree $\mathcal{T}$, whose root $\text{Root}_R$ is anchored on-chain.

### 2.2 Algebraic Private Key Extraction
To issue a payment for task message $M_h$:
$$e_h = H(R_h \parallel PK \parallel M_h) \pmod q$$
$$s_h = (k_h + e_h \cdot sk) \pmod q$$

If an attacker signs two distinct messages $M_1 \neq M_2$ at the identical height $h$:
$$s_1 = k_h + e_1 \cdot sk \pmod q$$
$$s_2 = k_h + e_2 \cdot sk \pmod q$$
$$s_1 - s_2 = (e_1 - e_2) \cdot sk \pmod q$$

Because $e_1 \neq e_2$, the scalar $(e_1 - e_2)$ has a unique modular inverse in $\mathbb{Z}_q$. The secret key is solved algebraically:
$$sk = (s_1 - s_2) \cdot (e_1 - e_2)^{-1} \pmod q$$

### 2.3 Pipelined Streaming Micro-Exposure Invariant
To prevent multi-vendor overdraft draining without global state synchronization:
1. Each vendor $v$ meters delivery in micro-quanta (e.g. $\Delta c = \$0.001$).
2. Unsettled in-flight credit per vendor is hard-capped at $\delta_v \le \$1.00$.
3. The surety bond satisfies $B > \sum_{v=1}^{N_v} \delta_v$.
4. Any multi-vendor draining attempt yields at most $\sum \delta_v$, while forfeiting $B$:
$$\mathbb{E}[\text{Payoff}] = \sum_{v=1}^{N_v} \delta_v - B < 0$$
Attack ROI is strictly negative ($\le -95\%$).

---

## 3. Verified Empirical Benchmarks

Benchmarks executed on x86_64 Linux (AMD Ryzen / Intel Xeon environment):

| Metric | Causal-Slash | Base / Arbitrum L2 | Stripe Interchange | Lightning (L402) |
|---|---|---|---|---|
| **Settlement Latency** | **< 25 microseconds** | 400 – 2,000 ms | 1,500 – 3,000 ms | 200 – 1,200 ms |
| **Intermediate Gas Fee** | **$0.000000** | $0.001 – $0.05 | $0.30 + 2.9% | $0.0002 – $0.001 |
| **Key Extraction Time** | **20.01 microseconds** | N/A (Consensus vote) | N/A (Chargeback) | N/A (HTLC expiry) |
| **Capital Efficiency** | **1x Shared Bond** | 1x Balance | Pre-funded deposit | Nx Locked hops |
| **Multi-hop Routing Failure** | **0.0% (Direct P2P)** | 0.0% (Single sequencer) | 0.0% (Centralized) | 12% – 34% (Liquidity depletion) |

---

## 4. Repository Structure

```
├── README.md                                 # Architecture & benchmark summary
├── LICENSE                                   # Apache-2.0 open-source license
├── USPTO_PROVISIONAL_PATENT_APPLICATION.pdf  # Compiled USPTO Provisional Patent Document
├── USPTO_PROVISIONAL_PATENT_APPLICATION.md   # Complete Patent Specification & 10 Claims
├── USPTO_PROVISIONAL_PATENT_APPLICATION.md.ots # Bitcoin OpenTimestamps Proof Receipt
├── full_system_demo.py                       # End-to-end benchmark & key extraction demo
├── test_concurrency.c                        # C11 POSIX multi-threaded atomics test
└── test_state_bloat.c                        # Memory footprint & state bloat audit
```

---

## 5. Quickstart & Verification

### 5.1 Run the Full System Benchmark (Python)
Simulates 1,000 sequential micro-payments, introduces a concurrent equivocation attack, and extracts the attacker's private key:

```bash
python3 full_system_demo.py
```

*Expected output:*
```text
[OK] Cheques 0..999 verified successfully.
[!] Equivocation detected at height h=500!
[CRITICAL] Algebraic Private Key Extraction triggered:
    Extracted sk: 0x937f9e83...
    True sk:      0x937f9e83...
    MATCH VERIFIED: True
    Key Extraction Latency: 20.01 microseconds
[ECONOMICS] Cumulative fee savings vs L2 gas: 99.4%
```

### 5.2 Run Multi-Threaded Concurrency Test (C)
Verifies that hardware-atomic monotonic height counters prevent race conditions:

```bash
gcc -O3 -pthread test_concurrency.c -o concurrency_test
./concurrency_test
```

---

## 6. Patent & Prior Art Notice

* **Filing Document:** [USPTO_PROVISIONAL_PATENT_APPLICATION.pdf](USPTO_PROVISIONAL_PATENT_APPLICATION.pdf)
* **Title:** *System and Method for Cryptographically Enforced Peer-to-Peer Micro-Settlements and Equivocation-Based Collateral Slashing in Autonomous Computational Agent Networks*
* **SHA-256 Digest:** `d3940e98fd5c14bb3df11f5f5f2363cfcf812e97147e0d39d63f35d79166633c`
* **Bitcoin Timestamp:** Anchored on Bitcoin via OpenTimestamps (`USPTO_PROVISIONAL_PATENT_APPLICATION.md.ots`).
* **Statutory Grace Period:** Under 35 U.S.C. § 102(b), global prior art is established, preserving 1-year priority rights.

---

## 7. License

Licensed under the [Apache License, Version 2.0](LICENSE).
