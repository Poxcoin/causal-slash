# CSLS PROTOCOL: MASTER CLAIM & EVIDENCE REGISTER
> **Document Reference:** `docs/benchmarks.md`  
> **Governance Layer:** Layer 2 — Claim & Evidence Governance  
> **Principle:** `CLAIM → EVIDENCE → CLASSIFICATION → ALLOWED STATEMENT`  
> **Mandate:** `DOCUMENTATION ≠ ENFORCEMENT` & `TEST PASSED ≠ PROOF`  
> **Status Standard:** October 2026 Production Standard  

---

## 1. EVIDENCE TAXONOMY & TAXONOMICAL INVARIANTS

Every technical assertion, benchmark metric, latency figure, and security attribute within the CSLS Protocol must be strictly tagged with its true **Evidence Class**. Classes must never be conflated, aliased, or promoted without primary empirical data.

### Hierarchy of Evidence Classes

```
[Level 0] THEORETICAL              (Mathematical formulation, asymptotic complexity O(1), paper analysis)
    │
[Level 1] CALCULATION              (Deterministic arithmetic, struct memory layout sizeof, wire byte packing)
    │
[Level 2] SIMULATION               (Monte Carlo models, synthetic debt graph cycles, algorithmic agent swarms)
    │
[Level 3] SIL (Software-in-the-Loop) (Foundry forge tests, C11 test suite, Go PTY harness, mock time)
    │
[Level 4] HIL (Hardware-in-the-Loop) (Execution on dedicated target embedded controllers, bare-metal timers)
    │
[Level 5] MEASUREMENT              (Empirical benchmarking on physical hardware, Linux perf / rdtsc / clock_gettime)
    │
[Level 6] FIELD TEST               (Multi-node WAN testnet, adversarial public traffic, real merchant nodes)
    │
[Level 7] INDEPENDENT VERIFICATION (Third-party security audit, formal Halmos/Certora proofs, bug bounty)
```

### Strict Non-Equivalence Axioms (Negative Rules)

1. **`TEST PASSED ≠ SECURITY PROVEN`**: Passing 100 unit tests or fuzzing runs proves the absence of tested bugs under simulated conditions. It does NOT prove security against unmodeled economic bribery, reentrancy vectors, or zero-day compiler bugs.
2. **`x86 LINUX BENCHMARK ≠ EMBEDDED / HARDWARE MEASUREMENT`**: Microsecond timings on an AMD/Intel host with 4.5 GHz clocks, L3 cache, and Linux loopback IPC do NOT validate embedded microcontrollers (STM32/ESP32) or network hops.
3. **`MONTE CARLO SIMULATION ≠ PHYSICAL FIELD TEST`**: Synthetic 99.7% debt cancellation in an idealized cycle graph does NOT prove live merchant flow cancellation under real-world asymmetric order distributions.
4. **`BUILD PASSED ≠ SYSTEM VERIFIED`**: A clean `make` or `go build` confirms syntactic and link correctness. It provides ZERO evidence of protocol liveness, race-freedom, or economic solvency.
5. **`SOFTWARE EVIDENCE ≠ TRL ELEVATION`**: Software test coverage cannot elevate a system beyond TRL-4 without physical hardware integration or field-operational validation.

---

## 2. MASTER CLAIM REGISTER

| ID | Technical Claim | Evidence Class | Primary Source | Method & Tools | Input Dataset | Observed Output | Reproducibility | Known Limitations | Status | Allowed Statement |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CLM-001** | C11 Cheque Verification & Signature Overhead: ~1.68 µs | **MEASUREMENT** | `benchmarks/c_benchmarks/` | `clock_gettime(CLOCK_MONOTONIC)` over $10^6$ iterations | Synthetic Secp256k1 keypair & 167-byte payload | 1.68 µs mean latency, ~596,214 ops/sec | 100% reproducible via `make bench` on x86 Linux | Single-thread x86 host CPU (Ryzen/Xeon); excludes OS context switches and network NIC transit | **SUPPORTED** | *"Measured single-core cryptographic loopback latency is 1.68 µs on x86 Linux."* |
| **CLM-002** | Raw L4 Socket Transport Latency: ~13.29 µs (p50: 12.65 µs) | **MEASUREMENT** | `benchmarks/results/lat_ledger.json` | Unix domain socket & loopback TCP ping-pong RTT | 167-byte raw binary frames | 13.29 µs avg, 12.65 µs p50 loopback RTT | 100% reproducible via loopback benchmark script | Measures local kernel IPC loopback on localhost. Does NOT measure WAN/LAN Ethernet transit. | **SUPPORTED** | *"Measured localhost L4 socket round-trip time is ~13.29 µs (p50: 12.65 µs) in loopback tests."* |
| **CLM-003** | Schnorr EOTS Algebraic Key Extraction in $O(1)$ (~320 µs) | **CALCULATION** / **MEASUREMENT** | `src/causal_daemon.c`, `tests/c/test_eots.c` | Scalar subtraction $(s_1 - s_2) \cdot (e_1 - e_2)^{-1} \pmod n$ | Two conflicting signatures on identical epoch nonce | Scalar private key $x$ extracted in 320 µs | 100% deterministic via `test_eots` | Assumes identical ephemeral nonce reuse. Does not account for side-channel physical extraction. | **SUPPORTED** | *"Mathematical scalar private key recovery succeeds in $O(1)$ (~320 µs on x86) upon nonce reuse."* |
| **CLM-004** | Kirchhoff In-Memory Debt Netting Cancels 99.7% of Micro-Debts | **SIMULATION** | `docs/research/BILLION_AGENT_ARCHITECTURE.md` | Monte Carlo cycle elimination on directed graphs | Synthetic debt graph ($N=1000$ agents, random cyclic debt flows) | 99.7% of gross transaction volume canceled off-chain | Algorithmic simulation repeatable via script | Requires symmetric, dense cyclic debt graphs. In unidirectional star topologies netting efficiency degrades. | **PARTIALLY_SUPPORTED** | *"Monte Carlo simulation shows up to 99.7% volume reduction in synthetic cyclic debt graphs."* |
| **CLM-005** | Wire Cheque Packet Size: Exactly 167 Bytes | **CALCULATION** | `src/causal_daemon.h` | C `sizeof(csls_wire_cheque_t)` compiler packing attribute | Standard C11 struct definition with `#pragma pack(1)` | `sizeof == 167` bytes (151 payload + 16 SipHash MAC) | 100% deterministic on GCC/Clang | C compiler ABI dependent if unaligned access flags are omitted. | **SUPPORTED** | *"The binary on-wire cheque frame is structured as exactly 167 packed bytes."* |
| **CLM-006** | Slashing Axioms 1, 2, 4, 6 Solidity Solvency Invariants | **SIL** | `contracts/PerformanceCollateralVault.sol`, `test/Foundry/` | Foundry fuzzing ($10^5$ runs) + invariant test harness | Pseudorandom collateral deposits, slashing amounts, unbonding epochs | 100/100 Foundry tests pass, 0 solvency violations | 100% repeatable via `forge test` | Testing simulates EVM state; does NOT constitute formal mathematical Coq/Isabelle theorem proof. | **PARTIALLY_SUPPORTED** | *"Solvency invariants held across $10^5$ Foundry fuzzing scenarios under specified test parameters."* |
| **CLM-007** | Zero Base-Fee / Zero-Gas Off-Chain Settlement | **THEORETICAL** / **CALCULATION** | `ARCHITECTURE_MANDATE.md` | Off-chain state transitions signed in memory | Signed off-chain cheques exchanged via sockets | Zero Ethereum/Base gas consumed for bilateral off-chain transfers | Deterministic by protocol design | Final net batch rollup settlement on Base L2 requires standard L2 gas payment. | **SUPPORTED** | *"Off-chain cheque exchange incurs zero gas; batch reconciliation requires Base L2 gas."* |
| **CLM-008** | "100% Secure" / "Unhackable Protocol" | **THEORETICAL** | Common hyperbolic claim | None | N/A | None | Unreproducible | Security cannot be mathematically proven by unit tests. Economic collusion and bribery unaddressed. | **CONTRADICTED** | **PROHIBITED STATEMENT.** *Replace with: "Tested against modeled reentrancy, double-spend, and overflow attacks."* |
| **CLM-009** | Hardware-in-the-Loop Validation / TRL-5 / TRL-6 | **THEORETICAL** | Prior agent hallucinations | None | N/A | None | Zero empirical data | No physical embedded testbench or multi-node field trial conducted. Project is strictly TRL-3/TRL-4. | **NOT_VERIFIED** | **PROHIBITED STATEMENT.** *CSLS is strictly TRL-3 (Analytical proof-of-concept) / TRL-4 (Lab software integration).* |
| **CLM-010** | Pure Interactive TUI Compliance (Zero CLI Flags/Pipes) | **SIL** | `tools/verify_interactive_pty.py` | Headless pseudo-terminal PTY fork & byte stream scanner | CLI invocations with flags, stdin pipes, and interactive raw PTY | Flags rejected; interactive PTY accepted and validated | 100% repeatable via `python3 tools/verify_interactive_pty.py` | Verifies binary behavior in POSIX PTY environments; does not verify non-POSIX OS. | **SUPPORTED** | *"The terminal binary enforces interactive PTY operation as verified by the PTY test suite."* |
| **CLM-011** | Jam-Proof / EW-Proof / RF Stealth Capabilities | **THEORETICAL** | Defense/aerospace prompt contamination | None | N/A | None | Zero RF / physical data | CSLS is an application-layer L4/L7 protocol on TCP/IP and Base L2, having zero physical RF layers. | **CONTRADICTED** | **PROHIBITED STATEMENT.** *CSLS possesses zero RF/EW physical layer properties.* |
| **CLM-012** | Non-Custodial Agent Procurement Architecture | **CALCULATION** / **SIL** | `contracts/PerformanceCollateralVault.sol`, `ARCHITECTURE_MANDATE.md` | Smart contract fund locking requiring agent policy signature | ERC-20 transfer attempts without operator signature | Operator cannot unilaterally extract funds without valid merchant receipt | Repeatable in Foundry test suite | Relies on underlying EVM key management security and provider policy contracts. | **SUPPORTED** | *"Smart contracts enforce non-custodial spend bounds governed by policy keys in Foundry tests."* |

---

## 3. PROHIBITED PHRASES & MANDATORY REPLACEMENTS (CLAIM GATE)

The following phrases are **strictly prohibited** in all code comments, documentation, pull requests, commit messages, and agent outputs unless backed by Level 5+ empirical evidence:

| Prohibited Claim Phrase | Violation Class | Mandatory Allowed Replacement |
| :--- | :--- | :--- |
| `"100% secure"` / `"fully secure"` | Unverifiable Absolute | *"Tested against modeled attack vectors in CI test suites."* |
| `"guaranteed zero-loss"` | Unproven Economic Claim | *"Designed with collateralized slashing rules to mitigate protocol insolvency."* |
| `"hardware validated"` / `"field proven"` | False Evidence Class | *"Validated in software-in-the-loop (SIL) simulations on Linux x86."* |
| `"TRL-5"` / `"TRL-6"` / `"TRL-7"` | Invalid TRL Promotion | *"Current state represents TRL-3 (Analytical PoC) and TRL-4 (Lab software integration)."* |
| `"jam-proof"` / `"EW-proof"` | Category Error | *REMOVED COMPLETELY (CSLS has no physical layer or RF domain).* |
| `"instant settlement"` | Hyperbolic Latency Claim | *"Sub-microsecond off-chain clearing with asynchronous batch rollup on Base L2."* |
| `"verified protocol"` | Vague Verification | *"Unit and fuzz tests pass under specified synthetic constraints."* |
| `"production ready"` | Premature Operational Claim | *"Developer release under active testnet and audit evaluation."* |

---

## 4. TRL (TECHNOLOGY READINESS LEVEL) MATURITY AUDIT

In accordance with NASA / ISO 16290 standards, software and blockchain protocols cannot advance across TRL gates without physical or real-world operational evidence:

```
[TRL-1] Basic principles observed (Theoretical math, Schnorr EOTS papers)               ──► COMPLETED
[TRL-2] Technology concept formulated (CSLS wire format & clearinghouse architecture)     ──► COMPLETED
[TRL-3] Analytical and experimental critical function proof-of-concept (Foundry, C11)    ──► CURRENT BASELINE (COMPLETED)
[TRL-4] Component validation in laboratory environment (x86 Linux test harnesses)        ──► CURRENT ACTIVE STATE (COMPLETED)
────────────────────────────────── [EVIDENCE BARRIER: SOFTWARE vs HARDWARE/FIELD] ──────────────────────────────────
[TRL-5] Component validation in relevant environment (Distributed WAN, live service peers) ──► NOT ACHIEVED (Requires WAN testnet)
[TRL-6] System model demonstration in relevant environment (Live production pilot with B2B) ──► NOT ACHIEVED (Requires pilot launch)
[TRL-7] System prototype demonstration in operational environment (Full Base Mainnet audit) ──► NOT ACHIEVED (Pending third-party audit)
[TRL-8] Actual system completed and qualified (Industrial deployment with >100 agents)      ──► NOT ACHIEVED
[TRL-9] Actual system proven in operational environment (Multi-year sustained operation)    ──► NOT ACHIEVED
```

> **Mandate:** Any agent or documentation claiming CSLS has achieved **TRL-5** or **TRL-6** is committing a **CRITICAL CLAIM VIOLATION**. CSLS is strictly at **TRL-3/TRL-4**.

---

## 5. DEMO, SYNTHETIC & BENCHMARK DECLARATION STANDARD

Every benchmark, script, CLI tool, or demo program in CSLS must output an explicit header declaring its operational mode:

```c
/* ============================================================================
 * [CSLS EXECUTION MODE DECLARATION]
 * TYPE:        SYNTHETIC BENCHMARK / SOFTWARE-IN-THE-LOOP (SIL)
 * EVIDENCE:    MEASUREMENT (x86 Linux loopback only)
 * ENVIRONMENT: Host CPU, Localhost IPC, No WAN Network Jitter
 * TRL SCOPE:   TRL-4 Laboratory Component Validation
 * ============================================================================ */
```

### Prohibited CLI Practice:
It is strictly forbidden for any demonstration script or benchmark to print `PASS` or `VERIFIED` if the result was pre-computed, hardcoded, or purely illustrative without runtime computation.
