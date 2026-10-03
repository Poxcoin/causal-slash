# LAUNCH LOG: README VERIFICATION & EMPIRICAL EVIDENCE LEDGER

## Step 0: Protocol Synthesis

Causal-Slash is a sovereign machine-to-machine micro-settlement protocol operating at the L4 transport layer.
It is designed for autonomous agent swarms and compute providers that operate without passports, KYC, or bank accounts.
Agent identity is anchored by a secp256k1 public key, while bilateral trust is backed by an on-chain collateral bond on Base L2 and Arbitrum.
Payments stream over raw C11 sockets as 167-byte cheques per token with zero gas overhead and microsecond latency.
Axiom 1 protects master collateral by isolating subagent equivocation penalties strictly to their individual Merkle quotas.
Axiom 2 enforces monotonic cumulative cheque amounts and sequence heights to guarantee mathematical replay protection.
Axioms 3 and 4 eliminate circular debt in RAM via Kirchhoff graph netting and protect MEV searchers with commit-reveal bonds.
Axioms 5 and 6 deploy an 80/20 ERC-4626 yield and liquidity buffer and deter double-spending via O(1) algebraic key extraction.

---

## 1. Session Command Outputs (Exact Pasted Output Lines)

### Command 1: `timeout 300 forge test`
Output:
```
Suite result: ok. 5 passed; 0 failed; 0 skipped; finished in 9.76s (24.92s CPU time)
Ran 13 test suites in 9.76s (18.38s CPU time): 100 tests passed, 0 failed, 0 skipped (100 total tests)
```

### Command 2: `timeout 300 pytest -v`
Output:
```
FAILED test/test_redteam_sdk_forgery.py::test_r5_legacy_path_requires_explicit_opt_out
FAILED test/test_sdk_v3_features.py::test_session_mac_backwards_compatibility_151_byte
======================== 2 failed, 68 passed in 10.05s =========================
```

### Command 3: `timeout 120 make test`
Output:
```
Executing 50000 sequential micro-cheques on single CPU core...
  Processed: 50000 cheques
  Total Time: 0.0839 seconds
  Latency per End-to-End Cheque (Sign + Verify): 1.68 microseconds
  Throughput: 596214 operations/second
  Total Settled Volume: $500.00 USDC
Key Extraction & Proof Generation Latency: 335.96 microseconds
Real Socket RTT (Sign + TCP Tx + Verify + TCP Ack): 12.08 microseconds
Network Throughput: 82794 cheques/second over loopback TCP
```

### Command 4: `timeout 120 make test-asan`
Output:
```
Executing 50000 sequential micro-cheques on single CPU core...
  Processed: 50000 cheques
  Total Time: 0.2102 seconds
  Latency per End-to-End Cheque (Sign + Verify): 4.20 microseconds
  Throughput: 237813 operations/second
  Total Settled Volume: $500.00 USDC
Key Extraction & Proof Generation Latency: 450.68 microseconds
Real Socket RTT (Sign + TCP Tx + Verify + TCP Ack): 17.18 microseconds
Network Throughput: 58221 cheques/second over loopback TCP
```

### Command 5: `timeout 120 make test-tsan`
Output:
```
Executing 50000 sequential micro-cheques on single CPU core...
  Processed: 50000 cheques
  Total Time: 0.7745 seconds
  Latency per End-to-End Cheque (Sign + Verify): 15.49 microseconds
  Throughput: 64560 operations/second
  Total Settled Volume: $500.00 USDC
Key Extraction & Proof Generation Latency: 363.26 microseconds
Real Socket RTT (Sign + TCP Tx + Verify + TCP Ack): 36.38 microseconds
Network Throughput: 27488 cheques/second over loopback TCP
```

### Command 6: `timeout 120 make test-bloodhound`
Output:
```
[BLOODHOUND TEST 1] Verifying Keccak-256 standard Ethereum test vector...
  RESULT: Keccak-256 matches Ethereum specification exactly!
[BLOODHOUND TEST 2] Simulating Schnorr Bloodhound MEV Searcher Stream...
  [PASS] Double-spend intercepted at height 500!
  [PASS] Rogue private key extracted algebraically: MATCH!
  [PASS] Commit-reveal transaction payload ready for Base L2 RPC!
  [BOUNTY] 15% Finder Bounty secured for Bloodhound searcher!
[BLOODHOUND TEST 3] Evidence-eviction attack with KNOWN slot seed (threat model bound)...
  [PASS] Control round: without eviction, equivocation at height 777 is caught.
[BLOODHOUND TEST 4] Targeted eviction with GUESSED seed (production attacker)...
  [PASS] 512 seed-guessed eviction packets missed slot 6475; double-spend still captured.
[BLOODHOUND TEST 5] Blind-flood eviction resilience (statistical)...
  [METRIC] captures under blind flood: 128/128 rounds
[BLOODHOUND TEST 6] Benign slot collisions produce no false equivocation...
  [PASS] Cross-agent and cross-height slot sharing: zero false positives, zero evidence corruption.
[BLOODHOUND TEST 7] Interception latency gate (invariant: 35ns)...
  [METRIC] best mean inspection latency: 137.62 ns (limit 300.0 ns)
  [PASS] Interception decision within budget.
[VERDICT] All Schnorr Bloodhound Tests Successfully Passed!
```

### Command 6b (Strict Gate): `timeout 120 make test-bloodhound-strict`
Output:
```
[BLOODHOUND TEST 7] Interception latency gate (invariant: 35ns)...
  [METRIC] best mean inspection latency: 17.28 ns (limit 50.0 ns)
  [PASS] Interception decision within budget.
[VERDICT] All Schnorr Bloodhound Tests Successfully Passed!
```

### Command 7: `timeout 120 python3 benchmarks/slashbench.py`
Output:
```
======================================================================
SLASHBENCH: HIGH-FREQUENCY M2M PERFORMANCE PROFILER
======================================================================
Profiling 10000 sequential micro-settlements on local core...
Traceback (most recent call last):
  File "/home/minus/Рабочий стол/Causal_Slash_Protocol/benchmarks/slashbench.py", line 80, in <module>
    run_slashbench(10000)
  File "/home/minus/Рабочий стол/Causal_Slash_Protocol/benchmarks/slashbench.py", line 43, in run_slashbench
    assert res.accepted
AssertionError
```

### Command 8: `timeout 120 forge build --sizes`
Output:
```
| MockUSDC                   | 1,864            | 2,792             | 22,712             | 46,360              |
| PerformanceCollateralVault | 17,959           | 19,683            | 6,617              | 29,469              |
| SwarmDelegationVault       | 24,239           | 26,012            | 337                | 23,140              |
```

---

## 2. README Verification Table

| Claim | README Line | Measured | Verdict |
|---|---|---|---|
| Badge: Foundry Tests 100/100 Passing | 5 | `100 tests passed, 0 failed, 0 skipped (100 total tests)` across 13 suites | MATCH |
| Badge: Pytest 70/70 Passing | 6 | `2 failed, 68 passed in 10.05s` (70 total tests) | MISMATCH (68/70 passing, 2 failed) |
| Badge: C11 Latency 1.62 µs | 9 | `Latency per End-to-End Cheque (Sign + Verify): 1.68 microseconds` | MISMATCH (measured 1.68 µs) |
| Badge: Throughput 530k ops/sec | 10 | `Throughput: 596214 operations/second` (~596k ops/sec) | MISMATCH (measured 596k ops/sec) |
| Sec 5: Cryptographic Overhead 1.68 µs | 147 | `1.68 microseconds` | MATCH |
| Sec 5: Sustained Throughput 289,575 cheques/s (peak 306,340) | 157 | Historical file `benchmarks/results/stress_ledger.json` (`"tps_avg": 289574.8, "tps_peak_100ms": 306340.0`); in-session single-stream loopback: 82,794 cheques/s, core: 596,214 ops/s | MATCH (historical stress ledger confirmed) |
| Sec 5: Latency distribution Average RTT 13.29 µs | 158 | Historical file `benchmarks/results/lat_ledger.json` (`"avg": 13.286`); in-session loopback: 12.08 µs | MATCH (historical lat ledger confirmed) |
| Sec 6: Foundry Test Suites (87/87 Passing) | 171 | `100 tests passed, 0 failed, 0 skipped` across 13 test suites | MISMATCH (outdated, updated to 100/100) |
| Sec 6: Python SDK Tests (52/52 Passing) | 188 | `68 passed, 2 failed` (70 total tests) | MISMATCH (outdated, updated to 68/70) |
| Sec 6: C Core throughput & latency (1.68 µs, 596k ops/sec) | 182 | `1.68 microseconds`, `596214 operations/second` | MATCH |
| Sec 8: Expected EVM Solidity Test Suite (`87 tests passed`) | 264 | `Ran 13 test suites: 100 tests passed, 0 failed, 0 skipped` | MISMATCH (updated to 100 tests passed across 13 suites) |
| Sec 8: Expected Python SDK Test Suite (`52 passed`) | 270 | `68 passed, 2 failed` | MISMATCH (updated to 68 passed, 2 failed) |
| Sec 8: Expected C11 Daemon Latency (`~1.68 µs`) | 276 | `Latency per End-to-End Cheque (Sign + Verify): 1.68 microseconds` | MATCH |
| Sec 8: Expected MEV Bloodhound (`All Schnorr Bloodhound Tests Successfully Passed`) | 282 | `All Schnorr Bloodhound Tests Successfully Passed!` | MATCH |
| Sec 8: `python3 benchmarks/slashbench.py` & `test/test_slash_proxy.py` | 285-288 | `test/test_slash_proxy.py` is NOT FOUND; `benchmarks/slashbench.py` fails with AssertionError | UNREPRODUCIBLE (deleted per Rule 3) |
| Sec 9: Base Sepolia SwarmDelegationVault Bytecode 24,240 bytes | 296 | Runtime Size: 24,239 bytes (Margin: 337 bytes) | MISMATCH (updated to 24,239 bytes) |
| Sec 9: Base Sepolia PerformanceCollateralVault Bytecode 17,960 bytes | 299 | Runtime Size: 17,959 bytes (Margin: 6,617 bytes) | MISMATCH (updated to 17,959 bytes) |
| Sec 9: Arbitrum Sepolia SwarmDelegationVault Bytecode 24,239 bytes | 306 | Runtime Size: 24,239 bytes | MATCH |
| Sec 9: Arbitrum Sepolia PerformanceCollateralVault Bytecode 17,959 bytes | 309 | Runtime Size: 17,959 bytes | MATCH |
| Sec 7: Repository Tree `examples/full_system_demo.py` | 246 | NOT FOUND (`examples/` contains `quickstart_agent.py`, `quickstart_sidecar.py`, `agentkit_provider_demo.py`, `elizaos_plugin_demo.py`) | MISMATCH (updated to reflect real files) |
| Sec 7: Repository Tree `test/invariants/` | 222-238 | Present on disk: `HalmosProtocolInvariants.t.sol`, `ProtocolInvariants.t.sol`, `VaultHandler.sol` | MISMATCH (added missing invariant suites to tree) |
| Sec 7: Repository Tree Python test files | 229-233 | Present on disk: 10 python test files (`test_causal_agentkit.py`, `test_channel_store_and_async.py`, `test_debt_cycle_stress.py`, `test_e2e_full_stack.py`, `test_guardrail.py`, `test_onchain_settler.py`, `test_redteam_debt_mesh.py`, `test_redteam_sdk_forgery.py`, `test_sdk_unified.py`, `test_sdk_v3_features.py`) | MISMATCH (updated to list all 10 active test suites) |
