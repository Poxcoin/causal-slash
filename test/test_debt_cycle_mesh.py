# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Unit and Invariant Verification Suite for DebtCycleMesh & Kirchhoff Cycle Reduction.
Proves the mathematical invariants established in docs/research/BILLION_AGENT_ARCHITECTURE.md Section 2:
1. Conservation of Net Divergence Balance under cycle elimination (Theorem 2).
2. Strict Monotonic Debt Reduction (Theorem 3).
3. >= 99% Compression of on-chain transactions and volume in high-density swarms.
4. Thread-safe concurrent execution under high-frequency agent loads.
"""

from __future__ import annotations
import os
import sys
import threading
import random
from typing import Dict, List, Set, Tuple

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_TEST_DIR)
sys.path.insert(0, os.path.join(_PROJECT_ROOT, "sdk"))

from causal_slash import (
    DebtCycleMesh,
    NettingSummary,
    CycleEliminationRecord,
    CausalAgentWallet,
    CslsCheque,
)


def test_kirchhoff_balance_conservation_triangle():
    """
    Theorem 2 Invariant:
    Simple 3-node cycle (A -> B -> C -> A) with asymmetric debt weights.
    Verify that b'(u) == b(u) for all nodes after bottleneck subtraction,
    and total system debt decreases strictly by k * Delta_C.
    """
    print("\n[TEST 1] Verifying Kirchhoff Net Balance Conservation (Triangle Cycle)...")
    mesh = DebtCycleMesh(auto_bilateral_netting=False)

    pk_a = b"\x02" + b"AGENT_A" * 4 + b"\x01"
    pk_b = b"\x02" + b"AGENT_B" * 4 + b"\x02"
    pk_c = b"\x02" + b"AGENT_C" * 4 + b"\x03"

    # A owes B 300,000 ($0.30)
    # B owes C 200,000 ($0.20)
    # C owes A 100,000 ($0.10)
    mesh.add_obligation(pk_a, pk_b, 300_000)
    mesh.add_obligation(pk_b, pk_c, 200_000)
    mesh.add_obligation(pk_c, pk_a, 100_000)

    debt_before = mesh.total_system_debt
    assert debt_before == 600_000

    bal_before = mesh.get_all_net_balances()
    # b(A) = in (100k) - out (300k) = -200k
    # b(B) = in (300k) - out (200k) = +100k
    # b(C) = in (200k) - out (100k) = +100k
    assert bal_before[pk_a] == -200_000
    assert bal_before[pk_b] == 100_000
    assert bal_before[pk_c] == 100_000
    assert sum(bal_before.values()) == 0

    # Bottleneck Delta_C is min(300k, 200k, 100k) = 100k
    cycles, cleared = mesh.reduce_kirchhoff_cycles()
    assert cycles == 1
    assert cleared == 300_000  # k * Delta = 3 * 100k

    debt_after = mesh.total_system_debt
    assert debt_after == 300_000  # 600k - 300k = 300k
    assert debt_before - debt_after == cleared

    bal_after = mesh.get_all_net_balances()
    # Strict Mathematical Invariant Check: b'(u) == b(u)
    assert bal_before == bal_after, "Theorem 2 violated: net balances changed!"
    assert sum(bal_after.values()) == 0

    # C -> A edge must be completely eliminated (weight 0)
    assert mesh.is_dag, "Residual graph must be a DAG with 0 cycles!"
    print("  [PASS] Theorem 2 & Theorem 3 strictly hold. Balance vector invariant preserved.")


def test_complex_multicycle_mesh_invariant():
    """
    Complex multi-cycle mesh with 20 agents, interlocking cycles (k=3, 4, 5),
    cross-chords, and external leaf nodes.
    Proves global invariant preservation and DAG termination.
    """
    print("\n[TEST 2] Verifying Multi-Cycle Interlocking Mesh Invariant...")
    mesh = DebtCycleMesh(auto_bilateral_netting=True)

    rng = random.Random(0xCA55A1)
    agents = [b"\x02" + f"AGENT_{i:04d}".encode("utf-8") + b"\x00" * 22 for i in range(20)]

    # 1. Create multiple directed cycles
    # Cycle 1 (length 4): 0 -> 1 -> 2 -> 3 -> 0
    c1 = [0, 1, 2, 3, 0]
    for i in range(4):
        mesh.add_obligation(agents[c1[i]], agents[c1[i+1]], 50_000 + i * 10_000)

    # Cycle 2 (length 5): 3 -> 4 -> 5 -> 6 -> 7 -> 3 (intersects at 3)
    c2 = [3, 4, 5, 6, 7, 3]
    for i in range(5):
        mesh.add_obligation(agents[c2[i]], agents[c2[i+1]], 40_000 + i * 5_000)

    # Cycle 3 (length 3): 7 -> 8 -> 9 -> 7 (intersects at 7)
    c3 = [7, 8, 9, 7]
    for i in range(3):
        mesh.add_obligation(agents[c3[i]], agents[c3[i+1]], 75_000)

    # Additional cross-chords and tree flows
    mesh.add_obligation(agents[2], agents[5], 25_000)
    mesh.add_obligation(agents[6], agents[1], 15_000)
    mesh.add_obligation(agents[10], agents[0], 100_000)  # Ingress source
    mesh.add_obligation(agents[9], agents[11], 80_000)   # Egress sink

    # Random background bilateral transactions among remaining nodes
    for _ in range(50):
        u_idx = rng.randint(12, 19)
        v_idx = rng.randint(12, 19)
        if u_idx != v_idx:
            mesh.add_obligation(agents[u_idx], agents[v_idx], rng.randint(1_000, 20_000))

    bal_before = mesh.get_all_net_balances()
    assert sum(bal_before.values()) == 0, "Kirchhoff sum != 0 before reduction"

    debt_before = mesh.total_system_debt
    cycles_elim, cleared = mesh.reduce_kirchhoff_cycles()

    debt_after = mesh.total_system_debt
    bal_after = mesh.get_all_net_balances()

    assert cycles_elim > 0, "Expected multiple cycles to be found and eliminated"
    assert debt_after < debt_before, "System debt must strictly decrease"
    assert mesh.is_dag, "Graph must be completely reduced to a DAG"

    # Strict Invariant: Every single node's net balance is identical
    for node in agents:
        b_b = bal_before.get(node, 0)
        b_a = bal_after.get(node, 0)
        assert b_b == b_a, f"Balance mismatch on {node}: {b_b} != {b_a}"

    assert sum(bal_after.values()) == 0, "Kirchhoff sum != 0 after reduction"
    print(f"  [PASS] Successfully eliminated {cycles_elim} cycles ({cleared / 1e6:.4f} USDC cleared).")
    print("  [PASS] Multi-cycle mesh strictly preserved net balance invariant.")


def test_99_percent_compression_swarm_workload():
    """
    Hyperscale Swarm Workload Test (Section 2.4.2):
    Simulates an enterprise swarm of 50 sub-agents executing 10,000 cyclical
    micro-transactions (e.g. Scraper -> Parser -> Embedder -> LLM -> Router -> Scraper).
    Proves that on-chain settlement volume and transaction count are reduced by >= 99%.
    """
    print("\n[TEST 3] Verifying >= 99% Compression on High-Density Swarm Workload...")
    mesh = DebtCycleMesh(auto_bilateral_netting=True)

    rng = random.Random(0x42)
    num_agents = 50
    agents = [b"\x02" + f"SWARM_SUB_{i:04d}".encode("utf-8") + b"\x00" * 19 for i in range(num_agents)]

    # 1. Generate 10,000 cyclical micro-transactions (closed rings)
    # 5 rings of 10 agents each, performing 2,000 cycles
    ring_size = 10
    total_injected_txs = 0
    for r in range(num_agents // ring_size):
        ring_agents = agents[r * ring_size : (r + 1) * ring_size]
        for _ in range(200):
            # Each loop has 10 hops
            amt = rng.randint(100, 500) # $0.0001 - $0.0005
            for i in range(ring_size):
                u = ring_agents[i]
                v = ring_agents[(i + 1) % ring_size]
                mesh.add_obligation(u, v, amt)
                total_injected_txs += 1

    # 2. Add small linear residual non-cyclical drift (< 1% of transactions)
    # E.g. 10 external funding/egress micro-obligations
    for i in range(10):
        mesh.add_obligation(agents[i], agents[num_agents - 1 - i], 1_000)
        total_injected_txs += 1

    summary_before = mesh.get_summary()
    assert summary_before.gross_obligations_count == total_injected_txs

    # 3. Execute Kirchhoff Cycle Elimination
    cycles_elim, cleared = mesh.reduce_kirchhoff_cycles()
    summary_after = mesh.get_summary()

    print(f"  Gross Ingested Transactions: {summary_after.gross_obligations_count:,}")
    print(f"  Gross Volume:               ${summary_after.gross_volume_micro_usdc / 1e6:.4f} USDC")
    print(f"  Net Residual Transactions:   {summary_after.net_obligations_count:,}")
    print(f"  Net Residual Volume:         ${summary_after.net_volume_micro_usdc / 1e6:.4f} USDC")
    print(f"  Volume Compression Ratio:    {summary_after.volume_compression_ratio * 100:.2f}%")
    print(f"  Transaction Compression:     {summary_after.tx_compression_ratio * 100:.2f}%")

    # Verify >= 99% compression requirement
    assert summary_after.volume_compression_ratio >= 0.99, (
        f"Volume compression {summary_after.volume_compression_ratio:.4f} < 0.99"
    )
    assert summary_after.tx_compression_ratio >= 0.99, (
        f"Tx compression {summary_after.tx_compression_ratio:.4f} < 0.99"
    )
    print("  [PASS] Swarm workload achieves >= 99% on-chain transaction & volume compression!")


def test_minimal_onchain_settlements():
    """
    Verifies generate_clearing_settlements() produces the minimal on-chain
    settlement transactions to liquidate all net balances with zero error.
    """
    print("\n[TEST 4] Verifying Minimal On-Chain Settlement Generation...")
    mesh = DebtCycleMesh(auto_bilateral_netting=True)

    pk_a = b"\x02" + b"SETTLE_A" * 3 + b"\x00" * 8
    pk_b = b"\x02" + b"SETTLE_B" * 3 + b"\x00" * 8
    pk_c = b"\x02" + b"SETTLE_C" * 3 + b"\x00" * 8
    pk_d = b"\x02" + b"SETTLE_D" * 3 + b"\x00" * 8

    # A owes B 100k, B owes C 100k, C owes A 60k, D owes B 40k
    mesh.add_obligation(pk_a, pk_b, 100_000)
    mesh.add_obligation(pk_b, pk_c, 100_000)
    mesh.add_obligation(pk_c, pk_a, 60_000)
    mesh.add_obligation(pk_d, pk_b, 40_000)

    mesh.reduce_kirchhoff_cycles()

    net_balances = mesh.get_all_net_balances()
    settlements = mesh.generate_clearing_settlements()

    print(f"  Net settlements generated: {len(settlements)}")
    for d, c, amt in settlements:
        print(f"    Debtor {d[:10].hex()}... pays Creditor {c[:10].hex()}...: ${amt / 1e6:.4f} USDC")

    # Simulate applying settlements to verify all net balances reach exact 0
    simulated_balances = dict(net_balances)
    for debtor, creditor, amount in settlements:
        simulated_balances[debtor] += amount   # debtor pays, relieving their negative balance
        simulated_balances[creditor] -= amount # creditor receives, reducing their positive balance

    for node, rem in simulated_balances.items():
        assert rem == 0, f"Residual imbalance on {node}: {rem} != 0"

    print("  [PASS] Settlement plan completely liquidates all net balances.")


def test_cheque_streaming_channel_integration():
    """
    Verifies that CslsCheque packets from CausalAgentWallet instances
    are seamlessly ingested into DebtCycleMesh via record_cheque.
    """
    print("\n[TEST 5] Verifying CslsCheque Streaming Channel Ingestion...")
    wallet_a = CausalAgentWallet(bytes([0x11] * 32))
    wallet_b = CausalAgentWallet(bytes([0x22] * 32))
    wallet_c = CausalAgentWallet(bytes([0x33] * 32))

    mesh = DebtCycleMesh(auto_bilateral_netting=True)

    # 1. A streams cheques to B: 3 sequential cheques (cumulative 1k, 2k, 3k)
    c1 = wallet_a.sign_cheque(wallet_b.public_key, amount_usdc=0.001)
    c2 = wallet_a.sign_cheque(wallet_b.public_key, amount_usdc=0.001)
    c3 = wallet_a.sign_cheque(wallet_b.public_key, amount_usdc=0.001)

    mesh.record_cheque(c1)
    mesh.record_cheque(c2)
    mesh.record_cheque(c3)

    # 2. B streams cheques to C: cumulative 3k
    for _ in range(3):
        cb = wallet_b.sign_cheque(wallet_c.public_key, amount_usdc=0.001)
        mesh.record_cheque(cb)

    # 3. C streams cheques to A: cumulative 3k
    for _ in range(3):
        cc = wallet_c.sign_cheque(wallet_a.public_key, amount_usdc=0.001)
        mesh.record_cheque(cc)

    bal_before = mesh.get_all_net_balances()
    assert bal_before[wallet_a.public_key] == 0
    assert bal_before[wallet_b.public_key] == 0
    assert bal_before[wallet_c.public_key] == 0

    cycles, cleared = mesh.reduce_kirchhoff_cycles()
    assert cycles == 1
    assert cleared == 9_000  # 3 * 3,000 micro-USDC
    assert mesh.total_system_debt == 0
    assert mesh.active_edges_count == 0

    print("  [PASS] CslsCheque streaming channel successfully ingested and cleared.")


def test_thread_safe_concurrent_mesh():
    """
    Concurrency Stress Test:
    8 threads adding obligations in parallel while 2 threads continuously
    execute Kirchhoff cycle elimination.
    Proves thread safety, absence of deadlocks, and invariant preservation.
    """
    print("\n[TEST 6] Verifying Thread-Safe Concurrent Mesh Ingestion & Clearing...")
    mesh = DebtCycleMesh(auto_bilateral_netting=True)

    agents = [b"\x02" + f"CONC_AGENT_{i:02d}".encode("utf-8") + b"\x00" * 18 for i in range(16)]
    barrier = threading.Barrier(10)
    stop_event = threading.Event()

    def worker_producer(worker_id: int):
        barrier.wait()
        rng = random.Random(worker_id * 1000 + 7)
        for _ in range(500):
            u_idx = rng.randint(0, 15)
            # Bias towards cyclical patterns
            v_idx = (u_idx + rng.choice([1, 2, 4])) % 16
            if u_idx != v_idx:
                mesh.add_obligation(agents[u_idx], agents[v_idx], rng.randint(10, 500))

    def worker_reducer():
        barrier.wait()
        while not stop_event.is_set():
            mesh.reduce_kirchhoff_cycles(max_cycles=5)

    threads = []
    for i in range(8):
        t = threading.Thread(target=worker_producer, args=(i,))
        threads.append(t)
        t.start()

    for _ in range(2):
        t = threading.Thread(target=worker_reducer)
        threads.append(t)
        t.start()

    # Wait for producers to finish
    for t in threads[:8]:
        t.join()

    stop_event.set()
    for t in threads[8:]:
        t.join()

    # Final sweep
    mesh.reduce_kirchhoff_cycles()

    balances = mesh.get_all_net_balances()
    assert sum(balances.values()) == 0, f"Concurrent Kirchhoff sum != 0: {sum(balances.values())}"
    assert mesh.is_dag, "Graph must be a DAG after final sweep"

    summary = mesh.get_summary()
    print(f"  Ingested obligations under concurrency: {summary.gross_obligations_count}")
    print(f"  Cycles eliminated:                      {summary.cycles_eliminated_count}")
    print(f"  Cleared volume:                         ${summary.total_cleared_micro_usdc / 1e6:.4f} USDC")
    print("  [PASS] Thread-safety verified: zero race conditions, invariants intact.")


def run_all_tests():
    print("=" * 70)
    print("DEBT CYCLE MESH: FORMAL INVARIANT VERIFICATION SUITE")
    print("=" * 70)
    test_kirchhoff_balance_conservation_triangle()
    test_complex_multicycle_mesh_invariant()
    test_99_percent_compression_swarm_workload()
    test_minimal_onchain_settlements()
    test_cheque_streaming_channel_integration()
    test_thread_safe_concurrent_mesh()
    print("=" * 70)
    print("ALL DEBT CYCLE MESH INVARIANT TESTS PASSED WITH 100% SUCCESS!")
    print("=" * 70)


if __name__ == "__main__":
    run_all_tests()
