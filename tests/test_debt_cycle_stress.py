# SPDX-License-Identifier: Apache-2.0
"""
Quantitative Stress Testing & Systems Verification Suite for DebtCycleMesh.
Tests:
1. 100+ node random directed graphs, dense clique networks, disjoint cycles.
2. Extreme edge case fee calculation: 1 micro-USDC, prime participants, integer conservation.
3. Adversarial cycle injection & signature verification analysis.
"""

import hashlib
import os
import random
import sys
import time
from typing import List, Tuple

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(_ROOT, "sdk"))

from debt_cycle_mesh import DebtCycleMesh, DebtCycleMeshError, NettingCancellationCertificate


def make_node(i: int) -> bytes:
    # 33-byte compressed secp256k1 key format
    return b"\x02" + hashlib.sha256(f"node_{i}".encode()).digest()[:32]


def test_100_node_random_directed_graph():
    print("\n--- TEST: 100+ Node Random Directed Graph Cycle Annihilation ---")
    rng = random.Random(1337)
    num_nodes = 120
    nodes = [make_node(i) for i in range(num_nodes)]
    treasury = make_node(9999)
    mesh = DebtCycleMesh(treasury_node=treasury)

    # Generate random edges
    edges_added = 0
    for _ in range(500):
        u, v = rng.sample(nodes, 2)
        amt = rng.randint(10, 50_000)
        mesh.add_obligation(u, v, amt)
        edges_added += 1

    initial_debt = mesh.total_system_debt()
    initial_balances = mesh.all_net_balances()
    assert sum(initial_balances.values()) == 0, "Initial conservation violated"
    print(f"Generated {edges_added} edges across {num_nodes} nodes. Total debt: {initial_debt} micro-USDC")

    t0 = time.perf_counter()
    sccs = mesh.tarjan_sccs()
    t_tarjan = time.perf_counter() - t0
    scc_sizes = [len(s) for s in sccs if len(s) >= 2]
    print(f"Tarjan SCC detection in {t_tarjan*1000:.2f}ms. Found {len(scc_sizes)} non-trivial SCCs: {scc_sizes[:10]}...")

    t0 = time.perf_counter()
    summary = mesh.net_all()
    t_net = time.perf_counter() - t0

    print(f"net_all completed in {t_net*1000:.2f}ms.")
    print(f"Cycles resolved: {summary.cycles_resolved}")
    print(f"Gross volume before: {summary.gross_volume_micro} micro-USDC")
    print(f"Residual volume: {summary.residual_volume_micro} micro-USDC")
    print(f"Annihilated volume: {summary.annihilated_volume_micro} micro-USDC")
    print(f"Treasury fee: {summary.treasury_fee_micro} micro-USDC")
    print(f"Compression ratio: {summary.compression_ratio:.4%}")

    # Check post-netting invariants
    post_balances = mesh.all_net_balances()
    assert sum(post_balances.values()) == 0, "Kirchhoff conservation violated post-netting"
    # Post-netting graph must be a DAG (no SCC >= 2)
    post_sccs = [s for s in mesh.tarjan_sccs() if len(s) >= 2]
    assert len(post_sccs) == 0, f"Graph is not a DAG! Remaining SCCs: {post_sccs}"
    # Verify minimal residual volume == sum(|net_balance|) // 2
    expected_minimal = sum(abs(b) for b in post_balances.values()) // 2
    assert mesh.total_system_debt() == expected_minimal, f"Residual volume {mesh.total_system_debt()} != minimal {expected_minimal}"
    print("PASS: 100+ node random directed graph netting verified successfully.")


def test_dense_clique_networks():
    print("\n--- TEST: Dense Clique Networks (Complete Directed Graphs) ---")
    for clique_size in [10, 20]:
        nodes = [make_node(i) for i in range(clique_size)]
        treasury = make_node(9999)
        mesh = DebtCycleMesh(treasury_node=treasury)

        # Complete directed graph: every pair has directed edges in both directions
        rng = random.Random(42 + clique_size)
        total_edges = 0
        for i in range(clique_size):
            for j in range(clique_size):
                if i != j:
                    amt = rng.randint(100, 10_000)
                    mesh.add_obligation(nodes[i], nodes[j], amt)
                    total_edges += 1

        print(f"Testing K_{clique_size} complete clique ({total_edges} edges)...")
        t0 = time.perf_counter()
        summary = mesh.net_all()
        t_elapsed = time.perf_counter() - t0
        print(f"K_{clique_size} resolved in {t_elapsed*1000:.2f}ms. Cycles resolved: {summary.cycles_resolved}. Edges after: {summary.edges_after}")

        post_balances = mesh.all_net_balances()
        assert sum(post_balances.values()) == 0, "Conservation violated in clique"
        post_sccs = [s for s in mesh.tarjan_sccs() if len(s) >= 2]
        assert len(post_sccs) == 0, "Clique not reduced to DAG"
        print(f"PASS: K_{clique_size} dense clique verified.")


def test_disjoint_cycles():
    print("\n--- TEST: Multiple Disjoint Cycles Running Concurrently ---")
    mesh = DebtCycleMesh(treasury_node=make_node(9999))
    num_cycles = 15
    cycle_lengths = [3, 4, 5, 6, 7]

    node_counter = 0
    total_cycles_expected = num_cycles
    for c in range(num_cycles):
        length = cycle_lengths[c % len(cycle_lengths)]
        cycle_nodes = [make_node(node_counter + i) for i in range(length)]
        node_counter += length
        amt = 1000 * (c + 1)
        for i in range(length):
            mesh.add_obligation(cycle_nodes[i], cycle_nodes[(i + 1) % length], amt)

    print(f"Injected {num_cycles} completely disjoint cycles ({node_counter} total nodes).")
    sccs = [s for s in mesh.tarjan_sccs() if len(s) >= 2]
    assert len(sccs) == num_cycles, f"Expected {num_cycles} SCCs, got {len(sccs)}"

    summary = mesh.net_all()
    print(f"Disjoint cycles resolved: {summary.cycles_resolved}. Annihilated: {summary.annihilated_volume_micro} micro-USDC")
    assert summary.cycles_resolved == num_cycles
    post_balances = mesh.all_net_balances()
    assert sum(post_balances.values()) == 0, "Conservation violated for disjoint cycles"
    print("PASS: Disjoint cycles verified.")


def test_fee_calculation_and_integer_conservation_edge_cases():
    print("\n--- TEST: Fee Calculation Edge Cases & Exact Integer Conservation ---")
    treasury = make_node(8888)

    # Edge Case 1: 1 micro-USDC obligations
    # 0.01% of 1 micro-USDC is 0.0001 micro-USDC -> integer division truncates to 0
    mesh1 = DebtCycleMesh(treasury_node=treasury)
    a, b, c = make_node(1), make_node(2), make_node(3)
    mesh1.add_obligation(a, b, 1)
    mesh1.add_obligation(b, c, 1)
    mesh1.add_obligation(c, a, 1)

    assert sum(mesh1.all_net_balances().values()) == 0
    summary1 = mesh1.net_all()
    assert summary1.annihilated_volume_micro == 3
    # 3 * 100 // 1_000_000 == 0
    assert summary1.treasury_fee_micro == 0
    assert sum(mesh1.all_net_balances().values()) == 0
    print("Edge Case 1 (1 micro-USDC): Annihilated with fee=0, integer conservation preserved.")

    # Edge Case 2: Odd prime participants and large prime amounts
    # Primes: 3, 5, 7, 11, 13, 17, 19, 23, 29, 31
    primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
    large_prime_amounts = [999983, 1000003, 104729, 7919, 100000007]

    for p_nodes in primes:
        for p_amt in large_prime_amounts:
            mesh_p = DebtCycleMesh(treasury_node=treasury)
            ring_nodes = [make_node(1000 + i) for i in range(p_nodes)]
            for i in range(p_nodes):
                mesh_p.add_obligation(ring_nodes[i], ring_nodes[(i + 1) % p_nodes], p_amt)

            bal_pre = mesh_p.all_net_balances()
            assert sum(bal_pre.values()) == 0, f"Pre-netting conservation failed for p={p_nodes}, amt={p_amt}"

            summary_p = mesh_p.net_all()
            bal_post = mesh_p.all_net_balances()
            net_sum = sum(bal_post.values())
            assert net_sum == 0, f"CRITICAL: Conservation violated by {net_sum} micro-USDC for p={p_nodes}, amt={p_amt}!"

            # Verify exact treasury fee accounting
            annihilated = p_nodes * p_amt
            expected_fee = (annihilated * 100) // 1_000_000
            assert summary_p.treasury_fee_micro == expected_fee, f"Fee mismatch: {summary_p.treasury_fee_micro} != {expected_fee}"

            # Verify that sum of fee obligations created equals expected_fee
            treasury_credit = bal_post.get(treasury, 0)
            assert treasury_credit == expected_fee, f"Treasury balance {treasury_credit} != expected_fee {expected_fee}"

    print(f"Edge Case 2 (Odd prime participants & large prime amounts): Tested {len(primes) * len(large_prime_amounts)} combinations. Integer conservation sum(net_balances) == 0 held with 0 wei drift.")

    # Edge Case 3: Treasury node inside the cycle
    print("Testing Treasury node as participant in cycle...")
    mesh_tr = DebtCycleMesh(treasury_node=treasury)
    node_x = make_node(701)
    node_y = make_node(702)
    mesh_tr.add_obligation(node_x, node_y, 10_000_000)
    mesh_tr.add_obligation(node_y, treasury, 10_000_000)
    mesh_tr.add_obligation(treasury, node_x, 10_000_000)

    try:
        mesh_tr.net_all()
        print("Treasury in cycle: net_all completed successfully.")
    except Exception as e:
        print(f"Treasury in cycle: RAISED EXCEPTION: {type(e).__name__}: {e}")


def test_adversarial_cycle_injection():
    print("\n--- TEST: Adversarial Cycle Injection & Signature Verification ---")
    treasury = make_node(9999)
    mesh = DebtCycleMesh(treasury_node=treasury)

    victim_a = make_node(101)
    victim_b = make_node(102)
    attacker = make_node(666)

    # Legitimate debt: victim_a owes victim_b 1,000,000 micro-USDC ($1.00)
    mesh.add_obligation(victim_a, victim_b, 1_000_000)

    # Attacker injects fake obligations WITHOUT signatures:
    # Attacker claims: victim_b owes attacker 1,000,000
    # Attacker claims: attacker owes victim_a 1,000,000
    # Forming a cycle: victim_a -> victim_b -> attacker -> victim_a
    mesh.add_obligation(victim_b, attacker, 1_000_000)
    mesh.add_obligation(attacker, victim_a, 1_000_000)

    print("Injected fake cycle: victim_a (honest) -> victim_b (honest) -> attacker (fake) -> victim_a (fake)")
    print(f"Mesh has {mesh.active_edges_count()} edges before netting.")

    summary = mesh.net_all()
    print(f"Netting executed: {summary.cycles_resolved} cycles resolved. Annihilated: {summary.annihilated_volume_micro} micro-USDC.")
    print("Certificates generated:")
    for cert in summary.certificates:
        valid_digest = cert.verify()
        has_debtor_sk = cert.debtor in mesh._key_registry
        has_creditor_sk = cert.creditor in mesh._key_registry
        print(f"  Cert: {cert.debtor[:6].hex()}... -> {cert.creditor[:6].hex()}... | "
              f"cancelled: {cert.cancelled_amount_micro} | digest_valid: {valid_digest} | "
              f"has_debtor_sk: {has_debtor_sk} | has_creditor_sk: {has_creditor_sk} | "
              f"debtor_sig_len: {len(cert.debtor_signature)}")

    print(f"Post-netting edges: {mesh.edges}")
    print(f"Post-netting balances: {mesh.all_net_balances()}")


if __name__ == "__main__":
    test_100_node_random_directed_graph()
    test_dense_clique_networks()
    test_disjoint_cycles()
    test_fee_calculation_and_integer_conservation_edge_cases()
    test_adversarial_cycle_injection()
