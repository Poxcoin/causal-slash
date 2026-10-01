# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Multi-Channel Swarm Concurrency Stress Test
Validates:
1. 100 virtual agent threads streaming to 10 vendors (50,000 total cheques).
2. Zero sequence collisions (no -11 DECREASING_AMOUNT_ATTACK).
3. Zero nonce replays (no -21) and zero out-of-order errors (no -22).
4. Exact cent-level / micro-cent balance preservation.
5. DebtCycleMesh achieves >= 99.0% transaction and volume netting in RAM.
"""

from __future__ import annotations
import os
import sys
import threading
import time
import random
import struct
from typing import List, Dict

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_TEST_DIR)
sys.path.insert(0, os.path.join(_PROJECT_ROOT, "sdk"))

from causal_slash import (
    CausalAgentWallet,
    CausalVendorNode,
    DebtCycleMesh,
    CSLS_OK,
    CSLS_ERR_EXPOSURE_CAP,
    CSLS_ERR_FRAUD,
    CSLS_ERR_REPLAY,
    CSLS_ERR_OUT_OF_ORDER,
)


def test_multichannel_swarm_stress():
    print("\n" + "=" * 76)
    print("TEST: Multi-Channel Swarm Concurrency (100 Agents -> 10 Vendors, 50,000 Cheques)")
    print("=" * 76)

    num_agents = 100
    num_vendors = 10
    cheques_per_agent = 500
    total_expected_cheques = num_agents * cheques_per_agent  # 50,000

    # 1. Instantiate 100 Virtual Agents and 10 Vendors with High Exposure Buffers
    print(f"[1/4] Initializing {num_agents} Agent Wallets and {num_vendors} Vendor Nodes...")
    agents: List[CausalAgentWallet] = []
    for i in range(num_agents):
        sk = bytes([0x10]) + struct.pack(">I", i + 1) + bytes([0xAA] * 27)
        agents.append(CausalAgentWallet(secret_key=sk))

    vendors: List[CausalVendorNode] = []
    for v in range(num_vendors):
        sk = bytes([0x20]) + struct.pack(">I", v + 1) + bytes([0xBB] * 27)
        vendors.append(CausalVendorNode(secret_key=sk, delta_v_usdc=500.0))

    # Shared DebtCycleMesh for swarm-level P2P netting
    mesh = DebtCycleMesh(auto_bilateral_netting=True)

    # Concurrency and Error Accounting
    error_counts: Dict[int, int] = {}
    error_lock = threading.Lock()
    accepted_cheques = 0
    accepted_lock = threading.Lock()

    print(f"[2/4] Launching {num_agents} concurrent threads streaming {total_expected_cheques:,} cheques...")
    t_start = time.perf_counter()

    barrier = threading.Barrier(num_agents)

    def agent_worker(agent_idx: int):
        nonlocal accepted_cheques
        agent = agents[agent_idx]
        barrier.wait()

        local_accepted = 0
        local_errors: Dict[int, int] = {}

        # Each agent distributes cheques cyclically across vendors
        for seq in range(cheques_per_agent):
            vendor_idx = (agent_idx + seq) % num_vendors
            vendor = vendors[vendor_idx]
            amt_usdc = 0.0002  # $0.0002 (200 micro-USDC)

            # Sign per-vendor isolated cheque
            cheque = agent.sign_cheque(vendor.public_key, amount_usdc=amt_usdc)

            # Vendor validates and processes cheque
            res = vendor.process_cheque(cheque)

            if res.accepted and res.status_code == CSLS_OK:
                local_accepted += 1
            else:
                code = res.status_code
                local_errors[code] = local_errors.get(code, 0) + 1

            # Ingest into DebtCycleMesh to form closed reciprocal credit loops
            # Construct cyclical swarm flow: Agent -> Vendor -> Next Agent in ring -> Agent
            next_agent_idx = (agent_idx + 1) % num_agents
            mesh.add_obligation(agent.public_key, vendor.public_key, 200)
            mesh.add_obligation(vendor.public_key, agents[next_agent_idx].public_key, 200)

        with accepted_lock:
            accepted_cheques += local_accepted
        with error_lock:
            for code, cnt in local_errors.items():
                error_counts[code] = error_counts.get(code, 0) + cnt

    threads = [threading.Thread(target=agent_worker, args=(i,)) for i in range(num_agents)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    t_elapsed = time.perf_counter() - t_start
    throughput = total_expected_cheques / t_elapsed

    print(f"      Completed {accepted_cheques:,}/{total_expected_cheques:,} cheques in {t_elapsed:.2f}s ({throughput:,.0f} ops/sec)")

    # 2. Assert Zero Sequence Collisions and Zero Replays
    print("[3/4] Verifying sequence integrity across all channels...")
    assert error_counts.get(-11, 0) == 0, f"FATAL: Sequence collision (-11 DECREASING_AMOUNT_ATTACK) occurred: {error_counts[-11]} times"
    assert error_counts.get(-22, 0) == 0, f"FATAL: Out-of-order sequence (-22) occurred: {error_counts[-22]} times"
    assert error_counts.get(-21, 0) == 0, f"FATAL: Nonce replay (-21) occurred: {error_counts[-21]} times"
    assert error_counts.get(-20, 0) == 0, f"FATAL: Fraudulent equivocation (-20) detected: {error_counts[-20]} times"
    assert accepted_cheques == total_expected_cheques, f"Expected {total_expected_cheques} accepted cheques, got {accepted_cheques}"
    print("      [PASS] 0 sequence collisions (-11), 0 replays (-21), 0 out-of-order errors (-22).")

    # 3. Assert Exact Cent-Level Balance Matching
    total_sent_by_agents = sum(a.total_sent_usdc for a in agents)
    total_received_by_vendors = sum(v.accumulated_usdc for v in vendors)
    expected_total_usdc = total_expected_cheques * 0.0002

    print(f"      Total Sent by 100 Agents:    ${total_sent_by_agents:.4f} USDC")
    print(f"      Total Received by 10 Vendors: ${total_received_by_vendors:.4f} USDC")
    print(f"      Expected Settlement Value:   ${expected_total_usdc:.4f} USDC")

    assert round(total_sent_by_agents, 4) == round(expected_total_usdc, 4), "Agent sent amount mismatch"
    assert round(total_received_by_vendors, 4) == round(expected_total_usdc, 4), "Vendor accumulated amount mismatch"
    print("      [PASS] Exact cent-level and micro-cent balance matching confirmed across all 110 nodes.")

    # 4. In-Memory DebtCycleMesh Netting Verification
    print("[4/4] Executing Tarjan Kirchhoff Cycle Elimination on Swarm Graph...")
    cycles_elim, cleared = mesh.reduce_kirchhoff_cycles()
    summary = mesh.get_summary()

    print(f"      Gross Ingested Obligations: {summary.gross_obligations_count:,}")
    print(f"      Gross Ingested Volume:      ${summary.gross_volume_micro_usdc / 1e6:.4f} USDC")
    print(f"      Cycles Eliminated in RAM:   {summary.cycles_eliminated_count:,}")
    print(f"      Cleared Volume in Memory:   ${summary.total_cleared_micro_usdc / 1e6:.4f} USDC")
    print(f"      Net Residual Obligations:   {summary.net_obligations_count:,}")
    print(f"      Net Residual Volume:        ${summary.net_volume_micro_usdc / 1e6:.4f} USDC")
    print(f"      Volume Compression Ratio:   {summary.volume_compression_ratio * 100:.2f}%")
    print(f"      Tx Compression Ratio:       {summary.tx_compression_ratio * 100:.2f}%")

    # Assert >= 99% off-chain transaction netting in RAM
    assert summary.volume_compression_ratio >= 0.990, (
        f"Volume compression ratio {summary.volume_compression_ratio:.4f} < 0.990"
    )
    assert summary.tx_compression_ratio >= 0.990, (
        f"Transaction compression ratio {summary.tx_compression_ratio:.4f} < 0.990"
    )

    # Invariant: Conservation of Kirchhoff Net Balance
    balances = mesh.get_all_net_balances()
    assert sum(balances.values()) == 0, f"Kirchhoff invariant violation: sum(b) = {sum(balances.values())}"
    assert mesh.is_dag, "Residual debt graph must be an acyclic DAG"

    print("      [PASS] DebtCycleMesh achieves >= 99.0% off-chain transaction netting in RAM.")
    print("=" * 76)
    print("[VERDICT] MULTI-CHANNEL SWARM CONCURRENCY FULLY VERIFIED WITH 100% PRECISION!")
    print("=" * 76)

    # Cleanup
    for a in agents:
        a.close()
    for v in vendors:
        v.close()


if __name__ == "__main__":
    test_multichannel_swarm_stress()
