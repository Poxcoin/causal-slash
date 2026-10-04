#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Causal-Slash Protocol: Machine-to-Machine (M2M) P2P Quickstart
Demonstrates zero-gas autonomous agent commerce:
1. Agent 1 (Orchestrator) initializes session with Agent 2 (Worker Node).
2. Agent 1 delegates tasks and streams monotonic 167-byte Session MAC cheques.
3. Agent 2 verifies cheques at microsecond speed with zero gas drag.
4. Mathematical equivocation trapping extracts attacker private key in O(1).
5. Final cumulative settlement calldata is generated for Base L2 on-chain claim.
"""

import os
import sys
import time

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if os.path.join(_ROOT, "sdk") not in sys.path:
    sys.path.insert(0, os.path.join(_ROOT, "sdk"))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from causal_slash import (
    CausalAgentWallet,
    CausalVendorNode,
    CSLS_OK,
    CSLS_ERR_FRAUD,
)
from causal_eth import (
    function_selector,
    keccak256,
)


def run_m2m_quickstart():
    print("================================================================================")
    print("CAUSAL-SLASH PROTOCOL: AUTONOMOUS M2M P2P CLEARING QUICKSTART")
    print("================================================================================")

    # 1. Initialize Autonomous Agent Identities (secp256k1)
    print("[1/5] Initializing Autonomous Agent Identities...")
    # Agent 1 (Orchestrator / Buyer)
    agent_orchestrator = CausalAgentWallet()
    # Agent 2 (Worker / Provider Node with $5.00 unconfirmed credit buffer)
    agent_worker = CausalVendorNode(delta_v_usdc=5.0)

    print(f"  Agent 1 (Orchestrator) PK: {agent_orchestrator.public_key_hex}")
    print(f"  Agent 2 (Worker Node)   PK: {agent_worker.public_key_hex}")
    print(f"  Bounded Exposure Limit  : ${agent_worker._ctx.max_exposure_delta_v / 1e6:.2f} USDC (delta_v)")

    # 2. Cryptographic Session Handshake (Static-Static ECDH + SipHash-128 KDF)
    print("\n[2/5] Initiating Mutual Session Handshake (C2 Gate)...")
    init_packet = agent_orchestrator.create_session(agent_worker.public_key)
    session_ok = agent_worker.init_session(init_packet)
    assert session_ok, "Session handshake failed"
    print("  Session active: 167-byte Session MAC authenticated wire channel established.")

    # 3. Stream Micro-Tasks with Real-Time 167-Byte Cheques
    print("\n[3/5] Streaming M2M Micro-Tasks with Sub-Microsecond Settlement...")
    tasks = [
        "Task #1: Distributed web crawl and raw text extraction",
        "Task #2: Tokenization and neural embeddings generation",
        "Task #3: Cross-source factual verification",
        "Task #4: Deduplication and knowledge graph indexing",
        "Task #5: Final synthesized intelligence report delivery",
    ]

    price_per_task_usdc = 0.0005  # 500 micro-USDC per task
    total_latency_us = 0.0

    for idx, task_name in enumerate(tasks, start=1):
        # Agent 1 creates and signs monotonic 167-byte Session MAC cheque
        t_sign_start = time.perf_counter()
        cheque = agent_orchestrator.sign_cheque(
            agent_worker.public_key,
            amount_usdc=price_per_task_usdc,
            session_mac=True,
        )
        t_sign_end = time.perf_counter()
        assert len(cheque.raw_packet) == 167, f"Expected 167 bytes, got {len(cheque.raw_packet)}"

        # Agent 2 verifies cheque packet over wire
        t_verify_start = time.perf_counter()
        result = agent_worker.process_cheque(cheque.raw_packet)
        t_verify_end = time.perf_counter()

        verify_latency_us = (t_verify_end - t_verify_start) * 1_000_000
        total_latency_us += verify_latency_us

        assert result.accepted, f"Worker rejected valid cheque: {result.error_message}"

        # Worker delivers computation output
        print(f"  [{idx}/5] {task_name}")
        print(f"        Wire Cheque : seq={cheque.height} | packet=167 bytes | verify_latency={verify_latency_us:.2f} us")
        print(f"        Ledger State: settled=${agent_worker.accumulated_usdc:.4f} USDC | on-chain gas=0")

    avg_latency_us = total_latency_us / len(tasks)
    print(f"\n  All tasks processed successfully! Average wire verification latency: {avg_latency_us:.2f} us")

    # 4. Economic Security Verification: O(1) Double-Sign Slashing
    print("\n[4/5] Testing Economic Deterrence (O(1) Equivocation Slashing)...")
    rogue_agent = CausalAgentWallet()
    honest_worker = CausalVendorNode(delta_v_usdc=10.0)
    assert honest_worker.init_session(rogue_agent.create_session(honest_worker.public_key))

    # Legitimate cheque at sequence height 1
    valid_cheque = rogue_agent.sign_cheque(honest_worker.public_key, amount_usdc=0.01, session_mac=True)
    honest_worker.process_cheque(valid_cheque.raw_packet)

    # Malicious double-spending attempt: signing a conflicting cheque at height 1
    rogue_agent._ctx.height = 1
    conflicting_cheque = rogue_agent.sign_cheque(honest_worker.public_key, amount_usdc=0.02, session_mac=True)

    fraud_res = honest_worker.process_cheque(conflicting_cheque.raw_packet)
    assert not fraud_res.accepted, "Fraudulent double-signing was unexpectedly accepted"
    assert fraud_res.status_code == CSLS_ERR_FRAUD, "Expected CSLS_ERR_FRAUD status"
    assert fraud_res.fraud_proof is not None, "Worker failed to construct mathematical fraud proof"

    extracted_sk = fraud_res.fraud_proof.extracted_secret_key
    print(f"  Double-spend trapped at seq=1! Slashing trigger executed.")
    print(f"  Extracted Offender Private Key: 0x{extracted_sk.hex()}")
    assert extracted_sk == bytes(rogue_agent._ctx.sk), "Algebraically extracted key does not match offender key"
    print("  Mathematical key extraction verified: 100% collateral bond subject to forfeiture.")

    # 5. On-Chain Settlement Finalization (Base L2)
    print("\n[5/5] On-Chain Settlement Finalization (Base L2)...")
    final_settled_usdc = agent_worker.accumulated_usdc
    final_settled_micro = int(round(final_settled_usdc * 1e6))
    final_height = agent_orchestrator._ctx.height

    vault_address = "0x901c98Da847DD24ff23FcC37B6D1549A17F12253"  # Base Sepolia
    agent_addr = "0x" + keccak256(agent_orchestrator.public_key[1:])[12:].hex()
    worker_addr = "0x" + keccak256(agent_worker.public_key[1:])[12:].hex()

    selector = function_selector("settleCheque(address,uint256,uint256,uint256,bytes)")

    print(f"  Base Sepolia Vault : {vault_address}")
    print(f"  Payer Address (L2) : {agent_addr}")
    print(f"  Worker Address (L2): {worker_addr}")
    print(f"  Total Batches Run  : {len(tasks)} requests")
    print(f"  Gross Volume       : ${final_settled_usdc:.6f} USDC ({final_settled_micro} micro-USDC)")
    print(f"  Channel Sequence   : {final_height}")
    print(f"  On-chain Tx Count  : Exactly 1 final settlement transaction required!")
    print(f"  Off-chain Gas Saved: 100% (zero gas spent during active task streaming)")
    print(f"  Calldata Selector  : 0x{selector.hex()} (settleCheque)")
    print("================================================================================")
    print("M2M P2P QUICKSTART COMPLETE: ALL VERIFICATION INVARIANTS PASSED")
    print("================================================================================")


if __name__ == "__main__":
    run_m2m_quickstart()
