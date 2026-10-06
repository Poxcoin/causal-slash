# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Complete E2E full-stack lifecycle integration test:
- Stage 1: Master bond anchoring ($100.00 USDC + keccak Merkle tree of 100 subagents)
- Stage 2: Streaming 1,000 real cheques across active subagents and vendors
- Stage 3: Referral commissions (mutual debts)
- Stage 4: Agent task ring (swarm internal economy)
- Stage 5: Kirchhoff mutual debt clearing (DebtCycleMesh in RAM)
- Stage 6: Double-spend attack & Bloodhound interception (O(1) key extraction)
- Stage 7: Bloodhound latency gates
"""

from __future__ import annotations

import hashlib
import hmac
import os
import resource
import subprocess
import sys
import time

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_TEST_DIR)
if os.path.join(_ROOT, "sdk") not in sys.path:
    sys.path.insert(0, os.path.join(_ROOT, "sdk"))

from causal_slash import CausalAgentWallet, CausalVendorNode          # noqa: E402
from causal_eth import (                                              # noqa: E402
    keccak256,
    derive_subagent_sk,
    pubkey_from_sk,
    derive_address,
    build_merkle_tree,
    merkle_leaf,
    merkle_proof,
    merkle_verify,
    encode_deposit_collateral,
    encode_commit_fraud_proof,
    encode_reveal_and_slash,
    commit_hash_for,
)
from debt_cycle_mesh import DebtCycleMesh                             # noqa: E402
from swarm_stream import StreamCoordinator                            # noqa: E402
from bloodhound import BloodhoundWatchdog                             # noqa: E402

SWARM_SEED = bytes.fromhex("ca5a1511") * 8          # deterministic swarm epoch seed
MASTER_BOND_MICRO = 100_000_000                     # $100.00 USDC (6 decimals)
N_SUBAGENTS = 100
N_ACTIVE_AGENTS = 10
WAVE1_CHEQUES = 1_000
WAVE1_AMOUNT_MICRO = 100                            # $0.0001 per compute unit
WAVE2_ROUNDS = 100
WAVE2_AMOUNT_MICRO = 25                             # referral commission per round
WAVE3_ROUNDS = 20
WAVE3_RING_MICRO = 500_000                          # $0.50 task payment
WAVE3_COUNTER_MICRO = 300_000                       # $0.30 counter-ring payment
TREASURY_NODE = keccak256(b"causal-slash/treasury")
HUNTER_ADDRESS = keccak256(b"causal-slash/hunter-0x01")[:20]
BOND_BOUNTY_BPS = 1500                              # 15% guaranteed finder bounty


def _fmt_usdc(micro: int) -> str:
    return f"${micro / 1e6:,.6f}"


def _hline(title: str) -> None:
    pass


def run(with_c_gate: bool = True) -> dict:
    t_start = time.perf_counter()
    stats: dict = {}

    # ------------------------------------------------------------------ Stage 1
    _hline("[STAGE 1] MASTER BOND & SWARM MERKLE ANCHORING")
    master_sk = int.from_bytes(
        hmac.new(SWARM_SEED, b"causal-slash/master", hashlib.sha256).digest(), "big"
    ) % 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    master_pk33 = pubkey_from_sk(master_sk)
    master_address = derive_address(master_sk)

    subagent_pk: list[bytes] = []
    for i in range(N_SUBAGENTS):
        sk = derive_subagent_sk(SWARM_SEED, i)
        subagent_pk.append(pubkey_from_sk(sk))
    active_wallets: list[CausalAgentWallet] = []
    differential_mismatches = 0
    for i in range(N_ACTIVE_AGENTS):
        sk = derive_subagent_sk(SWARM_SEED, i)
        wallet = CausalAgentWallet(secret_key=sk.to_bytes(32, "big"))
        if wallet.public_key != subagent_pk[i]:
            differential_mismatches += 1
        active_wallets.append(wallet)
    assert differential_mismatches == 0, "pure-Python secp256k1 vs OpenSSL C engine mismatch"

    leaves = [merkle_leaf(pk, i) for i, pk in enumerate(subagent_pk)]
    levels, merkle_root = build_merkle_tree(leaves)
    proof_checks = 0
    for idx in (0, 41, 99):
        proof = merkle_proof(levels, idx)
        assert merkle_verify(leaves[idx], proof, idx, merkle_root)
        proof_checks += 1

    deposit_calldata = encode_deposit_collateral(MASTER_BOND_MICRO, merkle_root, master_address)
    stats["merkle_root"] = merkle_root.hex()

    # ------------------------------------------------------------------ Stage 2
    _hline("[STAGE 2] WAVE 1: 1,000 CHEQUES - 10 SUBAGENTS -> 3 VENDORS")
    vendors = {
        "LLM": CausalVendorNode(delta_v_usdc=20.0),
        "VectorDB": CausalVendorNode(delta_v_usdc=20.0),
        "WebScraper": CausalVendorNode(delta_v_usdc=20.0),
    }
    vendor_nodes = [vendors[k] for k in ("LLM", "VectorDB", "WebScraper")]
    agent_nodes = [
        CausalVendorNode(secret_key=derive_subagent_sk(SWARM_SEED, i).to_bytes(32, "big"),
                         delta_v_usdc=25.0)
        for i in range(N_ACTIVE_AGENTS)
    ]

    coord = StreamCoordinator()
    for i, w in enumerate(active_wallets):
        coord.register_wallet(f"subagent-{i}", w)
    for v in vendor_nodes + agent_nodes:
        coord.register_payee(v)

    t0 = time.perf_counter()
    for i in range(1, WAVE1_CHEQUES + 1):
        agent = active_wallets[(i - 1) % N_ACTIVE_AGENTS]
        vendor = vendor_nodes[(i - 1) % 3]
        coord.stream(agent, vendor, WAVE1_AMOUNT_MICRO, lane_height=i,
                     purpose="compute.unit")
    t1 = time.perf_counter()
    wave1_rate = WAVE1_CHEQUES / (t1 - t0)
    stats["wave1_rate"] = wave1_rate

    # ------------------------------------------------------------------ Stage 3
    _hline("[STAGE 3] WAVE 2: VENDOR REFERRAL COMMISSIONS (MUTUAL DEBT CREATION)")
    vendor_wallets = [
        CausalAgentWallet(secret_key=bytes(v._ctx.sk)) for v in vendor_nodes
    ]
    for i, w in enumerate(vendor_wallets):
        coord.register_wallet(f"vendor-{i}", w)
    for r in range(1, WAVE2_ROUNDS + 1):
        for v, vw in enumerate(vendor_wallets):
            payee = agent_nodes[(r + v) % N_ACTIVE_AGENTS]
            coord.stream(vw, payee, WAVE2_AMOUNT_MICRO, purpose="referral.commission")

    # ------------------------------------------------------------------ Stage 4
    _hline("[STAGE 4] WAVE 3: AGENT TASK RING (SWARM INTERNAL ECONOMY)")
    for r in range(1, WAVE3_ROUNDS + 1):
        for k in range(N_ACTIVE_AGENTS):
            coord.stream(active_wallets[k],
                         agent_nodes[(k + 1) % N_ACTIVE_AGENTS],
                         WAVE3_RING_MICRO, purpose="task.ring")
        for k in range(N_ACTIVE_AGENTS):
            coord.stream(active_wallets[k],
                         agent_nodes[(k + 3) % N_ACTIVE_AGENTS],
                         WAVE3_COUNTER_MICRO, purpose="task.counter_ring")
    ring_gross = WAVE3_ROUNDS * N_ACTIVE_AGENTS * (WAVE3_RING_MICRO + WAVE3_COUNTER_MICRO)

    # ------------------------------------------------------------------ Stage 5
    _hline("[STAGE 5] KIRCHHOFF MUTUAL DEBT CLEARING (DebtCycleMesh, in RAM)")
    mesh = DebtCycleMesh(treasury_node=TREASURY_NODE)
    for (payer, payee), micro in coord.edges().items():
        mesh.add_obligation(payer, payee, micro)
    gross_before = mesh.total_system_debt()
    summary = mesh.net_all()
    assert abs(sum(mesh.all_net_balances().values())) == 0, "Kirchhoff invariant violated"

    settlements = mesh.generate_clearing_settlements()
    wallet_by_pk = {w.public_key: w for w in active_wallets + vendor_wallets}
    node_by_pk = {n.public_key: n for n in vendor_nodes + agent_nodes}
    treasury_income = sum(m for (_p, q, m) in settlements if q == TREASURY_NODE)

    commercial: dict[bytes, list[tuple[int, bytes]]] = {}
    for payer, payee, micro in settlements:
        if payee == TREASURY_NODE:
            continue
        commercial.setdefault(payee, []).append((micro, payer))
    executed = 0
    for payee, items in commercial.items():
        node = node_by_pk[payee]
        node.advance_cleared(cleared_usdc=node.accumulated_usdc)
        ordered = sorted(items, key=lambda t: wallet_by_pk[t[1]]._ctx.cumulative_sent + t[0])
        for micro, payer in ordered:
            coord.stream(wallet_by_pk[payer], node, micro,
                         purpose="clearing.net_settlement")
            mesh.clear_edge(payer, payee, micro)
            executed += 1
    residual = mesh.total_system_debt()
    assert residual == summary.treasury_fee_micro, "ledger did not close to treasury fees"

    # ------------------------------------------------------------------ Stage 6
    _hline("[STAGE 6] DOUBLE-SPEND ATTACK & BLOODHOUND INTERCEPTION")
    attacker_sk = derive_subagent_sk(SWARM_SEED, 9)     # bonded subagent #9 goes rogue
    attacker = CausalAgentWallet(secret_key=attacker_sk.to_bytes(32, "big"))
    audit_vendor = CausalVendorNode(delta_v_usdc=1.0)
    assert audit_vendor.init_session(attacker.create_session(audit_vendor.public_key))
    attacker_address = derive_address(attacker_sk)

    with BloodhoundWatchdog(HUNTER_ADDRESS) as hound:
        legit = attacker.sign_cheque(audit_vendor.public_key, 0.05, session_mac=True)     # h=1
        rc1, _ = hound.inspect(legit.raw_packet[:151])
        r_legit = audit_vendor.process_cheque(legit)
        assert r_legit.accepted and rc1 == 0

        attacker._ctx.height = 1                                        # deliberate rewind
        fork = attacker.sign_cheque(audit_vendor.public_key, 0.07, session_mac=True)      # same h=1 conflicting cheque
        r_fork = audit_vendor.process_cheque(fork)
        assert not r_fork.accepted and r_fork.fraud_proof is not None, "equivocation not trapped"
        extracted = bytes(r_fork.fraud_proof.extracted_secret_key)
        true_sk = bytes(attacker._ctx.sk)
        assert extracted == true_sk, "extracted key != offender secret key"

        rc2, payload = hound.inspect(fork.raw_packet[:151])
        assert rc2 == 1, "bloodhound failed to capture equivocation"

        py_commit = commit_hash_for(extracted, HUNTER_ADDRESS, bytes(payload.commit_salt))
        assert py_commit == bytes(payload.commit_hash), "C/Python keccak divergence"

        derived_from_extracted = derive_address(int.from_bytes(extracted, "big"))
        assert derived_from_extracted == attacker_address

        commit_calldata = encode_commit_fraud_proof(attacker_address, py_commit)
        reveal_calldata = encode_reveal_and_slash(attacker_address,
                                                  int.from_bytes(extracted, "big"),
                                                  bytes(payload.commit_salt))

        bond = MASTER_BOND_MICRO
        bounty = bond * BOND_BOUNTY_BPS // 10_000
        remaining = bond - bounty
        exposure_observed = audit_vendor.accumulated_usdc
        restitution = min(remaining, int(exposure_observed * 1e6))
        remaining -= restitution
        insurance = remaining * 60 // 100
        treasury = remaining - insurance

    stats["attacker_address"] = attacker_address.hex()
    stats["commit_hash"] = py_commit.hex()

    # ------------------------------------------------------------------ Stage 7
    _hline("[STAGE 7] BLOODHOUND LATENCY GATES")
    timing_hound = BloodhoundWatchdog(HUNTER_ADDRESS)
    timing_wallet = CausalAgentWallet()
    target_pk = b"\x02" + b"\x11" * 32
    N_TIMING = 200_000
    t0 = time.perf_counter()
    for _ in range(N_TIMING):
        cheque = timing_wallet.sign_cheque(target_pk, 0.0001)
        timing_hound.inspect(cheque.raw_packet)
    t1 = time.perf_counter()
    ffi_ns_per_op = (t1 - t0) / N_TIMING * 1e9
    timing_hound.close()
    gate_rc = None
    if with_c_gate:
        for target in ("test-bloodhound", "test-bloodhound-strict"):
            proc = subprocess.run(["make", target], cwd=_ROOT,
                                  capture_output=True, text=True, timeout=300)
            assert proc.returncode == 0, f"{target} failed (rc={proc.returncode}):\n{proc.stdout[-2000:]}"
    stats["ffi_ns_per_op"] = ffi_ns_per_op
    stats["c_gate_rc"] = gate_rc

    # ------------------------------------------------------------------ Report
    rss_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    elapsed = time.perf_counter() - t_start
    stats.update({
        "total_cheques": coord.total_cheques,
        "total_streamed_micro": coord.total_streamed_micro,
        "compression_ratio": summary.compression_ratio,
        "treasury_fee_micro": summary.treasury_fee_micro,
        "cycles_resolved": summary.cycles_resolved,
        "treasury_income_micro": treasury_income,
        "peak_rss_mb": rss_mb,
        "elapsed_s": elapsed,
    })
    return stats


def test_full_stack_e2e_all_stages():
    """
    Runs the complete E2E (streaming, Kirchhoff clearing, double-spend,
    Bloodhound, calldata). The C-level 35ns gate is skipped here because it
    compiles a sanitizer build; it is asserted by the example itself and by
    `make test-bloodhound`.
    """
    stats = run(with_c_gate=False)

    assert stats["total_cheques"] >= 1_700
    assert stats["total_streamed_micro"] > 160_000_000
    assert stats["compression_ratio"] >= 0.99, "netting compression below 99%"
    assert stats["cycles_resolved"] > 0
    assert stats["treasury_fee_micro"] > 0
    assert stats["treasury_income_micro"] == stats["treasury_fee_micro"]
    # Fraud chain closed end-to-end:
    assert len(stats["commit_hash"]) == 64
    assert len(stats["attacker_address"]) == 40
    # Honest FFI measurement exists (Python path; ~tens of microseconds).
    assert 0 < stats["ffi_ns_per_op"] < 100_000
    assert stats["peak_rss_mb"] < 1500
