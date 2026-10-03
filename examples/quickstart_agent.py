# SPDX-License-Identifier: Apache-2.0
"""
Causal-Slash Protocol: Minimalist Autonomous Agent Integration
Demonstrates streaming micro-cheques for LLM token inference.
"""

import sys
import os

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(_ROOT, "sdk"))
sys.path.insert(0, _ROOT)
from causal_slash import CausalAgentWallet, CausalVendorNode

def run_agent_workflow():
    print("[agent] session starting...")
    agent = CausalAgentWallet()
    vendor = CausalVendorNode(delta_v_usdc=0.50)

    print(f"[agent] wallet_pk:  {agent.public_key_hex[:22]}...")
    print(f"[vendor] endpoint:  {vendor.public_key_hex[:22]}...")
    print(f"[channel] buffer:   ${vendor._ctx.max_exposure_delta_v / 1e6:.2f} USDC")

    # Authenticated Session MAC channel (C2 gate): vendors mandate Session MAC
    # by default because wire cheques omit the Schnorr point R.
    assert vendor.init_session(agent.create_session(vendor.public_key))

    print("[stream] streaming 50 batches (500 tokens total)...")
    num_token_batches = 50
    total_cost_usdc = 0.0

    for batch_idx in range(1, num_token_batches + 1):
        cheque = agent.sign_cheque(vendor.public_key, amount_usdc=0.0001, session_mac=True)
        res = vendor.process_cheque(cheque)
        assert res.accepted, f"rejected: {res.error_message}"
        total_cost_usdc += 0.0001

        if batch_idx % 10 == 0:
            print(f"  batch {batch_idx:02d}/50: 10 tokens delivered | seq={cheque.height} | settled=${vendor.accumulated_usdc:.4f}")

    print(f"[stream] completed: 500 tokens | total=${total_cost_usdc:.4f} USDC | gas=0")

    # Equivocation detection test
    print("[security] testing double-signing detection...")
    attacker = CausalAgentWallet()
    v2 = CausalVendorNode(delta_v_usdc=1.0)
    assert v2.init_session(attacker.create_session(v2.public_key))

    c1 = attacker.sign_cheque(v2.public_key, amount_usdc=0.01, session_mac=True)
    v2.process_cheque(c1)

    attacker._ctx.height = 1
    c2 = attacker.sign_cheque(v2.public_key, amount_usdc=0.02, session_mac=True)

    fraud_res = v2.process_cheque(c2)
    assert not fraud_res.accepted
    print(f"  equivocation caught at seq=1 (code {fraud_res.status_code})")
    print(f"  extracted_sk: 0x{fraud_res.fraud_proof.extracted_secret_key.hex()[:24]}...")
    print("[security] fraud proof verified.")

if __name__ == "__main__":
    run_agent_workflow()
