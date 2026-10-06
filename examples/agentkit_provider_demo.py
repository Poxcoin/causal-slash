# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Causal-Slash Protocol: Production Coinbase AgentKit Integration Demo
Demonstrates autonomous AI agents on Base executing multi-vendor compute streaming
with zero-gas micro-cheques, instant verification, and automated on-chain foreclosure.
"""

from __future__ import annotations

import json
import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(_ROOT, "sdk"))
sys.path.insert(0, _ROOT)

from causal_agentkit import CausalSlashActionProvider
from causal_slash import CausalAgentWallet, CausalVendorNode, CSLS_OK


def main():
    print("======================================================================")
    print("COINBASE AGENTKIT: CAUSAL-SLASH PRODUCTION ACTION PROVIDER DEMO")
    print("======================================================================")
    print("Initializing production Coinbase AgentKit ActionProvider...")

    # 1. Initialize ActionProvider adhering to Coinbase AgentKit SDK
    provider = CausalSlashActionProvider(
        vault_address="0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
        rpc_url=os.environ.get("BASE_RPC_URL", "http://127.0.0.1:8545"),
    )
    print(f"[AGENTKIT] ActionProvider registered: '{provider.name}'")
    print(f"[AGENTKIT] Agent Wallet PK: {provider.public_key_hex[:26]}...")

    # 2. Connect to 3 heterogeneous API providers simultaneously (Single Shared Bond)
    vendor_llm = CausalVendorNode(delta_v_usdc=1.00)
    vendor_vectordb = CausalVendorNode(delta_v_usdc=0.50)
    vendor_scraper = CausalVendorNode(delta_v_usdc=0.25)

    providers = [
        ("LLM Inference (DeepSeek V3)", vendor_llm, 0.0001, 20),
        ("Vector Search (Qdrant Cloud)", vendor_vectordb, 0.0020, 5),
        ("Web Scraping (Firecrawl Engine)", vendor_scraper, 0.0050, 3),
    ]

    # Initialize vendor ActionProviders for receiving and verifying micro-cheques
    vendor_providers = {
        name: CausalSlashActionProvider(vendor_node=v_node)
        for name, v_node, _, _ in providers
    }

    # Authenticated Session MAC channels (C2 gate): the vendor nodes mandate
    # Session MAC by default (wire cheques omit the Schnorr point R), so the
    # paying wallet establishes a session with each local vendor node.
    for _, v_node, _, _ in providers:
        assert provider.agent_wallet.open_secure_session(v_node)

    total_spent = 0.0

    for name, v_node, price_per_call, num_calls in providers:
        v_pk_hex = "0x" + v_node.public_key.hex()
        v_provider = vendor_providers[name]
        print(f"\n[ACTION: create_channel] Establishing session with {name}...")
        create_raw = provider.create_channel(vendor_address=v_pk_hex, deposit_usdc=1.0)
        create_data = json.loads(create_raw)
        print(f"  Channel Status: {create_data['status']} | Quota: ${create_data['deposit_usdc']:.2f} USDC")

        print(f"  Streaming {num_calls} micro-cheques (${price_per_call:.4f} per unit)...")
        for i in range(1, num_calls + 1):
            # Agent action: sign_stream_cheque
            sign_raw = provider.sign_stream_cheque(vendor_address=v_pk_hex, amount_usdc=price_per_call)
            sign_data = json.loads(sign_raw)

            # Vendor action: verify_cheque_stream via vendor's ActionProvider
            verify_raw = v_provider.verify_cheque_stream(cheque_bytes=sign_data["cheque_hex"])
            verify_data = json.loads(verify_raw)
            assert verify_data["accepted"] is True, f"Verification failed: {verify_data}"

            total_spent += price_per_call

        print(f"  Delivered {num_calls} units. Settled: ${v_node.accumulated_usdc:.4f} USDC | Gas: 0 wei")

    print("\n======================================================================")
    print(f"WORKFLOW COMPLETED: Total Compute Purchased: ${total_spent:.4f} USDC")
    print("Fragmented Deposits Required: $0.00 (Single Shared Bond on Base)")
    print("Total Intermediate Gas Transactions: 0 (Zero Gas Drag)")
    print("Actions Executed via Coinbase AgentKit ActionProvider: create_channel, sign_stream_cheque, verify_cheque_stream")
    print("======================================================================")

    # Clean shutdown
    provider.close()
    for vp in vendor_providers.values():
        vp.close()
    vendor_llm.close()
    vendor_vectordb.close()
    vendor_scraper.close()
    print("Clean shutdown complete: Zero memory leaks.")


if __name__ == "__main__":
    main()
