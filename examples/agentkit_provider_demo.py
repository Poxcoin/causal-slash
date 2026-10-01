# SPDX-License-Identifier: Apache-2.0
"""
Causal-Slash Protocol: AgentKit & ElizaOS Streaming Provider Demo
Demonstrates autonomous agent compute purchasing with zero gas and instant settlement.
"""

import os
import sys
import time

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(_ROOT, "sdk"))
from causal_slash import CausalAgentWallet, CausalVendorNode, CSLS_OK

def main():
    print("======================================================================")
    print("CAUSAL-SLASH: AUTONOMOUS AGENT PROVIDER INTEGRATION")
    print("======================================================================")
    print("Simulating Coinbase AgentKit / ElizaOS agent executing multi-step workflow...")

    # 1. Initialize agent wallet backed by Base L2 collateral bond
    agent_sk = b"\x42" * 32
    agent = CausalAgentWallet(secret_key=agent_sk)
    print(f"[AGENTKIT] Agent Wallet Initialized: {agent.public_key_hex[:26]}...")
    print("[AGENTKIT] Collateral Bond: $10.00 USDC anchored in PerformanceCollateralVault.sol")

    # 2. Connect to 3 heterogeneous API providers simultaneously (Single Shared Bond)
    vendor_llm = CausalVendorNode(delta_v_usdc=1.00)
    vendor_vectordb = CausalVendorNode(delta_v_usdc=0.50)
    vendor_scraper = CausalVendorNode(delta_v_usdc=0.25)

    print("\n[STEP 1] Streaming LLM tokens ($0.0001 per token)...")
    for token_idx in range(1, 21):
        cheque = agent.sign_cheque(vendor_llm.public_key, amount_usdc=0.0001)
        res = vendor_llm.process_cheque(cheque)
        assert res.accepted, f"Rejected: {res.error_message}"
    print(f"  Delivered 20 tokens. Total Settled: ${vendor_llm.accumulated_usdc:.4f} USDC | Gas Paid: $0.00")

    print("\n[STEP 2] Streaming Vector Search queries ($0.0020 per embedding query)...")
    for query_idx in range(1, 6):
        cheque = agent.sign_cheque(vendor_vectordb.public_key, amount_usdc=0.0020)
        res = vendor_vectordb.process_cheque(cheque)
        assert res.accepted, f"Rejected: {res.error_message}"
    print(f"  Executed 5 vector searches. Total Settled: ${vendor_vectordb.accumulated_usdc:.4f} USDC | Gas Paid: $0.00")

    print("\n[STEP 3] Streaming Web Scraping pages ($0.0050 per page)...")
    for page_idx in range(1, 4):
        cheque = agent.sign_cheque(vendor_scraper.public_key, amount_usdc=0.0050)
        res = vendor_scraper.process_cheque(cheque)
        assert res.accepted, f"Rejected: {res.error_message}"
    print(f"  Scraped 3 pages. Total Settled: ${vendor_scraper.accumulated_usdc:.4f} USDC | Gas Paid: $0.00")

    total_spent = (
        vendor_llm.accumulated_usdc +
        vendor_vectordb.accumulated_usdc +
        vendor_scraper.accumulated_usdc
    )
    print("\n======================================================================")
    print(f"WORKFLOW COMPLETED: Total Compute Purchased: ${total_spent:.4f} USDC")
    print("Fragmented Deposits Required: $0.00 (Single Shared Bond on Base)")
    print("Total Intermediate Gas Transactions: 0 (Zero Gas Drag)")
    print("======================================================================")

if __name__ == "__main__":
    main()
