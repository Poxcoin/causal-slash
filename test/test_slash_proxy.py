# SPDX-License-Identifier: Apache-2.0
import urllib.request
import json
import os
import sys

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_TEST_DIR)
sys.path.insert(0, os.path.join(_PROJECT_ROOT, "sdk"))

from causal_slash import CausalAgentWallet, CausalVendorNode
from slash_proxy import SlashSidecarProxy

def test_proxy_streaming():
    print("======================================================================")
    print("[SLASH PROXY TEST] Verifying Sidecar Reverse Proxy & Cheque Streaming")
    print("======================================================================")

    agent_sk = bytes([0x77] * 32)
    vendor_sk = bytes([0x88] * 32)

    agent = CausalAgentWallet(agent_sk)
    vendor = CausalVendorNode(vendor_sk, delta_v_usdc=50.0)

    proxy = SlashSidecarProxy(
        agent_wallet=agent,
        vendor_public_key=vendor.public_key,
        price_per_request_usdc=0.001, # $0.001 per call
        bind_host="127.0.0.1",
        bind_port=18999
    )
    proxy.start()

    try:
        url = "http://127.0.0.1:18999/v1/chat/completions"
        payload = json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": "ping"}]}).encode()

        for i in range(1, 11):
            req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req) as resp:
                assert resp.status == 200
                data = json.loads(resp.read().decode())
                height = int(resp.headers.get("X-Causal-Slash-Cheque-Height"))
                settled = float(resp.headers.get("X-Causal-Slash-Settled-USDC"))
                assert height == i
                assert round(settled, 4) == round(i * 0.001, 4)
                assert data["_causal_slash"]["gas_paid"] == 0

        print("  [PASS] 10/10 HTTP completions intercepted and settled via CSLS cheques.")
        print(f"  [PASS] Final settled amount: ${proxy.total_settled_usdc:.4f} USDC.")
        print("======================================================================")
        print("[VERDICT] SlashSidecarProxy functions with 100% precision.")
        print("======================================================================")

    finally:
        proxy.stop()
        agent.close()

if __name__ == "__main__":
    test_proxy_streaming()
