# SPDX-License-Identifier: Apache-2.0
"""
Causal-Slash quickstart: sovereign wallet -> SlashSidecarProxy -> cheque-metered completion.

Prerequisite: pip install causal-slash-sdk   (linux x86_64 for native cheque signing)
Run:          python3 quickstart_sidecar.py
"""
import json
import urllib.request

from sdk.causal_slash import CausalAgentWallet, CausalVendorNode
from sdk.slash_proxy import SlashSidecarProxy

# 1. Sovereign wallet from a raw secp256k1 key (32 bytes). No account, no signup.
AGENT_SK = bytes.fromhex("11" * 32)  # demo key; use CausalAgentWallet() to generate a fresh one
agent = CausalAgentWallet(secret_key=AGENT_SK)
vendor = CausalVendorNode(delta_v_usdc=10.0)

# 2. Open an authenticated session channel (Session MAC, C2 gate).
assert vendor.init_session(agent.create_session(vendor.public_key))

# 3. Start the sidecar proxy bound to loopback.
proxy = SlashSidecarProxy(
    agent_wallet=agent,
    vendor_public_key=vendor.public_key,
    vendor_node=vendor,
    bind_host="127.0.0.1",
    bind_port=18977,
)
proxy.start()

# 4. Sign one 167-byte Session MAC cheque and pay per completion request.
cheque = agent.sign_cheque(vendor.public_key, amount_usdc=0.01, session_mac=True)
body = json.dumps({
    "model": "claude-opus-5.5",
    "messages": [{"role": "user", "content": "Say ready."}],
}).encode("utf-8")
req = urllib.request.Request(
    "http://127.0.0.1:18977/v1/chat/completions",
    data=body,
    headers={
        "Content-Type": "application/json",
        "X-Causal-Cheque": cheque.raw_packet.hex(),
        "Connection": "close",
    },
)
with urllib.request.urlopen(req, timeout=5.0) as resp:
    print("HTTP", resp.status,
          "| proxy-mode:", resp.headers.get("X-Causal-Proxy-Mode"),
          "| model:", resp.headers.get("X-Causal-Model"))
    print(resp.read().decode())

# 5. Show the settlement trail.
print(f"wallet_pk={agent.public_key_hex[:24]}...")
print(f"cheque_height={cheque.height} "
      f"vendor_accumulated=${vendor.accumulated_usdc:.4f} USDC gas=0")
proxy.stop()
print("QUICKSTART_E2E_OK")
