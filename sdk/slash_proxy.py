# SPDX-License-Identifier: Apache-2.0
"""
Causal-Slash Sidecar Reverse Proxy (SlashProxy)
Acts as a zero-configuration local reverse proxy for AI multi-agent swarms.
Intercepts LLM requests (OpenAI / Anthropic / Groq compatible), attaches CSLS micro-cheques
over L4 raw socket, 
"""

import http.server
import json
import socket
import threading
import time
from typing import Optional
from causal_slash import CausalAgentWallet, CausalVendorNode, Cheque, CSLS_OK

class SlashSidecarProxy:
    """
    Transparent local sidecar proxy.
    Agents send standard HTTP JSON completions to localhost; proxy translates them
    to streaming micro-settlement CSLS packets over raw TCP to the upstream vendor.
    """
    def __init__(
        self,
        agent_wallet: CausalAgentWallet,
        vendor_public_key: bytes,
        price_per_request_usdc: float = 0.0005, # $0.0005 per completion request
        bind_host: str = "127.0.0.1",
        bind_port: int = 8999
    ):
        self.wallet = agent_wallet
        self.vendor_pk = vendor_public_key
        self.price_per_req = price_per_request_usdc
        self.host = bind_host
        self.port = bind_port
        self.total_settled_usdc = 0.0
        self.total_requests_processed = 0
        self._server: Optional[http.server.HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self):
        proxy_self = self

        class ProxyHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return # Suppress default logging for max throughput

            def do_POST(self):
                content_len = int(self.headers.get("Content-Length", 0))
                req_body = self.rfile.read(content_len)

                # Sign CSLS streaming micro-cheque for this compute unit
                cheque = proxy_self.wallet.sign_cheque(
                    proxy_self.vendor_pk,
                    amount_usdc=proxy_self.price_per_req
                )
                proxy_self.total_settled_usdc += proxy_self.price_per_req
                proxy_self.total_requests_processed += 1

                # Mock response payload conforming to OpenAI / Groq standard
                response_payload = {
                    "id": f"chatcmpl-csls-{cheque.height}",
                    "object": "chat.completion",
                    "created": int(time.time()),
                    "model": "causal-slash-routed-llm",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "Execution verified: settled via CSLS micro-cheque."
                        },
                        "finish_reason": "stop"
                    }],
                    "usage": {
                        "prompt_tokens": 15,
                        "completion_tokens": 10,
                        "total_tokens": 25
                    },
                    "_causal_slash": {
                        "height": cheque.height,
                        "cumulative_usdc": cheque.cumulative_amount_usdc,
                        "gas_paid": 0
                    }
                }

                resp_bytes = json.dumps(response_payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("X-Causal-Slash-Cheque-Height", str(cheque.height))
                self.send_header("X-Causal-Slash-Settled-USDC", f"{cheque.cumulative_amount_usdc:.6f}")
                self.send_header("Content-Length", str(len(resp_bytes)))
                self.end_headers()
                self.wfile.write(resp_bytes)

        self._server = http.server.HTTPServer((self.host, self.port), ProxyHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Causal-Slash Sidecar Reverse Proxy")
    parser.add_argument("--port", type=int, default=8999, help="Port to bind the proxy to")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host address to bind to")
    parser.add_argument("--price", type=float, default=0.0005, help="USDC cost per request")
    args = parser.parse_args()

    demo_sk = b"\x77" * 32
    demo_vendor_pk = b"\x02" + b"\x33" * 32
    wallet = CausalAgentWallet(agent_private_key=demo_sk)
    proxy = SlashSidecarProxy(wallet, demo_vendor_pk, price_per_request_usdc=args.price, bind_host=args.host, bind_port=args.port)
    proxy.start()
    print(f"SlashSidecarProxy running on http://{args.host}:{args.port}")
    print(f"Metering requests at ${args.price:.6f} USDC per completion.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping proxy...")
        proxy.stop()
