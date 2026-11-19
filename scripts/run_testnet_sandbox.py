#!/usr/bin/env python3
"""In-memory testnet cheque meter. No inference or on-chain transfers occur."""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import os
import secrets
import signal
import sys
import threading

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from sdk.causal_slash import (
    CausalVendorNode,
    derive_public_key,
    unpack_cheque,
    CSLS_ERR_FRAUD,
    CSLS_ERR_REPLAY,
    CSLS_ERR_OUT_OF_ORDER,
    CSLS_ERR_FORGED_HASH,
    CSLS_ERR_BAD_MAC,
    CSLS_ERR_NO_SESSION,
    CSLS_ERR_EXPOSURE_CAP,
)

DEFAULT_VAULT = "0x901c98Da847DD24ff23FcC37B6D1549A17F12253"
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
MAX_BODY = 65536
METER_PATHS = frozenset((
    "/v1/sandbox/meter", "/v1/chat/completions", "/v1/service/execute",
))
ERROR_NAMES = {
    CSLS_ERR_REPLAY: "REPLAY_PACKET_IGNORED",
    CSLS_ERR_OUT_OF_ORDER: "OUT_OF_ORDER_OR_OLD_HEIGHT",
    CSLS_ERR_FORGED_HASH: "FORGED_CHALLENGE_HASH",
    CSLS_ERR_BAD_MAC: "INVALID_OR_MISSING_SESSION_MAC",
    CSLS_ERR_NO_SESSION: "NO_ACTIVE_MAC_SESSION",
    CSLS_ERR_EXPOSURE_CAP: "EXPOSURE_BUFFER_EXCEEDED",
    CSLS_ERR_FRAUD: "EQUIVOCATION_DETECTED",
}


def decode_hex(value, size):
    """Require exact hexadecimal wire size; do not silently accept whitespace."""
    if not isinstance(value, str):
        raise ValueError("Expected hexadecimal string")
    value = value.removeprefix("0x")
    if len(value) != size * 2 or any(c not in "0123456789abcdefABCDEF" for c in value):
        raise ValueError("Invalid hexadecimal packet")
    return bytes.fromhex(value)


class SandboxState:
    def __init__(self, vendor_sk=None, delta_v=1.0, unit_price_micro=500,
                 vault_address=DEFAULT_VAULT, payout_address=None):
        if not 0 < delta_v < float("inf"):
            raise ValueError("delta-v must be positive and finite")
        if not isinstance(unit_price_micro, int) or unit_price_micro <= 0:
            raise ValueError("unit-price-micro must be a positive integer")
        if vendor_sk is None:
            vendor_sk = os.environ.get("CSLS_SANDBOX_VENDOR_SK")
        if vendor_sk is None:
            secret = secrets.token_bytes(32)
        elif isinstance(vendor_sk, bytes) and len(vendor_sk) == 32:
            secret = vendor_sk
        else:
            secret = decode_hex(vendor_sk, 32)
        try:
            self.vendor_pk = derive_public_key(secret, compressed=True)
        except Exception:
            raise ValueError("Invalid vendor secret key") from None
        self.vendor_pk_hex = self.vendor_pk.hex()
        self.lock = threading.Lock()
        self.vendor = CausalVendorNode(secret_key=secret, delta_v_usdc=delta_v,
                                       enforce_mac=True)
        self.unit_price_micro = unit_price_micro
        self.vault_address = vault_address
        self.payout_address = (payout_address if payout_address is not None else
                               os.environ.get("CSLS_SANDBOX_PAYOUT_ADDRESS", ZERO_ADDRESS))
        self.cumulative_by_agent = {}
        self.metrics = dict(sessions_initialized=0, cheques_accepted=0,
                            cheques_rejected=0, equivocations_caught=0,
                            total_settled_micro_usdc=0)

    def health(self):
        with self.lock:
            metrics = dict(self.metrics)
        return {
            "status": "ok", "vendor_pk": self.vendor_pk_hex,
            "provider_pk": self.vendor_pk_hex,
            "provider_id": "csls-base-sepolia-sandbox",
            "payout_address": self.payout_address, "vault_address": self.vault_address,
            "network": "base-sepolia", "unit_price_usdc": self.unit_price_micro / 1e6,
            "unit_price_micro_usdc": self.unit_price_micro,
            "settlement_mode": "session_mac_167b",
            "capabilities": ["session_mac_167b", "sandbox_meter", "equivocation_eots"],
            "metrics": metrics,
        }

    def reject(self, error, code):
        with self.lock:
            self.metrics["cheques_rejected"] += 1
        return {"ok": False, "error": error, "code": code}

    def process(self, raw):
        with self.lock:
            fields = unpack_cheque(raw)
            if raw[:5] != b"\x53\x4c\x53\x43\x01" or fields["vendor_pk"] != self.vendor_pk:
                self.metrics["cheques_rejected"] += 1
                return 403, {"ok": False, "error": "INVALID_CHEQUE_FORMAT", "code": -1}
            res = self.vendor.process_cheque(raw)
            if not res.accepted:
                self.metrics["cheques_rejected"] += 1
                result = {"ok": False, "error": ERROR_NAMES.get(res.status_code, "CHEQUE_REJECTED"),
                          "code": res.status_code}
                if res.status_code == CSLS_ERR_FRAUD:
                    if res.fraud_proof is not None:
                        self.metrics["equivocations_caught"] += 1
                        proof = res.fraud_proof
                        result["fraud_proof"] = {
                            "extracted_secret_key": proof.extracted_secret_key.hex(),
                            "offender_pk": proof.offender_pk.hex(),
                            "height": proof.collision_height,
                        }
                    return 409, result
                return 403, result
            agent_pk = fields["agent_pk"]
            cumulative = fields["cumulative_amt"]
            delta = cumulative - self.cumulative_by_agent.get(agent_pk, 0)
            self.cumulative_by_agent[agent_pk] = cumulative
            self.metrics["cheques_accepted"] += 1
            self.metrics["total_settled_micro_usdc"] += delta
            return 200, {
                "ok": True, "status": "settled", "mode": "testnet_sandbox_meter",
                "height": fields["height"], "cumulative_micro_usdc": cumulative,
                "delta_micro_usdc": delta, "vendor_pk": self.vendor_pk_hex,
                "gas_wei": "0", "network": "base-sepolia",
                "message": "[CSLS TESTNET SANDBOX] Verified 167B Session MAC cheque (no LLM inference executed)",
            }


class SandboxHandler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, format, *args):
        # Never log request bodies, headers, paths, or cryptographic secrets.
        pass

    def respond(self, status, payload, content_type="application/json", streaming=False):
        body = (json.dumps(payload, separators=(",", ":")).encode("utf-8")
                if content_type == "application/json" else payload.encode("utf-8"))
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        if self.path in METER_PATHS:
            self.send_header("X-CSLS-Mode", "testnet-sandbox-meter")
        if streaming:
            self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.close_connection = True
        self.wfile.write(body)
        self.wfile.flush()

    def read_body(self):
        lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get("Transfer-Encoding") or len(lengths) > 1:
            self.respond(400, {"ok": False, "error": "INVALID_BODY_FRAMING"})
            return None
        if lengths:
            try:
                length = int(lengths[0])
                if length < 0:
                    raise ValueError
            except ValueError:
                self.respond(400, {"ok": False, "error": "INVALID_CONTENT_LENGTH"})
                return None
            if length > MAX_BODY:
                self.respond(413, {"ok": False, "error": "BODY_TOO_LARGE"})
                return None
        else:
            length = MAX_BODY + 1
        try:
            raw = self.rfile.read(length)
        except (OSError, ValueError):
            self.respond(400, {"ok": False, "error": "INCOMPLETE_BODY"})
            return None
        if len(raw) > MAX_BODY:
            self.respond(413, {"ok": False, "error": "BODY_TOO_LARGE"})
            return None
        if lengths and len(raw) != length:
            self.respond(400, {"ok": False, "error": "INCOMPLETE_BODY"})
            return None
        return raw

    def do_GET(self):
        if self.path == "/health":
            self.respond(200, self.server.state.health())
        else:
            self.respond(404, {"ok": False, "error": "NOT_FOUND"})

    def do_POST(self):
        raw = self.read_body()
        if raw is None:
            return
        if self.path in ("/v1/session/init", "/v1/session"):
            self.init_session(raw)
        elif self.path in METER_PATHS:
            self.meter(raw)
        else:
            self.respond(404, {"ok": False, "error": "NOT_FOUND"})

    def parse_json_body(self, body, error):
        try:
            return True, json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
            self.respond(400, {"ok": False, "error": error})
            return False, None

    def init_session(self, body):
        try:
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type == "application/octet-stream" or (
                    len(body) == 95 and content_type != "application/json"
                    and not body.lstrip().startswith((b"{", b"["))):
                packet = body
            else:
                parsed, data = self.parse_json_body(body, "INVALID_SESSION_PACKET")
                if not parsed:
                    return
                if not isinstance(data, dict):
                    raise ValueError
                packet = decode_hex(data.get("session_init_pkt", data.get("packet")), 95)
            if len(packet) != 95 or packet[:5] != b"\x53\x4c\x53\x43\x05":
                raise ValueError
        except (ValueError, TypeError, UnicodeError):
            self.respond(400, {"ok": False, "error": "INVALID_SESSION_PACKET"})
            return
        state = self.server.state
        with state.lock:
            try:
                accepted = state.vendor.init_session(packet)
            except (ValueError, TypeError, RuntimeError):
                accepted = False
            if accepted:
                state.metrics["sessions_initialized"] += 1
        if accepted:
            self.respond(200, {"ok": True, "session_initialized": True,
                               "vendor_pk": state.vendor_pk_hex})
        else:
            self.respond(403, {"ok": False, "error": "SESSION_AUTH_FAILED"})

    def meter(self, body):
        state = self.server.state
        header = self.headers.get("X-Causal-Cheque")
        if header is None:
            self.respond(403, state.reject("CHEQUE_REQUIRED", CSLS_ERR_NO_SESSION))
            return
        try:
            raw = decode_hex(header, 167)
        except ValueError:
            self.respond(403, state.reject("INVALID_CHEQUE_FORMAT", -1))
            return
        data = {}
        if body:
            parsed, data = self.parse_json_body(body, "INVALID_JSON")
            if not parsed:
                return
        status, receipt = state.process(raw)
        if (status == 200 and self.path == "/v1/chat/completions"
                and isinstance(data, dict) and data.get("stream") is True):
            message = (
                "[CSLS TESTNET SANDBOX] Verified 167B Session MAC cheque "
                f"height={receipt['height']} cumulative=${receipt['cumulative_micro_usdc'] / 1e6:.4f} USDC "
                "(gas=0, mode=testnet-sandbox-meter)"
            )
            chunk = {"id": "csls-sandbox", "object": "chat.completion.chunk",
                     "choices": [{"index": 0, "delta": {"content": message}, "finish_reason": "stop"}]}
            events = "data: " + json.dumps(chunk, separators=(",", ":")) + "\n\ndata: [DONE]\n\n"
            self.respond(200, events, "text/event-stream; charset=utf-8", streaming=True)
        else:
            self.respond(status, receipt)


class SandboxServer(ThreadingHTTPServer):
    # Join all request workers before freeing native vendor state.
    daemon_threads = False
    block_on_close = True

    def server_close(self):
        super().server_close()
        with self.state.lock:
            self.state.vendor.close()


def create_sandbox_server(host="127.0.0.1", port=8402, *, vendor_sk=None,
                          delta_v=1.0, unit_price_micro=500,
                          vault_address=DEFAULT_VAULT, payout_address=None):
    state = SandboxState(vendor_sk, delta_v, unit_price_micro, vault_address, payout_address)
    # Set state before binding: HTTPServer closes itself if bind fails.
    server = SandboxServer((host, port), SandboxHandler, bind_and_activate=False)
    server.state = state
    try:
        server.server_bind()
        server.server_activate()
    except BaseException:
        server.server_close()
        raise
    return server


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8402)
    parser.add_argument("--vendor-sk", help="32-byte vendor secret in hex (prefer environment)")
    parser.add_argument("--delta-v", type=float, default=1.0)
    parser.add_argument("--unit-price-micro", type=int, default=500)
    parser.add_argument("--vault-address", default=DEFAULT_VAULT)
    parser.add_argument("--payout-address", default=os.environ.get("CSLS_SANDBOX_PAYOUT_ADDRESS", ZERO_ADDRESS))
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        server = create_sandbox_server(
            args.host, args.port, vendor_sk=args.vendor_sk, delta_v=args.delta_v,
            unit_price_micro=args.unit_price_micro, vault_address=args.vault_address,
            payout_address=args.payout_address,
        )
    except (ValueError, TypeError, RuntimeError, OSError):
        parser.error("Invalid sandbox configuration or unavailable listening address")

    def stop(signum, frame):
        # shutdown must not run on the serve_forever thread.
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    logging.info("vendor_pk=%s", server.state.vendor_pk_hex)
    logging.info("sandbox listening on %s:%s", *server.server_address[:2])
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
