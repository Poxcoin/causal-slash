# SPDX-License-Identifier: Apache-2.0
"""
Causal-Slash Sidecar Reverse Proxy (SlashProxy)
Acts as a zero-configuration local reverse proxy for AI multi-agent swarms.
Intercepts M2M completions for frontier closed models, attaches CSLS micro-cheques
over L4 raw socket, and eliminates cyclic reciprocal debts in-memory via DebtCycleMesh
before broadcasting residual settlements to external network sockets.
"""

from __future__ import annotations
import http.server
import json
import logging
import os
import socket
import struct
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import concurrent.futures
from typing import Optional, Tuple, Union, Dict, List, Callable

try:
    from .causal_slash import (
        CausalAgentWallet,
        CausalVendorNode,
        Cheque,
        CslsCheque,
        DebtCycleMesh,
        NettingSummary,
        CSLS_MAGIC,
        CSLS_OK,
    )
    from .swarm_subagent import (
        SwarmDelegationVault,
        SubagentSession,
        SubagentQuotaExceededError,
        SpendRateLimitExceededError,
    )
    from .guardrails import EdgeSafetyGuardrail
except ImportError:
    from causal_slash import (
        CausalAgentWallet,
        CausalVendorNode,
        Cheque,
        CslsCheque,
        DebtCycleMesh,
        NettingSummary,
        CSLS_MAGIC,
        CSLS_OK,
    )
    from swarm_subagent import (
        SwarmDelegationVault,
        SubagentSession,
        SubagentQuotaExceededError,
        SpendRateLimitExceededError,
    )
    from guardrails import EdgeSafetyGuardrail


class SlashSidecarProxy:
    """
    Transparent local sidecar proxy with integrated P2P DebtCycleMesh.
    Agents send standard HTTP completions to localhost; proxy translates them
    to streaming micro-settlement CSLS packets.
    Reciprocal debts across multi-agent swarms are first eliminated in RAM via
    Kirchhoff Cycle Elimination before any external network packets hit the wire.
    """
    def __init__(
        self,
        agent_wallet: CausalAgentWallet,
        vendor_public_key: Optional[bytes] = None,
        price_per_request_usdc: float = 0.0005,  # $0.0005 per completion request
        bind_host: str = "127.0.0.1",
        bind_port: int = 8999,
        mesh: Optional[DebtCycleMesh] = None,
        upstream_socket_address: Optional[Tuple[str, int]] = None,
        auto_resolve_cycles: bool = True,
        custom_network_transport: Optional[Callable[[bytes], None]] = None,
        delegation_vault: Optional[SwarmDelegationVault] = None,
        upstream_url: Optional[str] = None,
        vendor_node: Optional[CausalVendorNode] = None,
        spend_rate_per_sec_usdc: float = 0.0001,
        guardrail: Optional[EdgeSafetyGuardrail] = None,
        enable_guardrail: bool = True,
    ):
        self.wallet = agent_wallet
        self.vendor_pk = vendor_public_key
        self.price_per_req = price_per_request_usdc
        self.host = bind_host
        self.port = bind_port
        self.upstream_addr = upstream_socket_address
        self.auto_resolve_cycles = auto_resolve_cycles
        self.custom_transport = custom_network_transport
        self.delegation_vault = delegation_vault
        self.upstream_url = upstream_url or os.environ.get("CAUSAL_UPSTREAM_URL")
        self.vendor_node = vendor_node
        self.spend_rate_per_sec_usdc = spend_rate_per_sec_usdc
        if guardrail is not None:
            self.guardrail: Optional[EdgeSafetyGuardrail] = guardrail
        elif enable_guardrail:
            self.guardrail = EdgeSafetyGuardrail()
        else:
            self.guardrail = None

        # In-memory Debt Graph & Kirchhoff cycle reduction engine
        self.mesh: DebtCycleMesh = mesh if mesh is not None else DebtCycleMesh(auto_bilateral_netting=True)

        # Thread synchronization & accounting
        self._lock = threading.RLock()
        self.total_settled_usdc = 0.0
        self.total_requests_processed = 0
        self.total_incoming_cheques = 0
        self.total_outgoing_cheques = 0
        self.external_network_packets_sent = 0

        self._server: Optional[http.server.ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._network_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=8, thread_name_prefix="csls_net_worker"
        )

    @property
    def packet_reduction_ratio(self) -> float:
        """
        Calculates the ratio of external network packets eliminated through in-memory cycle clearing.
        Reduction = 1.0 - (external_network_packets_sent / gross_obligations).
        """
        with self._lock:
            gross = self.mesh._gross_tx_count
            if gross == 0:
                return 1.0
            ratio = 1.0 - (self.external_network_packets_sent / gross)
            return max(0.0, min(1.0, ratio))

    def sign_and_ingest_outgoing(
        self,
        vendor_pk: Optional[bytes] = None,
        amount_usdc: Optional[float] = None
    ) -> Cheque:
        """
        Signs a micro-cheque for outgoing compute/service and records it in DebtCycleMesh.
        Resolves in-memory Kirchhoff cycles if auto_resolve_cycles is enabled.
        """
        target_pk = vendor_pk or self.vendor_pk
        if target_pk is None:
            raise ValueError("Target vendor public key must be specified")
        amt = amount_usdc if amount_usdc is not None else self.price_per_req

        with self._lock:
            cheque = self.wallet.sign_cheque(target_pk, amount_usdc=amt)
            self.mesh.record_cheque(cheque)
            self.total_settled_usdc += amt
            self.total_requests_processed += 1
            self.total_outgoing_cheques += 1

            if self.auto_resolve_cycles:
                self.mesh.reduce_kirchhoff_cycles()

            return cheque

    def ingest_incoming_cheque(self, cheque: CslsCheque) -> int:
        """
        Ingests an incoming micro-cheque from a peer agent into DebtCycleMesh.
        Resolves in-memory Kirchhoff cycles if auto_resolve_cycles is enabled.
        """
        with self._lock:
            res = self.mesh.record_cheque(cheque)
            self.total_incoming_cheques += 1

            if self.auto_resolve_cycles:
                self.mesh.reduce_kirchhoff_cycles()

            return res

    def ingest_obligation(
        self,
        debtor: Union[bytes, str],
        creditor: Union[bytes, str],
        amount_micro_usdc: int
    ) -> int:
        """
        Directly records an agent-to-agent obligation into the mesh.
        """
        with self._lock:
            res = self.mesh.add_obligation(debtor, creditor, amount_micro_usdc)
            if self.auto_resolve_cycles:
                self.mesh.reduce_kirchhoff_cycles()
            return res

    def resolve_cycles(self) -> Tuple[int, int]:
        """
        Executes explicit Kirchhoff cycle elimination across all recorded obligations in RAM.
        Returns (cycles_eliminated_count, total_micro_usdc_cleared).
        """
        with self._lock:
            return self.mesh.reduce_kirchhoff_cycles()

    def flush_settlements_to_network(self) -> List[Tuple[bytes, bytes, int]]:
        """
        Resolves all remaining cycles in RAM and offloads residual settlements
        to non-blocking worker pool without holding self._lock during network I/O.
        """
        with self._lock:
            self.mesh.reduce_kirchhoff_cycles()
            settlements = self.mesh.generate_clearing_settlements()
            self.external_network_packets_sent += len(settlements)

        # LOCK IS RELEASED! Now offload network transmissions to worker pool
        futures = []
        for debtor_pk, creditor_pk, amount_micro in settlements:
            f = self._network_executor.submit(
                self._dispatch_network_settlement, debtor_pk, creditor_pk, amount_micro
            )
            futures.append(f)

        if futures:
            concurrent.futures.wait(futures, timeout=5.0)

        return settlements

    def _dispatch_network_settlement(self, debtor_pk: bytes, creditor_pk: bytes, amount_micro: int):
        """
        Encodes and transmits an L4 CSLS net settlement packet to upstream socket or transport.
        Wire format: MAGIC (4B) | TYPE=0x04 (1B) | DEBTOR_PK (33B) | CREDITOR_PK (33B) | AMOUNT (8B).
        """
        debtor_33 = debtor_pk[:33].ljust(33, b"\x00")
        creditor_33 = creditor_pk[:33].ljust(33, b"\x00")
        wire_pkt = struct.pack("!IB33s33sQ", CSLS_MAGIC, 0x04, debtor_33, creditor_33, amount_micro)

        if self.custom_transport is not None:
            self.custom_transport(wire_pkt)
            return

        if self.upstream_addr is not None:
            try:
                with socket.create_connection(self.upstream_addr, timeout=2.0) as sock:
                    sock.sendall(wire_pkt)
            except (ConnectionRefusedError, socket.timeout, OSError) as e:
                logging.getLogger("SlashSidecarProxy").warning(
                    "Upstream settlement delivery failed to %s: %s", self.upstream_addr, e
                )

    def _make_handler(self):
        proxy_self = self

        class ProxyHandler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            close_connection = True

            def log_message(self, format, *args):
                return  # Suppress default console logging for maximum throughput

            def do_GET(self):
                # Health & mesh status endpoint
                if self.path in ("/status", "/v1/csls/mesh/status"):
                    summary = proxy_self.mesh.get_summary()
                    status_payload = {
                        "status": "healthy",
                        "gross_transactions": summary.gross_obligations_count,
                        "gross_volume_usdc": summary.gross_volume_micro_usdc / 1e6,
                        "net_residual_transactions": summary.net_obligations_count,
                        "net_residual_volume_usdc": summary.net_volume_micro_usdc / 1e6,
                        "cycles_eliminated": summary.cycles_eliminated_count,
                        "cleared_volume_usdc": summary.total_cleared_micro_usdc / 1e6,
                        "volume_compression": summary.volume_compression_ratio,
                        "network_packets_sent": proxy_self.external_network_packets_sent,
                        "packet_reduction_ratio": proxy_self.packet_reduction_ratio,
                    }
                    resp_bytes = json.dumps(status_payload).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(resp_bytes)))
                    self.end_headers()
                    try:
                        self.wfile.write(resp_bytes)
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self):
                try:
                    content_len = int(self.headers.get("Content-Length", 0))
                except (ValueError, TypeError):
                    content_len = 0

                req_body = self.rfile.read(content_len) if content_len > 0 else b""

                # Route A: Flush endpoint
                if self.path in ("/v1/csls/flush", "/flush"):
                    settlements = proxy_self.flush_settlements_to_network()
                    resp_data = {
                        "settlements_flushed": len(settlements),
                        "external_packets_sent": proxy_self.external_network_packets_sent,
                        "packet_reduction_ratio": proxy_self.packet_reduction_ratio,
                    }
                    resp_bytes = json.dumps(resp_data).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(resp_bytes)))
                    self.end_headers()
                    try:
                        self.wfile.write(resp_bytes)
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                    return

                # Route B: Direct Ingestion Endpoint
                if self.path in ("/v1/csls/ingest", "/v1/csls/cheque"):
                    try:
                        data = json.loads(req_body.decode("utf-8")) if req_body else {}
                        debtor = data.get("debtor")
                        creditor = data.get("creditor")
                        amount_micro = int(data.get("amount_micro", 0))
                        if debtor and creditor and amount_micro > 0:
                            proxy_self.ingest_obligation(debtor, creditor, amount_micro)
                            resp_data = {"status": "accepted", "gross_tx": proxy_self.mesh._gross_tx_count}
                        else:
                            resp_data = {"error": "Invalid obligation payload"}
                    except Exception as e:
                        resp_data = {"error": str(e)}

                    resp_bytes = json.dumps(resp_data).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(resp_bytes)))
                    self.end_headers()
                    try:
                        self.wfile.write(resp_bytes)
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                    return

                # Route C: M2M Vendor Completions (Frontier Closed Model Gateways)
                # Check for incoming client payment cheque (e.g. from autonomous agent)
                incoming_cheque_hdr = self.headers.get("X-Causal-Cheque")
                if incoming_cheque_hdr:
                    # 1. Verify cheque if vendor_node is active on proxy
                    if proxy_self.vendor_node is not None:
                        try:
                            raw_cheque = bytes.fromhex(incoming_cheque_hdr.replace("0x", ""))
                            proc_res = proxy_self.vendor_node.process_cheque(raw_cheque)
                            if not proc_res.accepted:
                                err_payload = json.dumps({
                                    "error": f"Payment cheque rejected: {proc_res.error_message}",
                                    "status_code": proc_res.status_code
                                }).encode("utf-8")
                                self.send_response(402)
                                self.send_header("Content-Type", "application/json")
                                self.send_header("Content-Length", str(len(err_payload)))
                                self.end_headers()
                                try:
                                    self.wfile.write(err_payload)
                                except (BrokenPipeError, ConnectionResetError):
                                    pass
                                return
                        except Exception as e:
                            err_payload = json.dumps({"error": f"Malformed X-Causal-Cheque: {e}"}).encode("utf-8")
                            self.send_response(400)
                            self.send_header("Content-Type", "application/json")
                            self.send_header("Content-Length", str(len(err_payload)))
                            self.end_headers()
                            try:
                                self.wfile.write(err_payload)
                            except (BrokenPipeError, ConnectionResetError):
                                pass
                            return

                    # 2. Edge Safety Guardrail inspection before upstream forwarding
                    if proxy_self.guardrail is not None and req_body:
                        is_safe, reason = proxy_self.guardrail.inspect_request(req_body)
                        if not is_safe:
                            err_payload = json.dumps({
                                "error": "PROMPT_SAFETY_VIOLATION",
                                "reason": reason or "Malicious prompt pattern detected"
                            }).encode("utf-8")
                            self.send_response(400)
                            self.send_header("Content-Type", "application/json")
                            self.send_header("Content-Length", str(len(err_payload)))
                            self.end_headers()
                            try:
                                self.wfile.write(err_payload)
                            except (BrokenPipeError, ConnectionResetError):
                                pass
                            return

                    # 3. Honest streaming forward to upstream Frontier Gateway
                    target_upstream = (
                        proxy_self.upstream_url
                        or self.headers.get("X-Causal-Upstream-Url")
                        or os.environ.get("CAUSAL_UPSTREAM_URL")
                    )

                    if target_upstream:
                        target_endpoint = target_upstream.rstrip("/") + self.path
                        fwd_headers = {}
                        for h, v in self.headers.items():
                            if h.lower() not in ("host", "content-length", "x-causal-cheque"):
                                fwd_headers[h] = v
                        fwd_headers["Host"] = urllib.parse.urlparse(target_upstream).netloc or "localhost"
                        fwd_headers["Connection"] = "close"

                        u_req = urllib.request.Request(
                            target_endpoint,
                            data=req_body if req_body else None,
                            headers=fwd_headers,
                            method=self.command,
                        )
                        try:
                            with urllib.request.urlopen(u_req, timeout=30.0) as u_resp:
                                self.send_response(u_resp.status)
                                for h, v in u_resp.getheaders():
                                    if h.lower() not in ("content-length", "transfer-encoding", "connection"):
                                        self.send_header(h, v)
                                self.send_header("Connection", "close")
                                self.send_header("X-Causal-Proxy-Mode", "streaming-forward")
                                self.end_headers()
                                # Body length is indeterminate (no Content-Length/chunked);
                                # the socket must close or clients block forever on read().
                                self.close_connection = True

                                t_start = time.time()
                                last_meter_sec = int(t_start)
                                while True:
                                    chunk = u_resp.read(512)
                                    if not chunk:
                                        break
                                    try:
                                        self.wfile.write(chunk)
                                        self.wfile.flush()
                                    except (BrokenPipeError, ConnectionResetError):
                                        break

                                    curr_sec = int(time.time())
                                    if curr_sec > last_meter_sec:
                                        delta_sec = curr_sec - last_meter_sec
                                        last_meter_sec = curr_sec
                                        with proxy_self._lock:
                                            proxy_self.total_settled_usdc += delta_sec * proxy_self.spend_rate_per_sec_usdc
                            return
                        except urllib.error.HTTPError as e:
                            err_data = e.read()
                            self.send_response(e.code)
                            self.send_header("Content-Type", "application/json")
                            self.send_header("Content-Length", str(len(err_data)))
                            self.end_headers()
                            try:
                                self.wfile.write(err_data)
                            except (BrokenPipeError, ConnectionResetError):
                                pass
                            return
                        except Exception as e:
                            err_data = json.dumps({"error": f"Upstream forward failed: {e}"}).encode("utf-8")
                            self.send_response(502)
                            self.send_header("Content-Type", "application/json")
                            self.send_header("Content-Length", str(len(err_data)))
                            self.end_headers()
                            try:
                                self.wfile.write(err_data)
                            except (BrokenPipeError, ConnectionResetError):
                                pass
                            return
                    else:
                        # Fallback simulated streaming forward with per-second micro-USDC metering
                        # Used for local loopback testing, quickstarts, and offline agent development
                        self.send_response(200)
                        self.send_header("Content-Type", "text/event-stream")
                        self.send_header("Cache-Control", "no-cache")
                        self.send_header("Connection", "close")
                        self.send_header("X-Causal-Proxy-Mode", "simulated-streaming-forward")
                        self.send_header("X-Causal-Model", "causal-slash-routed-llm")
                        self.end_headers()
                        # SSE ends with data: [DONE] and has no length framing;
                        # keep-alive here makes every stdlib client hang on read().
                        self.close_connection = True

                        stream_chunks = [
                            "Streaming", " compute", " verified", " via", " CSLS", " micro-cheque."
                        ]
                        t_start = time.time()
                        last_meter_sec = int(t_start)

                        for i, token in enumerate(stream_chunks):
                            payload = {
                                "id": f"chatcmpl-stream-{i}",
                                "object": "chat.completion.chunk",
                                "created": int(time.time()),
                                "model": "causal-slash-routed-llm",
                                "choices": [{
                                    "index": 0,
                                    "delta": {"content": token},
                                    "finish_reason": None if i < len(stream_chunks) - 1 else "stop"
                                }]
                            }
                            line = f"data: {json.dumps(payload)}\n\n".encode("utf-8")
                            try:
                                self.wfile.write(line)
                                self.wfile.flush()
                            except (BrokenPipeError, ConnectionResetError):
                                break
                            time.sleep(0.01)
                            curr_sec = int(time.time())
                            if curr_sec > last_meter_sec:
                                delta_sec = curr_sec - last_meter_sec
                                last_meter_sec = curr_sec
                                with proxy_self._lock:
                                    proxy_self.total_settled_usdc += delta_sec * proxy_self.spend_rate_per_sec_usdc

                        try:
                            self.wfile.write(b"data: [DONE]\n\n")
                            self.wfile.flush()
                        except (BrokenPipeError, ConnectionResetError):
                            pass
                        return

                # Edge Safety Guardrail check for outgoing requests
                if proxy_self.guardrail is not None and req_body:
                    is_safe, reason = proxy_self.guardrail.inspect_request(req_body)
                    if not is_safe:
                        err_payload = json.dumps({
                            "error": "PROMPT_SAFETY_VIOLATION",
                            "reason": reason or "Malicious prompt pattern detected"
                        }).encode("utf-8")
                        self.send_response(400)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(err_payload)))
                        self.end_headers()
                        try:
                            self.wfile.write(err_payload)
                        except (BrokenPipeError, ConnectionResetError):
                            pass
                        return

                # Check if incoming request carries a peer vendor PK override
                vendor_pk = proxy_self.vendor_pk
                vendor_hdr = self.headers.get("X-Causal-Slash-Vendor-Pk")
                if vendor_hdr:
                    try:
                        vendor_pk = bytes.fromhex(vendor_hdr.replace("0x", ""))
                    except ValueError:
                        pass

                # Check for subagent delegation header
                subagent_id = self.headers.get("X-Causal-Subagent-Id")
                subagent_session = None

                if subagent_id and proxy_self.delegation_vault is not None:
                    subagent_session = proxy_self.delegation_vault.get_session(subagent_id)
                    if subagent_session is None:
                        error_resp = json.dumps({
                            "error": f"Subagent '{subagent_id}' not found in delegation vault"
                        }).encode("utf-8")
                        self.send_response(404)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(error_resp)))
                        self.end_headers()
                        try:
                            self.wfile.write(error_resp)
                        except (BrokenPipeError, ConnectionResetError):
                            pass
                        return

                    # Validate subagent quota and Circuit Breaker spend rate
                    amount_micro = int(round(proxy_self.price_per_req * 1e6))
                    try:
                        subagent_session.check_and_reserve(amount_micro)
                        subagent_session.check_spend_rate(amount_micro)
                    except (SubagentQuotaExceededError, SpendRateLimitExceededError) as e:
                        error_resp = json.dumps({"error": str(e)}).encode("utf-8")
                        self.send_response(429)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(error_resp)))
                        self.end_headers()
                        try:
                            self.wfile.write(error_resp)
                        except (BrokenPipeError, ConnectionResetError):
                            pass
                        return

                # Sign CSLS streaming micro-cheque and ingest into in-memory mesh
                cheque = proxy_self.sign_and_ingest_outgoing(
                    vendor_pk=vendor_pk,
                    amount_usdc=proxy_self.price_per_req
                )

                # If subagent session is active, commit the spend to the session
                if subagent_session is not None:
                    amount_micro = int(round(proxy_self.price_per_req * 1e6))
                    subagent_session.commit_spend(amount_micro)

                # If an upstream URL is configured, forward the request with the attached cheque
                if proxy_self.upstream_url:
                    target_endpoint = proxy_self.upstream_url.rstrip("/") + self.path
                    fwd_headers = {}
                    for h, v in self.headers.items():
                        if h.lower() not in ("host", "content-length", "x-causal-cheque"):
                            fwd_headers[h] = v
                    fwd_headers["Host"] = urllib.parse.urlparse(proxy_self.upstream_url).netloc or "localhost"
                    fwd_headers["Connection"] = "close"
                    fwd_headers["X-Causal-Cheque"] = cheque.raw_packet.hex()

                    u_req = urllib.request.Request(
                        target_endpoint,
                        data=req_body if req_body else None,
                        headers=fwd_headers,
                        method=self.command,
                    )
                    try:
                        with urllib.request.urlopen(u_req, timeout=30.0) as u_resp:
                            self.send_response(u_resp.status)
                            for h, v in u_resp.getheaders():
                                if h.lower() not in ("content-length", "transfer-encoding", "connection"):
                                    self.send_header(h, v)
                            self.send_header("Connection", "close")
                            self.send_header("X-Causal-Proxy-Mode", "client-streaming-forward")
                            self.send_header("X-Causal-Slash-Cheque-Height", str(cheque.height))
                            self.send_header("X-Causal-Slash-Settled-USDC", f"{cheque.cumulative_amount_usdc:.6f}")
                            self.send_header("X-Causal-Slash-Packet-Reduction", f"{proxy_self.packet_reduction_ratio * 100:.2f}%")
                            if subagent_session:
                                self.send_header("X-Causal-Subagent-Id", subagent_id)
                            self.end_headers()
                            self.close_connection = True
                            while True:
                                chunk = u_resp.read(512)
                                if not chunk:
                                    break
                                try:
                                    self.wfile.write(chunk)
                                    self.wfile.flush()
                                except (BrokenPipeError, ConnectionResetError):
                                    break
                            return
                    except Exception as e:
                        err_data = json.dumps({"error": f"Upstream forward failed: {e}"}).encode("utf-8")
                        self.send_response(502)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(err_data)))
                        self.end_headers()
                        try:
                            self.wfile.write(err_data)
                        except (BrokenPipeError, ConnectionResetError):
                            pass
                        return

                summary = proxy_self.mesh.get_summary()

                # Response payload conforming to standard LLM completion structure
                response_payload = {
                    "id": f"chatcmpl-csls-{cheque.height}",
                    "object": "chat.completion",
                    "created": int(time.time()),
                    "model": "causal-slash-routed-llm",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "Execution verified: settled via in-memory CSLS debt cycle mesh."
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
                        "gas_paid": 0,
                        "cycles_eliminated": summary.cycles_eliminated_count,
                        "cleared_in_memory_usdc": summary.total_cleared_micro_usdc / 1e6,
                        "network_packet_reduction": f"{proxy_self.packet_reduction_ratio * 100:.2f}%",
                        "subagent_id": subagent_id if subagent_session else None,
                    }
                }

                resp_bytes = json.dumps(response_payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("X-Causal-Slash-Cheque-Height", str(cheque.height))
                self.send_header("X-Causal-Slash-Settled-USDC", f"{cheque.cumulative_amount_usdc:.6f}")
                self.send_header("X-Causal-Slash-Packet-Reduction", f"{proxy_self.packet_reduction_ratio * 100:.2f}%")
                if subagent_session:
                    self.send_header("X-Causal-Subagent-Id", subagent_id)
                self.send_header("Content-Length", str(len(resp_bytes)))
                self.end_headers()
                try:
                    self.wfile.write(resp_bytes)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        return ProxyHandler

    def start(self):
        """Starts the multi-threaded HTTP sidecar reverse proxy in a background thread."""
        with self._lock:
            if self._server is not None:
                return
            self._server = http.server.ThreadingHTTPServer((self.host, self.port), self._make_handler())
            self._server.daemon_threads = True
            self._server.block_on_close = False
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()

    def __enter__(self) -> SlashSidecarProxy:
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()

    def stop(self):
        """Cleanly stops the reverse proxy server and terminates the listener thread."""
        with self._lock:
            if self._server:
                self._server.shutdown()
                self._server.server_close()
                self._server = None
            if self._thread:
                self._thread.join(timeout=2.0)
                self._thread = None
        self._network_executor.shutdown(wait=False, cancel_futures=True)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Causal-Slash Sidecar Reverse Proxy")
    parser.add_argument("--port", type=int, default=8999, help="Port to bind the proxy to")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host address to bind to")
    parser.add_argument("--price", type=float, default=0.0005, help="USDC cost per request")
    args = parser.parse_args()

    demo_sk = b"\x77" * 32
    demo_vendor_pk = b"\x02" + b"\x33" * 32
    wallet = CausalAgentWallet(secret_key=demo_sk)
    proxy = SlashSidecarProxy(
        agent_wallet=wallet,
        vendor_public_key=demo_vendor_pk,
        price_per_request_usdc=args.price,
        bind_host=args.host,
        bind_port=args.port,
    )
    proxy.start()
    logger.info("SlashSidecarProxy running on http://%s:%d", args.host, args.port)
    logger.info("Metering requests at $%.6f USDC per completion.", args.price)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping proxy...")
        proxy.stop()


if __name__ == "__main__":
    main()
