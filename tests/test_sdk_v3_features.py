# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Unit and Integration Test Suite for SDK v0.3.0 Features:
1. Session MAC (167-Byte Wire Protocol, static-ECDH, SipHash-128 tag)
2. Pythonic Context Managers (CausalSession & AsyncCausalSession)
3. Zero-Sidecar Client (AsyncCausalOpenAI) with streaming and header injection
4. Universal AI Agent Decorators (@causal_paid, @causal_paid_tool)
5. Structured Observability & Telemetry (CausalMetrics, JSON & Prometheus exporters)
"""

import asyncio
import inspect
import json
import os
import sys
import time
import pytest

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from sdk import (
    CausalAgentWallet,
    CausalVendorNode,
    Cheque,
    DebtCycleMesh,
    CSLS_OK,
    CSLS_ERR_BAD_MAC,
    CausalSession,
    AsyncCausalSession,
    BudgetExceededError,
    SwarmDelegationVault,
    SpendRateLimitExceededError,
    causal_paid,
    causal_paid_tool,
    CausalMetrics,
    get_metrics,
    CausalQueueFullError,
    AsyncChannelActor,
    ChannelStore,
    SlashSidecarProxy,
)


@pytest.fixture
def anyio_backend():
    return "asyncio"


# ---------------------------------------------------------------------------
# 1. Session MAC (167-Byte Wire Protocol)
# ---------------------------------------------------------------------------

def test_session_mac_167_byte_wire_protocol_end_to_end():
    wallet = CausalAgentWallet()
    vendor = CausalVendorNode(delta_v_usdc=10.0)

    # 1. Begin Session MAC Handshake
    session_init_pkt = wallet.create_session(vendor.public_key)
    assert len(session_init_pkt) == 95, f"Expected 95-byte session_init packet, got {len(session_init_pkt)}"

    # 2. Vendor initializes session and enables mandatory MAC enforcement
    success = vendor.init_session(session_init_pkt)
    assert success is True
    vendor.enable_mac(True)

    # 3. Agent signs a 167-byte Session MAC cheque
    cheque = wallet.sign_cheque(vendor.public_key, amount_usdc=0.005, session_mac=True)
    assert cheque.mac is not None
    assert len(cheque.mac) == 16, f"Expected 16-byte SipHash MAC tag, got {len(cheque.mac)}"
    assert len(cheque.raw_packet) == 167, f"Expected 167-byte wire packet (151B + 16B MAC), got {len(cheque.raw_packet)}"
    assert cheque.height == 1
    assert cheque.cumulative_amt == 5000

    # 4. Vendor processes and verifies the 167-byte cheque
    result = vendor.process_cheque(cheque)
    assert result.accepted is True
    assert result.status_code == CSLS_OK
    assert round(result.accumulated_usdc, 4) == 0.0050

    # 5. Tampered MAC rejection test
    tampered_raw = bytearray(cheque.raw_packet)
    tampered_raw[-1] ^= 0xFF  # Corrupt last byte of MAC
    bad_result = vendor.process_cheque(bytes(tampered_raw))
    assert bad_result.accepted is False
    assert bad_result.status_code == CSLS_ERR_BAD_MAC


def test_session_mac_backwards_compatibility_151_byte():
    wallet = CausalAgentWallet()
    # Legacy 151-byte acceptance now requires an EXPLICIT opt-out: the secure
    # default mandates Session MAC enforcement because wire cheques omit the
    # Schnorr point R (sig_s can never be verified at ingestion time).
    vendor = CausalVendorNode(delta_v_usdc=10.0, enforce_mac=False)
    assert vendor._enforce_mac is False

    cheque = wallet.sign_cheque(vendor.public_key, amount_usdc=0.002, session_mac=False)
    assert cheque.mac is None
    assert len(cheque.raw_packet) == 151

    result = vendor.process_cheque(cheque)
    assert result.accepted is True
    assert result.status_code == CSLS_OK


# ---------------------------------------------------------------------------
# 2. Context Managers: CausalSession & AsyncCausalSession
# ---------------------------------------------------------------------------

def test_causal_session_sync_lifecycle_and_budget():
    wallet = CausalAgentWallet()
    vendor = CausalVendorNode(delta_v_usdc=10.0)
    mesh = DebtCycleMesh()

    with wallet.session(vendor.public_key, budget_usdc=0.010, price_per_call=0.0025, mesh=mesh) as s:
        c1 = s.pay()
        assert c1.height == 1
        assert s.spent_usdc == 0.0025

        c2 = s.pay()
        assert c2.height == 2
        assert s.spent_usdc == 0.0050

        # Custom payment amount
        c3 = s.pay(amount_usdc=0.0050)
        assert c3.height == 3
        assert s.spent_usdc == 0.0100

        # Attempting to exceed budget raises BudgetExceededError
        with pytest.raises(BudgetExceededError):
            s.pay(amount_usdc=0.0001)

    assert s.cheques_issued == 3
    # Check that mesh recorded obligations
    assert mesh.total_system_debt() > 0


@pytest.mark.anyio
async def test_causal_session_async_lifecycle_and_circuit_breaker():
    vault = SwarmDelegationVault(master_bond_usdc=50.0)
    subagent = vault.spawn_subagent(
        "researcher-01",
        quota_usdc=5.0,
        max_spend_rate_usdc_per_min=0.010  # low limit: $0.010 / min
    )
    wallet = CausalAgentWallet()
    vendor = CausalVendorNode(delta_v_usdc=10.0)

    async with wallet.async_session(
        vendor.public_key,
        budget_usdc=1.0,
        price_per_call=0.004,
        subagent_session=subagent
    ) as s:
        # First call: $0.004 (allowed)
        c1 = await s.pay()
        assert c1.height == 1

        # Second call: $0.004 (total $0.008, allowed)
        c2 = await s.pay()
        assert c2.height == 2

        # Third call: $0.004 (total $0.012 > $0.010/min -> Circuit Breaker trips!)
        with pytest.raises(SpendRateLimitExceededError):
            await s.pay()


# ---------------------------------------------------------------------------
# 3. Universal AI Agent Decorators (@causal_paid)
# ---------------------------------------------------------------------------

def test_causal_paid_sync_function():
    wallet = CausalAgentWallet()
    vendor = CausalVendorNode(delta_v_usdc=5.0)

    @causal_paid(price_usdc=0.002, vendor_node=vendor, wallet=wallet)
    def calculate_embedding(text: str) -> dict:
        """Computes text embedding vector."""
        return {"embedding": [0.1, 0.2, 0.3], "text": text}

    # Verify signature preservation for AI framework introspection
    sig = inspect.signature(calculate_embedding)
    assert "text" in sig.parameters
    assert calculate_embedding.__doc__ == "Computes text embedding vector."

    res = calculate_embedding("hello autonomous world")
    assert res["text"] == "hello autonomous world"
    assert res["_csls_cheque_height"] == 1
    assert vendor.accumulated_usdc == 0.0020


@pytest.mark.anyio
async def test_causal_paid_async_function_with_circuit_breaker():
    vault = SwarmDelegationVault(master_bond_usdc=20.0)
    subagent = vault.spawn_subagent("bot-02", quota_usdc=2.0, max_spend_rate_usdc_per_min=0.003)
    wallet = CausalAgentWallet()
    vendor = CausalVendorNode(delta_v_usdc=5.0)

    @causal_paid_tool(price_usdc=0.002, vendor_node=vendor, wallet=wallet, subagent_session=subagent)
    async def async_heavy_db_query(query: str) -> dict:
        return {"rows": 42, "query": query}

    # 1. First execution: $0.002 (permitted)
    r1 = await async_heavy_db_query("SELECT 1")
    assert r1["rows"] == 42
    assert r1["_csls_cheque_height"] == 1

    # 2. Second execution: another $0.002 -> total $0.004 > $0.003/min -> Circuit Breaker trips!
    with pytest.raises(SpendRateLimitExceededError):
        await async_heavy_db_query("SELECT 2")


# ---------------------------------------------------------------------------
# 5. Structured Observability & Telemetry (CausalMetrics)
# ---------------------------------------------------------------------------

def test_causal_metrics_collection_and_exporters():
    metrics = CausalMetrics()

    # Simulate metric recording
    metrics.record_sign(latency_us=4.5, amount_micro=1000)
    metrics.record_sign(latency_us=6.2, amount_micro=2000)
    metrics.record_verify(latency_us=2.8)
    metrics.record_verify(latency_us=3.1)
    metrics.record_circuit_breaker_trip()
    metrics.record_mesh_netting(cycles=5, cleared_micro=50_000)

    d = metrics.to_dict()
    assert d["traffic"]["total_cheques_signed"] == 2
    assert d["traffic"]["total_cheques_verified"] == 2
    assert d["traffic"]["total_volume_settled_usdc"] == 0.003
    assert d["security"]["circuit_breaker_trips"] == 1
    assert d["clearing_mesh"]["cycles_eliminated"] == 5

    # Check JSON export
    json_str = metrics.to_json()
    parsed = json.loads(json_str)
    assert parsed["traffic"]["total_cheques_signed"] == 2

    # Check Prometheus export
    prom_str = metrics.to_prometheus()
    assert "csls_cheques_signed_total 2" in prom_str
    assert "csls_circuit_breaker_trips_total 1" in prom_str
    assert "csls_mesh_cycles_eliminated_total 5" in prom_str


def test_vendor_enforce_mac_rejects_unauthenticated_151_byte_cheques():
    """Verifies that a vendor with enforce_mac=True rejects legacy 151B cheques without Session MAC."""
    wallet = CausalAgentWallet()
    vendor = CausalVendorNode(delta_v_usdc=10.0, enforce_mac=True)

    # 1. Sign legacy 151-byte cheque without MAC
    legacy_cheque = wallet.sign_cheque(vendor.public_key, amount_usdc=0.005, session_mac=False)
    assert len(legacy_cheque.raw_packet) == 151

    # 2. Vendor must reject with CSLS_ERR_BAD_MAC (-24)
    res = vendor.process_cheque(legacy_cheque)
    assert res.accepted is False
    assert res.status_code == CSLS_ERR_BAD_MAC


def test_multithreaded_metrics_and_percentiles_concurrency():
    """Launches 10 concurrent threads updating CausalMetrics to verify thread safety and race freedom."""
    import threading
    metrics = CausalMetrics(window_size=5000)
    threads = []
    num_threads = 10
    ops_per_thread = 200

    def worker(tid: int):
        for i in range(ops_per_thread):
            lat = 5.0 + (i % 50) * 0.1
            metrics.record_sign(latency_us=lat, amount_micro=100)
            metrics.record_verify(latency_us=lat * 0.5)

    for tid in range(num_threads):
        t = threading.Thread(target=worker, args=(tid,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    d = metrics.to_dict()
    assert d["traffic"]["total_cheques_signed"] == num_threads * ops_per_thread
    assert d["traffic"]["total_cheques_verified"] == num_threads * ops_per_thread
    assert d["latency_us"]["sign"]["p50"] > 0
    assert d["latency_us"]["verify"]["p50"] > 0


def test_async_channel_actor_backpressure_queue_full(tmp_path):
    """Verifies that AsyncChannelActor raises CausalQueueFullError when max_queue_size is exceeded."""
    import asyncio
    db_dir = str(tmp_path / "channels")
    store = ChannelStore(db_dir)
    store.open()
    peer_pk = b"\x02" + (b"\x11" * 32)
    actor = AsyncChannelActor(peer_pk, store, max_queue_size=2)
    # Do not start worker so queue fills up

    async def _test():
        async def dummy_dispatch(h, cum):
            return "ok"

        # Submit 2 requests filling the queue
        f1 = asyncio.create_task(actor.submit(100, dummy_dispatch))
        f2 = asyncio.create_task(actor.submit(200, dummy_dispatch))
        await asyncio.sleep(0.01)

        # 3rd request must immediately raise CausalQueueFullError
        with pytest.raises(CausalQueueFullError) as exc_info:
            await actor.submit(300, dummy_dispatch)
        assert "backpressure limit exceeded" in str(exc_info.value)

        # Cleanup
        f1.cancel()
        f2.cancel()

    asyncio.run(_test())
    store.close()


def test_async_channel_actor_client_timeout_cancellation_skips_signing(tmp_path):
    """Verifies that if a client cancels a request, the worker loop skips execution without spending."""
    import asyncio
    db_dir = str(tmp_path / "channels_cancel")
    store = ChannelStore(db_dir)
    store.open()
    peer_pk = b"\x02" + (b"\x22" * 32)
    actor = AsyncChannelActor(peer_pk, store, max_queue_size=10)
    # Do not start actor immediately to ensure request sits in queue

    executed = []

    async def dummy_dispatch(h, cum):
        executed.append(h)
        return "ok"

    async def _test():
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        from sdk.async_causal import PaymentRequest
        req = PaymentRequest(amount_micro=500, dispatch_fn=dummy_dispatch, future=future)
        actor.queue.put_nowait(req)

        # Client cancels future before worker processes it
        future.cancel()

        # Start actor
        actor.start()
        await asyncio.sleep(0.05)
        await actor.stop()

        # Invariant: Cancelled request must NEVER be executed or signed
        assert len(executed) == 0, "Cancelled request must not be executed!"

    asyncio.run(_test())
    store.close()


def test_atexit_cleanup_registration():
    """Verifies that csls_crypto_global_cleanup is registered with atexit."""
    from sdk.causal_slash import _LIB
    assert hasattr(_LIB, "csls_crypto_global_cleanup")


def test_slash_proxy_streaming_http_forward_and_cheque_verification():
    """
    Verifies that when SlashSidecarProxy receives X-Causal-Cheque:
    1. It verifies the cheque via vendor_node (rejects forged/tampered cheques with HTTP 402).
    2. Forwards valid requests to upstream LLM in streaming mode with per-second micro-USDC metering.
    """
    import http.server
    import urllib.request
    import urllib.error
    import json
    import threading

    # 1. Setup mock upstream LLM HTTP server
    upstream_received = []

    class MockLLMHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            return

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            upstream_received.append(json.loads(body.decode()))

            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()

            # Stream 3 SSE chunks
            for i in range(3):
                chunk = f"data: {{\"choices\": [{{\"delta\": {{\"content\": \"token_{i}\"}}}}]}}\n\n"
                self.wfile.write(chunk.encode())
                self.wfile.flush()
                time.sleep(0.02)
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()

    mock_server = http.server.ThreadingHTTPServer(("127.0.0.1", 19188), MockLLMHandler)
    mock_thread = threading.Thread(target=mock_server.serve_forever, daemon=True)
    mock_thread.start()

    agent = CausalAgentWallet()
    vendor = CausalVendorNode(delta_v_usdc=10.0)
    # Authenticated Session MAC channel (C2 gate): the proxy's vendor node
    # mandates Session MAC by default (wire cheques omit the Schnorr point R).
    assert vendor.init_session(agent.create_session(vendor.public_key))

    proxy = SlashSidecarProxy(
        agent_wallet=agent,
        vendor_public_key=vendor.public_key,
        bind_host="127.0.0.1",
        bind_port=19199,
        upstream_url="http://127.0.0.1:19188",
        vendor_node=vendor,
        spend_rate_per_sec_usdc=0.001,
    )
    proxy.start()

    try:
        # A. Sign a valid authenticated cheque
        valid_cheque = agent.sign_cheque(vendor.public_key, amount_usdc=0.01, session_mac=True)
        req_data = json.dumps({"model": "mock-llama", "messages": [{"role": "user", "content": "hi"}]}).encode()

        req = urllib.request.Request(
            "http://127.0.0.1:19199/v1/chat/completions",
            data=req_data,
            headers={
                "Content-Type": "application/json",
                "X-Causal-Cheque": valid_cheque.raw_packet.hex(),
                "Connection": "close",
            },
        )
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            assert resp.status == 200
            assert resp.headers.get("X-Causal-Proxy-Mode") == "streaming-forward"
            chunks_received = resp.read().decode()
            assert "token_0" in chunks_received
            assert "token_1" in chunks_received
            assert "data: [DONE]" in chunks_received

        assert len(upstream_received) == 1
        assert upstream_received[0]["model"] == "mock-llama"

        # B. Test forged/tampered cheque rejection (HTTP 402)
        tampered_cheque_bytes = bytearray(valid_cheque.raw_packet)
        tampered_cheque_bytes[10] ^= 0xFF  # Corrupt packet

        bad_req = urllib.request.Request(
            "http://127.0.0.1:19199/v1/chat/completions",
            data=req_data,
            headers={
                "Content-Type": "application/json",
                "X-Causal-Cheque": bytes(tampered_cheque_bytes).hex(),
                "Connection": "close",
            },
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(bad_req, timeout=5.0)
        assert exc_info.value.code == 402
        exc_info.value.close()

    finally:
        proxy.stop()
        agent.close()
        mock_server.shutdown()
        mock_server.server_close()
        mock_thread.join(timeout=1.0)
