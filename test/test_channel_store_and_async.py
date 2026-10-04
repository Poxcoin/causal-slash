# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Unit tests for Crash-Proof Channel Store, Swarm Subagent Isolation, and AsyncIO Concurrency.
Verifies compliance with Axiom 1 (Swarm Isolation), Axiom 2 (Monotonic Schnorr 151B),
and Axiom 6 (EOTS Safety under crash recovery).
"""

import asyncio
import os
import shutil
import sys
import tempfile
import pytest

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
if os.path.join(_ROOT, "sdk") not in sys.path:
    sys.path.insert(0, os.path.join(_ROOT, "sdk"))

from sdk.channel_store import (
    ChannelStore,
    ChannelStoreLockedError,
    ChannelStoreError,
)
from sdk.swarm_subagent import (
    SwarmDelegationVault,
    SubagentSession,
    SubagentQuotaExceededError,
    SpendRateLimitExceededError,
)
from sdk.async_causal import (
    AsyncChannelActor,
    AsyncCausalClient,
)
from sdk.integrations.langchain import (
    causal_paid_tool,
    CausalPaidTool,
)


@pytest.fixture
def temp_dir():
    d = tempfile.mkdtemp(prefix="csls_test_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


def test_channel_store_basic_flow_and_leap_ahead(temp_dir):
    peer_pk = b"\x02" + b"\x11" * 32
    store = ChannelStore(temp_dir, "test_channel.db")
    store.open()

    # Initial state
    assert store.get_channel(peer_pk) is None

    # Phase 1: Reserve height 1
    h1 = store.reserve_height(peer_pk)
    assert h1 == 1

    # Phase 2: Commit cheque 1
    store.commit_cheque(peer_pk, height=1, cumulative_amt=500)
    rec = store.get_channel(peer_pk)
    assert rec.committed_height == 1
    assert rec.cumulative_amt == 500

    # Next reserve should be 2
    h2 = store.reserve_height(peer_pk)
    assert h2 == 2
    store.commit_cheque(peer_pk, height=2, cumulative_amt=1000)

    # SIMULATE CRASH: Reserve height 3, but DO NOT commit!
    h3 = store.reserve_height(peer_pk)
    assert h3 == 3
    store.close()

    # Reopen after crash: store must perform FAIL-FORWARD LEAP-AHEAD to height 4
    store2 = ChannelStore(temp_dir, "test_channel.db")
    store2.open()

    # The uncommitted h3 must NEVER be reused!
    h_next = store2.reserve_height(peer_pk)
    assert h_next == 4, f"Expected leap-ahead height 4, got {h_next}"
    store2.commit_cheque(peer_pk, height=4, cumulative_amt=2000)

    rec2 = store2.get_channel(peer_pk)
    assert rec2.committed_height == 4
    assert rec2.cumulative_amt == 2000
    store2.close()


def test_channel_store_exclusive_process_lock(temp_dir):
    store1 = ChannelStore(temp_dir, "locked.db")
    store1.open()

    # Second instance must fail to acquire lock
    store2 = ChannelStore(temp_dir, "locked.db")
    with pytest.raises(ChannelStoreLockedError):
        store2.open()

    store1.close()

    # Now store2 can open
    store2.open()
    store2.close()


def test_swarm_delegation_vault_quota_isolation():
    master_sk = b"\x42" * 32
    vault = SwarmDelegationVault(master_sk)

    # Subagent 1 with 10,000 micro-USDC ($0.01) quota
    s1 = vault.spawn_subagent("worker_llm", quota_micro_usdc=10_000)
    assert s1.sub_sk != master_sk
    assert len(s1.sub_sk) == 32
    assert s1.remaining_quota == 10_000

    # Spend 6,000
    s1.check_and_reserve(6_000)
    s1.commit_spend(6_000)
    assert s1.remaining_quota == 4_000

    # Spend another 4,000 (exhausts quota)
    s1.check_and_reserve(4_000)
    s1.commit_spend(4_000)
    assert s1.remaining_quota == 0

    # Over-quota spend must raise SubagentQuotaExceededError (Axiom 1 protection)
    with pytest.raises(SubagentQuotaExceededError):
        s1.check_and_reserve(1)


def test_async_channel_actor_concurrency_and_fifo(temp_dir):
    async def _run():
        peer_pk = b"\x02" + b"\xaa" * 32
        master_sk = b"\x99" * 32
        client = await AsyncCausalClient.create(master_sk, temp_dir)
        session = client.spawn_subagent("async_worker", quota_micro_usdc=100_000)

        dispatched_heights = []

        async def mock_dispatch(h: int, cum: int):
            await asyncio.sleep(0.01)  # Simulate network latency
            dispatched_heights.append((h, cum))
            return f"ACK_{h}"

        # Launch 5 concurrent payment tasks for the same vendor
        tasks = [
            client.pay_and_stream(session, peer_pk, amount_micro=100, dispatch_fn=mock_dispatch)
            for _ in range(5)
        ]
        results = await asyncio.gather(*tasks)

        # All 5 results must have succeeded
        assert results == [f"ACK_{i}" for i in range(1, 6)]

        # Heights must be strictly sequential (1, 2, 3, 4, 5) with monotonic cumulative amounts
        assert len(dispatched_heights) == 5
        for idx, (h, cum) in enumerate(dispatched_heights, start=1):
            assert h == idx
            assert cum == idx * 100

        await client.close()

    asyncio.run(_run())


def test_causal_paid_tool_integration(temp_dir):
    async def _run():
        peer_pk = b"\x02" + b"\xbb" * 32
        master_sk = b"\x77" * 32
        client = await AsyncCausalClient.create(master_sk, temp_dir)
        session = client.spawn_subagent("tool_caller", quota_micro_usdc=50_000)

        payments = []

        async def mock_dispatch(h: int, cum: int):
            payments.append((h, cum))
            return True

        @causal_paid_tool(
            client=client,
            session=session,
            vendor_pk=peer_pk,
            cost_micro_usdc=250,
            dispatch_fn=mock_dispatch,
        )
        async def multiply_numbers(x: int, y: int) -> int:
            return x * y

        # Invoke tool
        result = await multiply_numbers(6, 7)
        assert result == 42
        assert len(payments) == 1
        assert payments[0] == (1, 250)
        assert session.remaining_quota == 50_000 - 250

        await client.close()

    asyncio.run(_run())


# ============================================================================
# NEW TESTS: secp256k1 PK, Circuit Breaker, Proxy Subagent Integration
# ============================================================================


def test_secp256k1_honest_pubkey_derivation():
    """
    Verifies that SubagentSession.sub_pk is an honest 33-byte compressed
    secp256k1 public key (PK = sub_sk · G) derived via the C11 engine,
    NOT a random SHA-256 hash.

    Validation criteria:
    1. Length must be exactly 33 bytes.
    2. Prefix byte must be 0x02 or 0x03 (valid compressed point prefix).
    3. The PK must match what the C library produces for the same SK.
    4. Different subagents must have different PKs.
    5. The PK must NOT be a SHA-256 hash of the SK (the old broken behavior).
    """
    import hashlib
    from sdk.swarm_subagent import _derive_secp256k1_pubkey

    master_sk = b"\x42" * 32
    vault = SwarmDelegationVault(master_sk)

    s1 = vault.spawn_subagent("verifier_agent", quota_micro_usdc=100_000)

    # 1. Correct length
    assert len(s1.sub_pk) == 33, f"PK length must be 33, got {len(s1.sub_pk)}"

    # 2. Valid compressed prefix (0x02 or 0x03)
    assert s1.sub_pk[0] in (0x02, 0x03), (
        f"PK prefix must be 0x02 or 0x03, got 0x{s1.sub_pk[0]:02x}"
    )

    # 3. Must match C library derivation for the same SK
    expected_pk = _derive_secp256k1_pubkey(s1.sub_sk)
    assert s1.sub_pk == expected_pk, (
        f"PK mismatch: got {s1.sub_pk.hex()}, expected {expected_pk.hex()}"
    )

    # 4. Different subagent must have different PK
    s2 = vault.spawn_subagent("different_agent", quota_micro_usdc=50_000)
    assert s1.sub_pk != s2.sub_pk, "Different subagents must have different PKs"
    assert s1.sub_sk != s2.sub_sk, "Different subagents must have different SKs"

    # 5. PK must NOT be the old broken SHA-256 hash stub
    broken_pk = b"\x02" + hashlib.sha256(b"csls_sub_pk:" + s1.sub_sk).digest()[:32]
    assert s1.sub_pk != broken_pk, (
        "PK must NOT be a SHA-256 hash — it must be an actual secp256k1 curve point!"
    )


def test_circuit_breaker_spend_rate_limiting():
    """
    Verifies the Circuit Breaker mechanism:
    1. Spending within the rate limit succeeds.
    2. Exceeding the configured max_spend_rate_usdc_per_min raises SpendRateLimitExceededError.
    3. The sliding window properly accounts for recent spending.
    4. Custom rate limits work correctly.
    """
    master_sk = b"\x55" * 32
    vault = SwarmDelegationVault(master_sk)

    # Create subagent with $0.50/min rate limit and generous quota
    session = vault.spawn_subagent(
        "rate_limited_bot",
        quota_micro_usdc=10_000_000,  # $10 quota (generous)
        max_spend_rate_usdc_per_min=0.50,  # $0.50/min limit
    )

    # Spend $0.40 (400,000 micro) — should succeed (under $0.50/min)
    session.check_spend_rate(400_000)
    session.commit_spend(400_000)

    # Now try to spend another $0.20 (200,000 micro) — total $0.60 > $0.50 limit
    with pytest.raises(SpendRateLimitExceededError) as exc_info:
        session.check_spend_rate(200_000)
    assert "Rate limit exceeded" in str(exc_info.value)
    assert "$0.5/min" in str(exc_info.value)

    # Remaining quota should still be available (rate limit != quota)
    assert session.remaining_quota == 10_000_000 - 400_000


def test_circuit_breaker_default_rate():
    """
    Verifies the default $2/min rate limit works as expected.
    """
    master_sk = b"\x66" * 32
    vault = SwarmDelegationVault(master_sk)

    # Default rate: $2/min
    session = vault.spawn_subagent(
        "default_rate_bot",
        quota_micro_usdc=50_000_000,  # $50 quota
    )
    assert session.max_spend_rate_usdc_per_min == 2.0

    # Spend $1.90 — should be fine
    session.check_spend_rate(1_900_000)
    session.commit_spend(1_900_000)

    # Spend another $0.20 — total $2.10 > $2.00 limit
    with pytest.raises(SpendRateLimitExceededError):
        session.check_spend_rate(200_000)


def test_circuit_breaker_in_async_pay_and_stream(temp_dir):
    """
    Verifies that AsyncCausalClient.pay_and_stream enforces Circuit Breaker
    before dispatching payments.
    """
    async def _run():
        peer_pk = b"\x02" + b"\xcc" * 32
        master_sk = b"\xdd" * 32
        client = await AsyncCausalClient.create(master_sk, temp_dir)
        session = client.spawn_subagent(
            "async_rate_bot",
            quota_micro_usdc=50_000_000,
        )
        # Override to a tiny rate for testing
        session.max_spend_rate_usdc_per_min = 0.001  # $0.001/min

        async def mock_dispatch(h: int, cum: int):
            return f"ACK_{h}"

        # First call: 500 micro ($0.0005) — should succeed
        result = await client.pay_and_stream(
            session, peer_pk, amount_micro=500, dispatch_fn=mock_dispatch
        )
        assert result == "ACK_1"

        # Second call: another 600 micro — total 1100 > 1000 limit
        with pytest.raises(SpendRateLimitExceededError):
            await client.pay_and_stream(
                session, peer_pk, amount_micro=600, dispatch_fn=mock_dispatch
            )

        await client.close()

    asyncio.run(_run())


def test_proxy_subagent_header_integration():
    """
    Verifies proxy integration with X-Causal-Subagent-Id header:
    1. Requests with valid subagent header use subagent session.
    2. Requests with unknown subagent header return 404.
    3. Requests without header work as before (master wallet).
    4. Subagent quota is consumed correctly.
    """
    import urllib.request

    agent_sk = bytes([0x77] * 32)
    vendor_sk = bytes([0x88] * 32)

    agent = CausalAgentWallet(agent_sk)
    vendor = CausalVendorNode(vendor_sk, delta_v_usdc=50.0)

    # Create delegation vault and spawn a subagent
    vault = SwarmDelegationVault(agent_sk)
    sub_session = vault.spawn_subagent(
        "proxy_test_bot", quota_micro_usdc=5_000  # $0.005 quota
    )

    proxy = SlashSidecarProxy(
        agent_wallet=agent,
        vendor_public_key=vendor.public_key,
        price_per_request_usdc=0.001,  # $0.001 per call = 1000 micro
        bind_host="127.0.0.1",
        bind_port=19099,
        delegation_vault=vault,
    )
    proxy.start()

    try:
        import json
        url = "http://127.0.0.1:19099/v1/chat/completions"
        payload = json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": "test"}]}).encode()

        # Test 1: Request WITHOUT subagent header — master wallet (existing behavior)
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode())
            assert data["_causal_slash"]["subagent_id"] is None

        # Test 2: Request WITH valid subagent header
        req = urllib.request.Request(url, data=payload, headers={
            "Content-Type": "application/json",
            "X-Causal-Subagent-Id": "proxy_test_bot",
        })
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode())
            assert data["_causal_slash"]["subagent_id"] == "proxy_test_bot"
            assert resp.headers.get("X-Causal-Subagent-Id") == "proxy_test_bot"

        # Subagent should have 1000 micro spent
        assert sub_session.spent_micro_usdc == 1_000

        # Test 3: Request with UNKNOWN subagent header — should return 404
        req = urllib.request.Request(url, data=payload, headers={
            "Content-Type": "application/json",
            "X-Causal-Subagent-Id": "nonexistent_bot",
        })
        try:
            urllib.request.urlopen(req)
            assert False, "Should have raised HTTPError 404"
        except urllib.error.HTTPError as e:
            assert e.code == 404

        # Test 4: Exhaust subagent quota (4 more requests x $0.001 = $0.004, total $0.005)
        for _ in range(4):
            req = urllib.request.Request(url, data=payload, headers={
                "Content-Type": "application/json",
                "X-Causal-Subagent-Id": "proxy_test_bot",
            })
            with urllib.request.urlopen(req) as resp:
                assert resp.status == 200

        assert sub_session.remaining_quota == 0

        # Test 5: Over-quota request should return 429
        req = urllib.request.Request(url, data=payload, headers={
            "Content-Type": "application/json",
            "X-Causal-Subagent-Id": "proxy_test_bot",
        })
        try:
            urllib.request.urlopen(req)
            assert False, "Should have raised HTTPError 429 (quota exceeded)"
        except urllib.error.HTTPError as e:
            assert e.code == 429

    finally:
        proxy.stop()
        agent.close()


# Import CausalAgentWallet and CausalVendorNode for proxy subagent test
from sdk.causal_slash import CausalAgentWallet, CausalVendorNode
from sdk.slash_proxy import SlashSidecarProxy
