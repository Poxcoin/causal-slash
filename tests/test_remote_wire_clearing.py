# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Integration test for remote M2M wire clearing over 167-byte Session MAC micro-cheques
and persistent rolling memory in CSLS (/v1/chat/completions).
"""

import pytest
import asyncio
import json
import os
import sys
import threading
import time
import httpx

from csls.core.session import SessionState
from csls.core.agent import VendorAgentBackend
from csls.core.config import CslsConfig, CONFIG_DIR
from csls.ui.theme import create_console
from csls.ui.gate import ensure_sovereign_identity, check_activation_needed
from scripts.launch_b2b_gateway import launch_gateway, FrontierGatewayServer

# Ensure SDK is loaded
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if os.path.join(_ROOT, "sdk") not in sys.path:
    sys.path.insert(0, os.path.join(_ROOT, "sdk"))

from causal_slash import CausalAgentWallet, CausalVendorNode, CSLS_OK, CSLS_ERR_BAD_MAC


@pytest.fixture(scope="module")
def frontier_gateway():
    """Launch ephemeral Frontier Vendor Gateway on random free port."""
    server = launch_gateway(host="127.0.0.1", port=0, delta_v_usdc=25.0, price_per_call=0.0005)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)
    yield f"http://127.0.0.1:{port}", server
    server.shutdown()
    server.server_close()


class TestRemoteM2MWireClearing:
    def test_167_byte_cheque_wire_spec(self):
        """Verify that Session MAC cheques strictly conform to the 167-byte wire packet standard."""
        agent = CausalAgentWallet()
        vendor = CausalVendorNode()
        pkt = agent.create_session(vendor.public_key)
        assert vendor.init_session(pkt)

        cheque = agent.sign_cheque(vendor.public_key, amount_usdc=0.0005, session_mac=True)
        assert len(cheque.raw_packet) == 167
        assert cheque.height == 1

        res = vendor.process_cheque(cheque.raw_packet)
        assert res.accepted is True
        assert res.status_code == CSLS_OK

    def test_instant_sovereign_identity_provisioning(self, tmp_path, monkeypatch):
        """Verify instant sovereign identity and sandbox margin auto-provisioning in milliseconds."""
        import csls.ui.gate as gate_mod
        monkeypatch.setattr(gate_mod, "CONFIG_DIR", str(tmp_path))

        session = SessionState(wallet_address=None, bond_status="no bond", collateral_usdc=0.0)
        assert check_activation_needed(session) is True

        t0 = time.perf_counter()
        ok = ensure_sovereign_identity(session)
        elapsed_ms = (time.perf_counter() - t0) * 1000

        assert ok is True
        assert elapsed_ms < 50.0  # Runs in single-digit milliseconds
        assert session.wallet_address is not None
        assert session.bond_status == "ready"
        assert session.collateral_usdc == 10.0
        assert check_activation_needed(session) is False

    def test_gateway_health_and_frontier_models(self, frontier_gateway):
        """Verify gateway health endpoint lists all 8 2026 Frontier Models."""
        async def _run():
            gw_url, _ = frontier_gateway
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"{gw_url}/health")
                assert resp.status_code == 200
                data = resp.json()
                assert data["settlement_mode"] == "SOVEREIGN_M2M_MICRO_CHEQUES"
                assert data["web2_api_keys"] == "STRICTLY_BANNED"

                expected_models = [
                    "claude-opus-5.5",
                    "claude-opus-4.6",
                    "deepseek-v4.1-flash",
                    "deepseek-v4-pro",
                    "glm-5.3",
                    "glm-5.2",
                    "gemini-3.8-flash",
                    "gemini-3.8-live",
                ]
                for m in expected_models:
                    assert m in data["supported_models"]
        asyncio.run(_run())

    def test_multi_turn_m2m_clearing_and_rolling_memory(self, frontier_gateway, tmp_path, monkeypatch):
        """
        Verify end-to-end multi-turn chat over /v1/chat/completions paid by 167-byte Session MAC micro-cheques
        with persistent rolling conversation memory.
        """
        async def _run():
            gw_url, server = frontier_gateway
            import csls.core.agent as agent_mod
            import csls.ui.gate as gate_mod
            import csls.core.session as session_mod
            monkeypatch.setattr(agent_mod, "CONFIG_DIR", str(tmp_path))
            monkeypatch.setattr(gate_mod, "CONFIG_DIR", str(tmp_path))
            monkeypatch.setattr(session_mod, "CONFIG_DIR", str(tmp_path))

            cfg = CslsConfig(agent={
                "backend": "vendor",
                "vendor_url": gw_url,
                "model": "claude-opus-5.5",
                "price_per_call": 0.0005,
            })
            session = SessionState(config=cfg, cwd=str(tmp_path))
            session.vendor_url = gw_url
            session.current_model = "claude-opus-5.5"

            # Initialize sovereign identity
            ensure_sovereign_identity(session)
            assert session.wallet_address is not None

            console = create_console()
            agent = VendorAgentBackend()

            # Turn 1: First user query
            q1 = "Explain the Causal-Slash consensus mechanism."
            await agent.process_query(q1, session, console)

            assert session.total_queries == 1
            assert session.accumulated_spent_usdc == 0.0005
            assert len(session.conversation_memory) == 2
            assert session.conversation_memory[0]["content"] == q1
            assert "Verified compute" in session.conversation_memory[1]["content"]

            # Turn 2: Follow-up query leveraging persistent rolling memory
            q2 = "Summarize the primary advantage in 5 words."
            await agent.process_query(q2, session, console)

            assert session.total_queries == 2
            assert session.accumulated_spent_usdc == 0.0010
            assert len(session.conversation_memory) == 4
            assert session.conversation_memory[2]["content"] == q2

            # Turn 3: Switch model to deepseek-v4.1-flash and query over wire
            session.current_model = "deepseek-v4.1-flash"
            q3 = "Calculate optimal gas rebate for 1000 micro-cheques."
            await agent.process_query(q3, session, console)

            assert session.total_queries == 3
            assert session.accumulated_spent_usdc == 0.0015
            assert len(session.conversation_memory) == 6
            assert session.conversation_memory[4]["content"] == q3
            assert "[deepseek-v4.1-flash]" in session.conversation_memory[5]["content"]

            # Verify rolling memory cap (limited to 50 items)
            for i in range(30):
                session.add_dialog_turn(f"History User {i}", f"History Assistant {i}")
            assert len(session.conversation_memory) == 50
        asyncio.run(_run())
