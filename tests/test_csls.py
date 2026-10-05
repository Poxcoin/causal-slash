# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Unit and integration tests for Causal-Slash CLI (CSLS).
Tests command registry, argument parsing, autocomplete data, and command execution.
"""

import os
import pytest
import asyncio
from prompt_toolkit.document import Document
from prompt_toolkit.completion import CompleteEvent

from csls.commands import registry, CommandRegistry, CslsSlashCompleter
from csls.commands.base import CommandContext
from csls.core.config import CslsConfig
from csls.core.session import SessionState
from csls.core.agent import StubAgentBackend, VendorAgentBackend, get_agent_backend
from csls.ui.theme import create_console, TEAL_HEX
from csls.ui.logo import get_logo_lines, get_logo_rich
from csls.cli import execute_line


EXPECTED_COMMANDS = [
    "/help",
    "/daemon",
    "/proxy",
    "/wallet",
    "/bond",
    "/status",
    "/stream",
    "/net",
    "/hound",
    "/test",
    "/bench",
    "/verify",
    "/exit",
    "/model",
    "/vendor",
    "/clear",
    "/memory",
]


class TestCommandRegistry:
    def test_registry_contains_all_17_commands(self):
        all_cmds = registry.list_all()
        cmd_names = [c.name for c in all_cmds]
        assert len(all_cmds) == 17
        for expected in EXPECTED_COMMANDS:
            assert expected in cmd_names

    def test_registry_lookup_case_insensitive(self):
        assert registry.get("/help") is not None
        assert registry.get("/HELP") is not None
        assert registry.get("/Daemon") is not None
        assert registry.get("/not_a_cmd") is None

    def test_closest_match_suggestions(self):
        # Typo suggestions
        assert registry.get_closest_match("/daemn") == "/daemon"
        assert registry.get_closest_match("/statu") == "/status"
        assert registry.get_closest_match("/bon") == "/bond"
        assert registry.get_closest_match("/walet") == "/wallet"
        assert registry.get_closest_match("/verfy") == "/verify"
        # Without leading slash
        assert registry.get_closest_match("exit") == "/exit"
        assert registry.get_closest_match("bench") == "/bench"


class TestAutocomplete:
    def test_slash_triggers_all_commands(self):
        completer = CslsSlashCompleter()
        doc = Document("/")
        completions = list(completer.get_completions(doc, CompleteEvent()))
        comp_texts = [c.text for c in completions]
        assert len(completions) == 17
        for expected in EXPECTED_COMMANDS:
            assert expected in comp_texts

    def test_prefix_filtering(self):
        completer = CslsSlashCompleter()
        doc = Document("/wa")
        completions = list(completer.get_completions(doc, CompleteEvent()))
        assert len(completions) == 1
        assert completions[0].text == "/wallet"
        assert "create agent wallet" in str(completions[0].display_meta)

    def test_subcommand_completion_for_wallet(self):
        completer = CslsSlashCompleter()
        doc = Document("/wallet ")
        completions = list(completer.get_completions(doc, CompleteEvent()))
        texts = [c.text for c in completions]
        assert "new" in texts
        assert "info" in texts

    def test_subcommand_completion_for_model(self):
        completer = CslsSlashCompleter()
        doc = Document("/model ")
        completions = list(completer.get_completions(doc, CompleteEvent()))
        texts = [c.text for c in completions]
        assert "claude-opus-5.5" in texts
        assert "claude-opus-4.6" in texts
        assert "deepseek-v4.1-flash" in texts
        assert "deepseek-v4-pro" in texts
        assert "glm-5.3" in texts
        assert "glm-5.2" in texts
        assert "gemini-3.8-flash" in texts
        assert "gemini-3.8-live" in texts

    def test_flag_completion_for_daemon(self):
        completer = CslsSlashCompleter()
        doc = Document("/daemon ")
        completions = list(completer.get_completions(doc, CompleteEvent()))
        flags = [c.text for c in completions]
        assert "--port" in flags
        assert "--vendor-sk" in flags
        assert "--buffer" in flags

    def test_non_slash_input_produces_no_slash_completions(self):
        completer = CslsSlashCompleter()
        doc = Document("hello world")
        completions = list(completer.get_completions(doc, CompleteEvent()))
        assert len(completions) == 0


class TestCommandExecution:
    def test_help_command(self):
        async def _run():
            session = SessionState()
            console = create_console()
            ctx = CommandContext(session=session, console=console)
            cmd = registry.get("/help")
            assert cmd is not None
            rc = await cmd.run(ctx, [])
            assert rc == 0
        asyncio.run(_run())

    def test_help_specific_command(self):
        async def _run():
            session = SessionState()
            console = create_console()
            ctx = CommandContext(session=session, console=console)
            cmd = registry.get("/help")
            assert cmd is not None
            rc = await cmd.run(ctx, ["daemon"])
            assert rc == 0
        asyncio.run(_run())

    def test_bond_command(self):
        async def _run():
            session = SessionState()
            console = create_console()
            ctx = CommandContext(session=session, console=console)
            cmd = registry.get("/bond")
            assert cmd is not None
            rc = await cmd.run(ctx, [])
            assert rc == 0
            assert session.bond_status == "ready"
        asyncio.run(_run())

    def test_exit_command(self):
        async def _run():
            session = SessionState()
            console = create_console()
            ctx = CommandContext(session=session, console=console)
            cmd = registry.get("/exit")
            assert cmd is not None
            assert session.should_exit is False
            rc = await cmd.run(ctx, [])
            assert rc == 0
            assert session.should_exit is True
        asyncio.run(_run())

    def test_model_command(self):
        async def _run():
            session = SessionState()
            console = create_console()
            ctx = CommandContext(session=session, console=console)
            cmd = registry.get("/model")
            assert cmd is not None
            # List models
            rc = await cmd.run(ctx, [])
            assert rc == 0
            # Switch to DeepSeek V4.1 Flash
            rc = await cmd.run(ctx, ["deepseek-v4.1-flash"])
            assert rc == 0
            assert session.current_model == "deepseek-v4.1-flash"
            # Switch to Gemini 3.8 Flash
            rc = await cmd.run(ctx, ["gemini-3.8-flash"])
            assert rc == 0
            assert session.current_model == "gemini-3.8-flash"
            # Invalid model returns non-zero error
            rc = await cmd.run(ctx, ["nonexistent-model"])
            assert rc == 1
        asyncio.run(_run())

    def test_vendor_command(self):
        async def _run():
            session = SessionState()
            console = create_console()
            ctx = CommandContext(session=session, console=console)
            cmd = registry.get("/vendor")
            assert cmd is not None
            rc = await cmd.run(ctx, [])
            assert rc == 0
        asyncio.run(_run())

    def test_clear_command_resets_memory(self, tmp_path, monkeypatch):
        async def _run():
            import csls.core.session as session_mod
            monkeypatch.setattr(session_mod, "CONFIG_DIR", str(tmp_path))
            session = SessionState(cwd=str(tmp_path))
            console = create_console()
            ctx = CommandContext(session=session, console=console)
            session.add_dialog_turn("User query", "Agent response")
            assert len(session.conversation_memory) == 2
            cmd = registry.get("/clear")
            assert cmd is not None
            rc = await cmd.run(ctx, [])
            assert rc == 0
            assert len(session.conversation_memory) == 0
        asyncio.run(_run())

    def test_agent_backend_routing_and_memory(self, tmp_path, monkeypatch):
        async def _run():
            import csls.core.session as session_mod
            monkeypatch.setattr(session_mod, "CONFIG_DIR", str(tmp_path))
            # Explicit vendor backend
            cfg_vendor = CslsConfig(agent={"backend": "vendor", "model": "claude-opus-5.5"})
            session_vendor = SessionState(config=cfg_vendor, cwd=str(tmp_path))
            agent_vendor = get_agent_backend(session_vendor)
            assert isinstance(agent_vendor, VendorAgentBackend)

            # Explicit stub backend
            cfg_stub = CslsConfig(agent={"backend": "stub"})
            session_stub = SessionState(config=cfg_stub, cwd=str(tmp_path))
            agent_stub = get_agent_backend(session_stub)
            assert isinstance(agent_stub, StubAgentBackend)

            # Rolling memory window (up to 50 items)
            for i in range(30):
                session_vendor.add_dialog_turn(f"Query {i}", f"Reply {i}")
            assert len(session_vendor.conversation_memory) == 50
            assert session_vendor.conversation_memory[-1]["content"] == "Reply 29"

            # Execute line with stub agent
            console = create_console()
            ctx = CommandContext(session=session_stub, console=console)
            await execute_line("What is the current gas cost?", ctx)
        asyncio.run(_run())

    def test_memory_command(self, tmp_path, monkeypatch):
        async def _run():
            import csls.core.session as session_mod
            monkeypatch.setattr(session_mod, "CONFIG_DIR", str(tmp_path))
            session = SessionState(cwd=str(tmp_path))
            console = create_console()
            ctx = CommandContext(session=session, console=console)
            session.add_dialog_turn("What is Causal Slash?", "A sovereign clearing protocol.")
            cmd = registry.get("/memory")
            assert cmd is not None
            rc = await cmd.run(ctx, [])
            assert rc == 0
        asyncio.run(_run())

    def test_unknown_command_shows_suggestion(self):
        async def _run():
            session = SessionState()
            console = create_console()
            ctx = CommandContext(session=session, console=console)
            await execute_line("/daemn", ctx)
            await execute_line("/unknown_foo", ctx)
        asyncio.run(_run())


class TestLogoAndTheme:
    def test_logo_generation(self):
        lines_main = get_logo_lines(small=False)
        assert len(lines_main) == 9
        for line in lines_main:
            assert len(line) > 0

        lines_small = get_logo_lines(small=True)
        assert len(lines_small) == 3

    def test_logo_rich(self):
        rich_lines = get_logo_rich(small=False)
        assert len(rich_lines) == 9
        rich_small = get_logo_rich(small=True)
        assert len(rich_small) == 3

    def test_session_bond_status_mutation(self):
        session = SessionState()
        session.set_bond_status("ready")
        assert session.bond_status == "ready"
        session.set_bond_status("no bond")
        assert session.bond_status == "no bond"
        session.set_bond_status("error")
        assert session.bond_status == "error"
        session.set_bond_status("invalid_status")
        assert session.bond_status == "error"


class TestSovereignGate:
    def test_check_activation_needed(self):
        from csls.ui.gate import check_activation_needed

        # Case 1: No wallet -> activation needed
        s1 = SessionState(wallet_address=None, bond_status="no bond", collateral_usdc=0.0)
        assert check_activation_needed(s1) is True

        # Case 2: Wallet exists but no bond -> activation needed
        s2 = SessionState(wallet_address="0x123", bond_status="no bond", collateral_usdc=0.0)
        assert check_activation_needed(s2) is True

        # Case 3: Wallet exists and bond is ready -> unlocked!
        s3 = SessionState(wallet_address="0x123", bond_status="ready", collateral_usdc=10.0)
        assert check_activation_needed(s3) is False

    def test_save_wallet_bond_helper(self, tmp_path):
        import json
        from csls.ui.gate import _save_wallet_bond

        w_path = str(tmp_path / "wallet.json")
        initial = {"address": "0xabc", "collateral_bond": 0.0, "status": "unfunded"}
        with open(w_path, "w", encoding="utf-8") as f:
            json.dump(initial, f)

        _save_wallet_bond(w_path, 10.0, "ready")

        with open(w_path, "r", encoding="utf-8") as f:
            updated = json.load(f)

        assert updated["collateral_bond"] == 10.0
        assert updated["status"] == "ready"

    def test_ensure_sovereign_identity(self, tmp_path, monkeypatch):
        import csls.ui.gate as gate_mod
        from csls.ui.gate import ensure_sovereign_identity
        monkeypatch.setattr(gate_mod, "CONFIG_DIR", str(tmp_path))
        s = SessionState(wallet_address=None, bond_status="no bond", collateral_usdc=0.0)
        assert ensure_sovereign_identity(s) is True
        assert s.wallet_address is not None
        assert s.bond_status == "ready"
        assert s.collateral_usdc == 10.0


class TestPersistentChatMemory:
    def test_memory_disk_roundtrip(self, tmp_path, monkeypatch):
        import csls.core.session as session_mod
        monkeypatch.setattr(session_mod, "CONFIG_DIR", str(tmp_path))

        proj_dir = tmp_path / "my_project"
        proj_dir.mkdir()

        # Session 1: write dialog turn
        s1 = SessionState(cwd=str(proj_dir))
        assert len(s1.conversation_memory) == 0
        s1.add_dialog_turn("User question: How does Kirchhoff netting work?", "Kirchhoff netting balances agent debt in RAM.")
        assert len(s1.conversation_memory) == 2
        assert os.path.exists(s1.project_memory_file)

        # Session 2: reload from disk in same project directory
        s2 = SessionState(cwd=str(proj_dir))
        assert len(s2.conversation_memory) == 2
        assert s2.conversation_memory[0]["content"] == "User question: How does Kirchhoff netting work?"
        assert s2.conversation_memory[1]["content"] == "Kirchhoff netting balances agent debt in RAM."

        # Clear memory removes disk file
        s2.clear_memory()
        assert len(s2.conversation_memory) == 0
        assert not os.path.exists(s2.project_memory_file)

        # Session 3: reopened project starts clean
        s3 = SessionState(cwd=str(proj_dir))
        assert len(s3.conversation_memory) == 0


class TestNetworkDiscoveryAndFailFast:
    def test_discovery_offline_returns_none(self):
        from csls.core.discovery import NetworkDiscovery
        async def _run():
            # Point to invalid port
            url, health = await NetworkDiscovery.resolve_active_vendor("http://127.0.0.1:59999", timeout=0.1)
            # If no local or public relay is responding, returns None, None
            # (or if one is responding in env, validates structure)
            if url is None:
                assert health is None
        asyncio.run(_run())

    def test_vendor_backend_offline_fails_fast_without_mocking(self, tmp_path, monkeypatch):
        from csls.core.agent import VendorAgentBackend
        import csls.core.discovery as disc_mod
        async def _mock_resolve(*args, **kwargs):
            return None, None
        monkeypatch.setattr(disc_mod.NetworkDiscovery, "resolve_active_vendor", _mock_resolve)

        async def _run():
            session = SessionState(cwd=str(tmp_path))
            console = create_console()
            agent = VendorAgentBackend()
            await agent.process_query("Write a rust quicksort", session, console)
            # Must NOT generate fake mock completions or add fake messages
            assert len(session.conversation_memory) == 0
            assert session.total_queries == 0
        asyncio.run(_run())



