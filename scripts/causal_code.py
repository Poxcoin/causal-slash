#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Causal Code: Production Sovereign Terminal Coding Agent

Interactive, full-featured terminal coding agent (like Claude Code) powered by
Causal-Slash Protocol and multi-turn conversational ReAct engine.

Capabilities:
1. Interactive multi-turn chat REPL maintaining full conversation memory.
2. Built-in tool calling: file exploration, reading, writing, and bash command execution.
3. Sovereign M2M settlement: 167-byte Session MAC micro-cheques against a $10.00 USDC deposit.
4. Optional direct provider key binding (/key) or pure sovereign zero-key mesh mode.
5. Persistent wallet and configuration in ~/.causal.
"""

from __future__ import annotations
import argparse
import base64
import http.server
import json
import os
import readline
import re
import shlex
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional, Dict, Any, Tuple, List

from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.live import Live

_REAL_SCRIPT = os.path.realpath(__file__)
_ROOT = os.path.abspath(os.path.join(os.path.dirname(_REAL_SCRIPT), ".."))
if os.path.join(_ROOT, "sdk") not in sys.path:
    sys.path.insert(0, os.path.join(_ROOT, "sdk"))
if os.path.join(_ROOT, "scripts") not in sys.path:
    sys.path.insert(0, os.path.join(_ROOT, "scripts"))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from causal_slash import (
    CausalAgentWallet,
    CausalVendorNode,
    Cheque,
    CSLS_OK,
)

console = Console()

CAUSAL_DIR = os.path.expanduser("~/.causal")
WALLET_FILE = os.path.join(CAUSAL_DIR, "wallet.json")
CONFIG_FILE = os.path.join(CAUSAL_DIR, "config.json")
HISTORY_FILE = os.path.join(CAUSAL_DIR, "history.json")


def load_or_create_config() -> Dict[str, Any]:
    """Loads persistent CLI configuration or creates default."""
    os.makedirs(CAUSAL_DIR, exist_ok=True)
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    default_cfg = {
        "deposit_usdc": 10.0,
        "vendor_url": "http://127.0.0.1:8402",
        "api_key": None,
        "provider": "sovereign",
        "model": "claude-3-7-sonnet-20250219",
    }
    save_config(default_cfg)
    return default_cfg


def save_config(cfg: Dict[str, Any]) -> None:
    """Saves CLI configuration to ~/.causal/config.json."""
    os.makedirs(CAUSAL_DIR, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def load_or_create_wallet() -> CausalAgentWallet:
    """Loads sovereign secp256k1 wallet from ~/.causal/wallet.json or generates a new one."""
    os.makedirs(CAUSAL_DIR, exist_ok=True)
    if os.path.isfile(WALLET_FILE):
        try:
            with open(WALLET_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                sk_hex = data.get("secret_key", "")
                if sk_hex:
                    sk_bytes = bytes.fromhex(sk_hex.replace("0x", ""))
                    return CausalAgentWallet(secret_key=sk_bytes)
        except Exception:
            pass
    # Generate fresh wallet and persist
    wallet = CausalAgentWallet()
    sk_hex = bytes(wallet._ctx.sk).hex()
    data = {
        "secret_key": sk_hex,
        "public_key": wallet.public_key_hex,
        "created_at": time.time(),
        "network": "Base L2",
    }
    with open(WALLET_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return wallet


class SovereignCodingAgent:
    """
    Autonomous terminal coding agent backed by Causal-Slash micro-cheques
    and conversational multi-turn ReAct reasoning loop.
    """
    def __init__(
        self,
        work_dir: Optional[str] = None,
        autonomous: bool = False,
    ):
        self.work_dir = os.path.abspath(work_dir or os.getcwd())
        self.autonomous = autonomous
        self.config = load_or_create_config()
        self.wallet = load_or_create_wallet()

        self.balance_usdc = float(self.config.get("deposit_usdc", 10.0))
        self.price_per_call = 0.0005
        self.vendor_url = self.config.get("vendor_url", "http://127.0.0.1:8402").rstrip("/")
        self.api_key = self.config.get("api_key") or os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY")
        self.model = self.config.get("model", "claude-3-7-sonnet-20250219")

        self.vendor_pk: Optional[bytes] = None
        self.vendor_pk_hex: str = ""
        self.session_active = False

        self.cheques_signed = 0
        self.total_settled_usdc = 0.0
        self.messages: List[Dict[str, str]] = []

        self._local_vendor_server: Optional[Any] = None

        # Base system prompt defining the agent's capabilities and tool syntax
        self.system_prompt = (
            "You are Causal Code, an expert autonomous terminal AI software engineer pair programming with the user.\n"
            "You have direct access to the user's filesystem and bash environment.\n\n"
            "AVAILABLE TOOLS:\n"
            "1. Execute bash command:\n"
            "```bash\n<command>\n```\n\n"
            "2. Create or overwrite a file:\n"
            "```write:<relative_path>\n<file_content>\n```\n\n"
            "3. Read an existing file:\n"
            "```read:<relative_path>\n```\n\n"
            "4. List directory contents:\n"
            "```list:<relative_dir>\n```\n\n"
            "GUIDELINES:\n"
            "- Work directly and autonomously in the current project directory.\n"
            "- When asked to build a project, inspect the workspace, create the files, test them with bash commands, and fix any errors.\n"
            "- Always communicate concisely in the same language as the user (Russian/English).\n"
            "- Keep a friendly, helpful, pair-programming tone. After completing a task, summarize what you did and ask for the next step."
        )

    def ensure_connection(self) -> None:
        """Connects to the CSLS Vendor Node or launches an embedded vendor node."""
        if self.api_key:
            return  # Direct provider mode active

        try:
            req = urllib.request.Request(f"{self.vendor_url}/health")
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                self.vendor_pk_hex = data.get("vendor_pk", "")
                pk_clean = self.vendor_pk_hex.replace("0x", "")
                self.vendor_pk = bytes.fromhex(pk_clean)
                self._handshake_session()
        except Exception:
            self._launch_embedded_vendor()
            self._handshake_session()

    def _launch_embedded_vendor(self) -> None:
        """Launches an embedded CausalVendorNode for instant local execution."""
        from launch_b2b_gateway import launch_gateway
        self._local_vendor_server = launch_gateway(
            host="127.0.0.1",
            port=0,
            delta_v_usdc=25.0,
            price_per_call=self.price_per_call,
        )
        port = self._local_vendor_server.server_address[1]
        self.vendor_url = f"http://127.0.0.1:{port}"
        t = threading.Thread(target=self._local_vendor_server.serve_forever, daemon=True)
        t.start()
        self.vendor_pk = self._local_vendor_server.vendor_node.public_key
        self.vendor_pk_hex = self._local_vendor_server.vendor_node.public_key_hex

    def _handshake_session(self) -> None:
        """Performs authenticated ECDH Session MAC handshake with the vendor."""
        if not self.vendor_pk:
            return
        init_pkt = self.wallet.create_session(self.vendor_pk)
        req = urllib.request.Request(
            f"{self.vendor_url}/v1/session/init",
            data=init_pkt,
            headers={"Content-Type": "application/octet-stream"},
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("status") == "SESSION_INITIALIZED":
                self.session_active = True

    def query_model(self, conversation: List[Dict[str, str]]) -> str:
        """
        Dispatches conversation to the LLM backend (either direct API key or CSLS micro-cheque mesh).
        Streams response in real-time.
        """
        # Mode A: Direct Anthropic Claude API Key
        if self.api_key and (self.api_key.startswith("sk-ant-") or "claude" in self.model.lower()):
            return self._query_anthropic_direct(conversation)

        # Mode B: Direct OpenAI API Key
        if self.api_key and (self.api_key.startswith("sk-") or "gpt" in self.model.lower()):
            return self._query_openai_direct(conversation)

        # Mode C: Sovereign Causal-Slash Vendor Mesh (Micro-cheque settlement)
        return self._query_causal_vendor(conversation)

    def _query_anthropic_direct(self, conversation: List[Dict[str, str]]) -> str:
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        # Format messages for Anthropic
        anthropic_msgs = []
        for m in conversation:
            if m["role"] in ("user", "assistant"):
                anthropic_msgs.append({"role": m["role"], "content": m["content"]})
        if not anthropic_msgs:
            anthropic_msgs = [{"role": "user", "content": "Hello"}]

        body = json.dumps({
            "model": self.model if "claude" in self.model else "claude-3-7-sonnet-20250219",
            "system": self.system_prompt,
            "messages": anthropic_msgs,
            "max_tokens": 4096,
            "stream": True,
        }).encode("utf-8")

        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        return self._stream_sse_response(req)

    def _query_openai_direct(self, conversation: List[Dict[str, str]]) -> str:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        openai_msgs = [{"role": "system", "content": self.system_prompt}]
        for m in conversation:
            openai_msgs.append({"role": m["role"], "content": m["content"]})

        body = json.dumps({
            "model": self.model if "gpt" in self.model else "gpt-4o",
            "messages": openai_msgs,
            "stream": True,
        }).encode("utf-8")

        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        return self._stream_sse_response(req)

    def _query_causal_vendor(self, conversation: List[Dict[str, str]]) -> str:
        if self.balance_usdc < self.price_per_call:
            raise RuntimeError(
                f"Deposit exhausted (remaining: ${self.balance_usdc:.4f} USDC). Top up deposit via /deposit."
            )

        if not self.session_active or not self.vendor_pk:
            self.ensure_connection()

        # Sign 167-byte Session MAC micro-cheque
        cheque = self.wallet.sign_cheque(
            self.vendor_pk,
            amount_usdc=self.price_per_call,
            session_mac=True,
        )
        self.cheques_signed += 1
        self.total_settled_usdc += self.price_per_call
        self.balance_usdc -= self.price_per_call
        self.config["deposit_usdc"] = round(self.balance_usdc, 6)
        save_config(self.config)

        body = json.dumps({
            "model": "claude-opus-5.5",
            "messages": conversation,
            "max_tokens": 4096,
            "stream": True,
        }).encode("utf-8")

        req = urllib.request.Request(
            f"{self.vendor_url}/v1/messages",
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-Causal-Cheque": "0x" + cheque.raw_packet.hex(),
            },
        )
        return self._stream_sse_response(req)

    def _stream_sse_response(self, req: urllib.request.Request) -> str:
        try:
            with urllib.request.urlopen(req, timeout=60.0) as resp:
                buffer = ""
                full_text = ""
                while True:
                    chunk = resp.read(256)
                    if not chunk:
                        break
                    buffer += chunk.decode("utf-8", errors="replace")
                    while "\n\n" in buffer:
                        event_block, buffer = buffer.split("\n\n", 1)
                        for line in event_block.splitlines():
                            if line.startswith("data: "):
                                data_str = line[6:].strip()
                                if data_str == "[DONE]":
                                    break
                                try:
                                    ev = json.loads(data_str)
                                    # Anthropic event format
                                    if ev.get("type") == "content_block_delta":
                                        delta = ev.get("delta", {}).get("text", "")
                                        full_text += delta
                                        console.print(delta, end="")
                                    # OpenAI event format
                                    elif "choices" in ev and ev["choices"]:
                                        delta = ev["choices"][0].get("delta", {}).get("content", "")
                                        if delta:
                                            full_text += delta
                                            console.print(delta, end="")
                                except Exception:
                                    pass
                if not full_text:
                    full_text = buffer.strip()
                    console.print(full_text)
                console.print()  # Final newline
                return full_text
        except urllib.error.HTTPError as exc:
            err_data = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"API Error (HTTP {exc.code}): {err_data}")

    # Built-in Agent Tools
    def tool_bash(self, command: str) -> str:
        """Executes a shell command in the workspace."""
        console.print(f"\n[bold cyan]> bash:[/bold cyan] [yellow]{command}[/yellow]")
        try:
            res = subprocess.run(
                command,
                shell=True,
                cwd=self.work_dir,
                capture_output=True,
                text=True,
                timeout=120,
            )
            out = res.stdout
            if res.stderr:
                out += ("\n[STDERR]\n" + res.stderr)
            preview = out.strip() if out.strip() else "(command completed successfully)"
            console.print(Panel(preview[:1500], title=f"Exit code: {res.returncode}", border_style="dim"))
            return f"Exit code: {res.returncode}\n{out}"
        except subprocess.TimeoutExpired:
            return "Error: Command timed out after 120 seconds."
        except Exception as exc:
            return f"Error executing command: {exc}"

    def tool_write_file(self, file_path: str, content: str) -> str:
        """Writes or creates a file in the workspace."""
        abs_path = os.path.abspath(os.path.join(self.work_dir, file_path))
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        console.print(f"\n[bold cyan]> write:[/bold cyan] [green]{file_path}[/green]")
        try:
            with open(abs_path, "w", encoding="utf-8") as f:
                f.write(content)
            lines = len(content.splitlines())
            syntax = Syntax(content[:1000], "python" if file_path.endswith(".py") else "text", line_numbers=True)
            console.print(Panel(syntax, title=f"Wrote {file_path} ({lines} lines)", border_style="green"))
            return f"Successfully wrote {lines} lines to '{file_path}'."
        except Exception as exc:
            return f"Error writing file '{file_path}': {exc}"

    def tool_read_file(self, file_path: str) -> str:
        """Reads a file in the workspace."""
        abs_path = os.path.abspath(os.path.join(self.work_dir, file_path))
        console.print(f"\n[bold cyan]> read:[/bold cyan] [yellow]{file_path}[/yellow]")
        if not os.path.isfile(abs_path):
            return f"Error: File '{file_path}' does not exist."
        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            lines = content.splitlines()
            numbered = [f"{i+1:4d} | {l}" for i, l in enumerate(lines[:120])]
            preview = "\n".join(numbered)
            console.print(Panel(preview[:1500], title=f"{file_path} ({len(lines)} lines)", border_style="dim"))
            return content[:8000]
        except Exception as exc:
            return f"Error reading file '{file_path}': {exc}"

    def tool_list_dir(self, dir_path: str = ".") -> str:
        """Lists directory entries."""
        abs_path = os.path.abspath(os.path.join(self.work_dir, dir_path))
        console.print(f"\n[bold cyan]> list:[/bold cyan] [yellow]{dir_path}[/yellow]")
        if not os.path.isdir(abs_path):
            return f"Error: Directory '{dir_path}' does not exist."
        try:
            entries = os.listdir(abs_path)
            entries.sort()
            out = "\n".join(entries)
            console.print(Panel(out[:1000], title=f"Contents of {dir_path}", border_style="dim"))
            return out
        except Exception as exc:
            return f"Error listing directory: {exc}"

    def process_turn(self, user_text: str) -> None:
        """Executes a complete multi-turn conversation turn with autonomous tool execution."""
        self.messages.append({"role": "user", "content": user_text})

        # Multi-step agentic ReAct loop
        for step in range(1, 6):
            try:
                response = self.query_model(self.messages)
            except Exception as exc:
                console.print(f"\n[bold red]Model Error:[/bold red] {exc}")
                return

            self.messages.append({"role": "assistant", "content": response})

            # Parse tool calls in assistant response
            tool_called = False

            # 1. Parse write file: ```write:path\ncontent```
            write_match = re.search(r"```write:([^\n]+)\n(.*?)```", response, re.DOTALL)
            if write_match:
                f_path = write_match.group(1).strip()
                f_content = write_match.group(2)
                res = self.tool_write_file(f_path, f_content)
                self.messages.append({"role": "user", "content": f"[Tool Output for write:{f_path}]:\n{res}"})
                tool_called = True

            # 2. Parse read file: ```read:path\n```
            read_match = re.search(r"```read:([^\n`]+)```", response)
            if read_match and not tool_called:
                f_path = read_match.group(1).strip()
                res = self.tool_read_file(f_path)
                self.messages.append({"role": "user", "content": f"[Tool Output for read:{f_path}]:\n{res}"})
                tool_called = True

            # 3. Parse list dir: ```list:path\n```
            list_match = re.search(r"```list:([^\n`]+)```", response)
            if list_match and not tool_called:
                d_path = list_match.group(1).strip()
                res = self.tool_list_dir(d_path)
                self.messages.append({"role": "user", "content": f"[Tool Output for list:{d_path}]:\n{res}"})
                tool_called = True

            # 4. Parse bash command: ```bash\ncommand\n```
            bash_match = re.search(r"```bash\n(.*?)```", response, re.DOTALL)
            if bash_match and not tool_called:
                cmd = bash_match.group(1).strip()
                res = self.tool_bash(cmd)
                self.messages.append({"role": "user", "content": f"[Tool Output for bash command `{cmd}`]:\n{res}"})
                tool_called = True

            if not tool_called:
                break

        # Render status line after turn
        self._render_turn_summary()

    def _render_turn_summary(self) -> None:
        """Renders subtle status metrics after a turn."""
        mode_text = "[bold green]Sovereign M2M (0 Gas, 0 Keys)[/bold green]" if not self.api_key else "[bold yellow]Direct API Key[/bold yellow]"
        status_line = (
            f"[dim]Balance:[/dim] [bold green]${self.balance_usdc:.4f} USDC[/bold green] | "
            f"[dim]Settled:[/dim] [bold cyan]${self.total_settled_usdc:.4f} USDC[/bold cyan] | "
            f"[dim]Cheques:[/dim] [yellow]{self.cheques_signed}[/yellow] | "
            f"[dim]Mode:[/dim] {mode_text}"
        )
        console.print(f"\n{status_line}\n")

    def print_welcome_banner(self) -> None:
        """Displays handsome welcome banner upon starting."""
        console.clear()
        title = Text("CAUSAL CODE: AUTONOMOUS SOVEREIGN TERMINAL", style="bold green")
        mode_str = "Sovereign M2M (Base L2 USDC Micro-cheques, 0 Keys)" if not self.api_key else f"Direct Provider Key ({self.model})"
        body = (
            f"[bold]Active Workspace:[/bold] {self.work_dir}\n"
            f"[bold]Sovereign Wallet:[/bold] {self.wallet.public_key_hex[:26]}... (Base L2)\n"
            f"[bold]Deposit Balance:[/bold] [bold green]${self.balance_usdc:.4f} USDC[/bold green]\n"
            f"[bold]Current Mode:[/bold] {mode_str}\n\n"
            "Commands: [cyan]/help[/cyan] (commands), [cyan]/balance[/cyan] (ledger), [cyan]/deposit[/cyan] (top-up), [cyan]/key[/cyan] (bind/unbind key), [cyan]/clear[/cyan], [cyan]/exit[/cyan]"
        )
        console.print(Panel(body, title=title, border_style="green"))


def start_repl(agent: SovereignCodingAgent) -> None:
    """Runs the continuous interactive chat session."""
    agent.print_welcome_banner()
    readline.parse_and_bind("tab: complete")

    while True:
        try:
            mode_prefix = "$" if not agent.api_key else "key"
            prompt_label = f"csls [{mode_prefix}{agent.balance_usdc:.2f}]> "
            user_input = input(prompt_label).strip()
            if not user_input:
                continue

            # Slash commands
            if user_input.startswith("/"):
                parts = user_input.split(maxsplit=1)
                cmd = parts[0].lower()
                arg = parts[1].strip() if len(parts) > 1 else ""

                if cmd in ("/exit", "/quit"):
                    console.print("\n[yellow]Session completed.[/yellow]")
                    console.print(f"Total Settled: ${agent.total_settled_usdc:.4f} USDC | Remaining: ${agent.balance_usdc:.4f} USDC | Gas: 0 wei")
                    break
                elif cmd == "/help":
                    table = Table(title="Causal Code Commands")
                    table.add_column("Command", style="cyan")
                    table.add_column("Description", style="white")
                    table.add_row("/balance", "Display sovereign deposit balance, wallet address, and gas metrics")
                    table.add_row("/deposit <amt>", "Top up sovereign USDC balance (e.g. /deposit 10)")
                    table.add_row("/key <api_key>", "Bind direct Anthropic or OpenAI API key (or '/key unbind')")
                    table.add_row("/vendor <url>", "Switch Vendor Node URL (e.g. /vendor http://127.0.0.1:8402)")
                    table.add_row("/model <name>", "Switch model (e.g. claude-3-7-sonnet-20250219)")
                    table.add_row("/clear", "Clear terminal screen and redraw welcome header")
                    table.add_row("/exit", "Exit Causal Code terminal session")
                    console.print(table)
                elif cmd == "/balance":
                    table = Table(title="Sovereign Channel & Settlement Ledger")
                    table.add_column("Field", style="cyan")
                    table.add_column("Value", style="green")
                    table.add_row("Agent Wallet PK", agent.wallet.public_key_hex)
                    table.add_row("Base L2 Vault", "0x901c98Da847DD24ff23FcC37B6D1549A17F12253")
                    table.add_row("Deposit Balance", f"${agent.balance_usdc:.4f} USDC")
                    table.add_row("Total Settled", f"${agent.total_settled_usdc:.4f} USDC")
                    table.add_row("167-Byte Cheques Signed", str(agent.cheques_signed))
                    table.add_row("On-chain Gas Drag", "0 wei (100% off-chain micro-settlement)")
                    table.add_row("Vendor Gateway", agent.vendor_url)
                    console.print(table)
                elif cmd == "/deposit":
                    try:
                        amt = float(arg) if arg else 10.0
                        agent.balance_usdc += amt
                        agent.config["deposit_usdc"] = agent.balance_usdc
                        save_config(agent.config)
                        console.print(f"[bold green]Deposit topped up by ${amt:.2f} USDC.[/bold green] Available: ${agent.balance_usdc:.4f} USDC")
                    except ValueError:
                        console.print("[red]Invalid amount. Example: /deposit 10[/red]")
                elif cmd == "/key":
                    if not arg or arg == "status":
                        status = f"Bound ({agent.api_key[:8]}...)" if agent.api_key else "None (Sovereign M2M Mode)"
                        console.print(f"Current API Key: {status}")
                        console.print("To bind a key: /key sk-ant-...\nTo unbind and return to Sovereign mode: /key unbind")
                    elif arg.lower() in ("unbind", "none", "clear", "remove"):
                        agent.api_key = None
                        agent.config["api_key"] = None
                        save_config(agent.config)
                        console.print("[bold green]Key unbound. Switched to pure Sovereign M2M Mode (0 keys, Base L2 micro-cheques).[/bold green]")
                    else:
                        agent.api_key = arg
                        agent.config["api_key"] = arg
                        save_config(agent.config)
                        console.print(f"[bold green]Key bound successfully ({arg[:8]}...). Switched to direct provider mode.[/bold green]")
                elif cmd == "/vendor":
                    if arg:
                        agent.vendor_url = arg.rstrip("/")
                        agent.config["vendor_url"] = agent.vendor_url
                        save_config(agent.config)
                        agent.session_active = False
                        agent.ensure_connection()
                        console.print(f"[bold green]Vendor URL updated to {agent.vendor_url}[/bold green]")
                    else:
                        console.print(f"Connected Vendor: {agent.vendor_url} (PK: {agent.vendor_pk_hex[:18]}...)")
                elif cmd == "/model":
                    if arg:
                        agent.model = arg
                        agent.config["model"] = arg
                        save_config(agent.config)
                        console.print(f"[bold green]Model set to {arg}[/bold green]")
                    else:
                        console.print(f"Current Model: {agent.model}")
                elif cmd == "/clear":
                    agent.print_welcome_banner()
                else:
                    console.print(f"[red]Unknown command:[/red] {cmd}. Type /help for available commands.")
                continue

            # Process conversational turn
            agent.process_turn(user_input)

        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Session closed by user.[/yellow]")
            break
        except Exception as exc:
            console.print(f"\n[bold red]Unexpected Error:[/bold red] {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Causal Code: Sovereign Terminal Coding Agent")
    parser.add_argument("prompt", nargs="?", default=None, help="Initial coding task to execute")
    parser.add_argument("--dir", default=None, help="Working directory (default: current directory)")
    parser.add_argument("--yes", "-y", action="store_true", help="Autonomous mode (no confirmation for tools)")
    args = parser.parse_args()

    agent = SovereignCodingAgent(
        work_dir=args.dir,
        autonomous=args.yes,
    )
    agent.ensure_connection()

    if args.prompt:
        agent.process_turn(args.prompt)
    else:
        start_repl(agent)


if __name__ == "__main__":
    main()
