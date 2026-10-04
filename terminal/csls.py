#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
CSLS - sovereign terminal coding agent.

One persistent chat per project directory: the agent keeps its memory between
questions and between launches. Older history is compacted into a summary by the
model itself, so the conversation never silently falls out of the context window.

The model endpoint is any OpenAI-compatible server (CSLS_BASE_URL). Today that is a
local Ollama; later it is the Causal-Slash vendor gateway paid by session cheques.
"""

from __future__ import annotations

import json
import os
import platform
import re
import readline
import subprocess
import sys
import time
import urllib.error
import urllib.request

HOME = os.path.expanduser(os.environ.get("CSLS_HOME", "~/.csls"))
BASE_URL = os.environ.get("CSLS_BASE_URL", "http://127.0.0.1:11434/v1").rstrip("/")
MODEL = os.environ.get("CSLS_MODEL", "csls-coder")
CTX = int(os.environ.get("CSLS_CTX", "20480"))
MAX_TOOL_OUT = 6000
MAX_STEPS = 25

COLOR = sys.stdout.isatty()


def c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if COLOR else text


def dim(t: str) -> str:
    return c("2", t)


def bold(t: str) -> str:
    return c("1", t)


# --------------------------------------------------------------------------- tools

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a text file. Path is relative to the working directory.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Create or overwrite a file with the given content.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_dir",
            "description": "List the entries of a directory.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "bash",
            "description": "Run a shell command in the working directory and return its output.",
            "parameters": {
                "type": "object",
                "properties": {"command": {"type": "string"}},
                "required": ["command"],
            },
        },
    },
]

ALLOW_ALL = False


def clip(text: str, limit: int = MAX_TOOL_OUT) -> str:
    if len(text) <= limit:
        return text
    half = limit // 2
    return text[:half] + f"\n... [{len(text) - limit} chars cut] ...\n" + text[-half:]


def confirm(prompt: str) -> bool:
    global ALLOW_ALL
    if ALLOW_ALL:
        return True
    try:
        answer = input(c("33", f"{prompt} [y/n/a(lways)] ")).strip().lower()
    except EOFError:
        return False
    if answer in ("a", "always"):
        ALLOW_ALL = True
        return True
    return answer in ("y", "yes", "")


def run_tool(name: str, args: dict) -> str:
    try:
        if name == "read_file":
            with open(args["path"], "r", encoding="utf-8", errors="replace") as f:
                return clip(f.read())
        if name == "list_dir":
            path = args.get("path") or "."
            entries = sorted(os.listdir(path))
            return "\n".join(e + ("/" if os.path.isdir(os.path.join(path, e)) else "") for e in entries)
        if name == "write_file":
            path, content = args["path"], args["content"]
            print(dim(f"  write_file {path} ({len(content)} chars)"))
            if not confirm(f"Write {path}?"):
                return "DENIED by user"
            parent = os.path.dirname(os.path.abspath(path))
            os.makedirs(parent, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            return f"wrote {len(content)} chars to {path}"
        if name == "bash":
            cmd = args["command"]
            print(dim(f"  $ {cmd}"))
            if not confirm("Run this command?"):
                return "DENIED by user"
            proc = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=120, cwd=os.getcwd()
            )
            out = (proc.stdout or "") + (proc.stderr or "")
            return clip(out.strip() or "(no output)") + f"\n[exit {proc.returncode}]"
        return f"unknown tool: {name}"
    except subprocess.TimeoutExpired:
        return "command timed out after 120s"
    except Exception as exc:  # tool errors go back to the model, not to a crash
        return f"tool error: {exc}"


# ------------------------------------------------------------------------- memory


def project_key() -> str:
    return re.sub(r"[^a-zA-Z0-9]", "-", os.getcwd())


def session_dir() -> str:
    path = os.path.join(HOME, "chats", project_key())
    os.makedirs(path, exist_ok=True)
    return path


def session_file() -> str:
    return os.path.join(session_dir(), "session.jsonl")


def load_history() -> list[dict]:
    path = session_file()
    if not os.path.exists(path):
        return []
    msgs = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    msgs.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return msgs


def append_history(msgs: list[dict]) -> None:
    with open(session_file(), "a", encoding="utf-8") as f:
        for m in msgs:
            f.write(json.dumps(m, ensure_ascii=False) + "\n")


def rewrite_history(msgs: list[dict]) -> None:
    with open(session_file(), "w", encoding="utf-8") as f:
        for m in msgs:
            f.write(json.dumps(m, ensure_ascii=False) + "\n")


def archive_session() -> None:
    path = session_file()
    if os.path.exists(path) and os.path.getsize(path) > 0:
        os.rename(path, os.path.join(session_dir(), f"archive-{int(time.time())}.jsonl"))


def memory_notes() -> str:
    parts = []
    for label, path in (("Global memory", os.path.join(HOME, "CSLS.md")), ("Project memory", "CSLS.md")):
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                parts.append(f"## {label} ({path})\n{f.read().strip()}")
    return "\n\n".join(parts)


def system_prompt() -> str:
    base = (
        "You are CSLS, a terminal coding agent running in the user's shell.\n"
        f"Working directory: {os.getcwd()}\nPlatform: {platform.system()}\n"
        f"Date: {time.strftime('%Y-%m-%d')}\n"
        "Inspect files with tools before changing them. Keep answers short and concrete. "
        "You remember the whole conversation, including earlier summaries. "
        "Reply in the language the user writes in."
    )
    notes = memory_notes()
    return base + ("\n\n" + notes if notes else "")


def estimate_tokens(msgs: list[dict]) -> int:
    return len(json.dumps(msgs, ensure_ascii=False)) // 3


# ------------------------------------------------------------------------- model


def request(payload: dict):
    req = urllib.request.Request(
        f"{BASE_URL}/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    return urllib.request.urlopen(req, timeout=600)


def chat_stream(messages: list[dict]) -> tuple[str, list[dict]]:
    """Stream one assistant turn. Returns (text, tool_calls)."""
    payload = {
        "model": MODEL,
        "messages": [{"role": "system", "content": system_prompt()}] + messages,
        "tools": TOOLS,
        "stream": True,
    }
    text = ""
    calls: dict[int, dict] = {}
    with request(payload) as resp:
        for raw in resp:
            line = raw.decode("utf-8", errors="replace").strip()
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            try:
                delta = json.loads(data)["choices"][0].get("delta", {})
            except (json.JSONDecodeError, KeyError, IndexError):
                continue
            piece = delta.get("content")
            if piece:
                text += piece
                # a reply that starts with "{" is a tool call printed as text; do not show it raw
                if not text.lstrip().startswith("{"):
                    sys.stdout.write(piece)
                    sys.stdout.flush()
            for tc in delta.get("tool_calls") or []:
                slot = calls.setdefault(tc.get("index", len(calls)), {"id": "", "name": "", "args": ""})
                if tc.get("id"):
                    slot["id"] = tc["id"]
                fn = tc.get("function", {})
                if fn.get("name"):
                    slot["name"] += fn["name"]
                if fn.get("arguments"):
                    slot["args"] += fn["arguments"] if isinstance(fn["arguments"], str) else json.dumps(fn["arguments"])
    tool_calls = []
    for i, slot in sorted(calls.items()):
        tool_calls.append(
            {
                "id": slot["id"] or f"call_{int(time.time() * 1000)}_{i}",
                "type": "function",
                "function": {"name": slot["name"], "arguments": slot["args"] or "{}"},
            }
        )
    # Some models print the call as JSON text instead of using the tool channel.
    if not tool_calls and text.strip().startswith("{"):
        try:
            obj = json.loads(text.strip())
            if isinstance(obj, dict) and obj.get("name") in {t["function"]["name"] for t in TOOLS}:
                args = obj.get("arguments", obj.get("parameters", {}))
                tool_calls.append(
                    {
                        "id": f"call_{int(time.time() * 1000)}",
                        "type": "function",
                        "function": {"name": obj["name"], "arguments": json.dumps(args)},
                    }
                )
                text = ""
        except json.JSONDecodeError:
            pass
    return text, tool_calls


def summarize(old: list[dict]) -> str:
    transcript = clip(json.dumps(old, ensure_ascii=False), 24000)
    payload = {
        "model": MODEL,
        "stream": False,
        "messages": [
            {
                "role": "system",
                "content": "Write a compact memory note of this coding session for yourself: goals, decisions, "
                "files touched, facts the user told you, open tasks. No filler.",
            },
            {"role": "user", "content": transcript},
        ],
    }
    with request(payload) as resp:
        return json.loads(resp.read())["choices"][0]["message"]["content"].strip()


def compact_if_needed(history: list[dict]) -> list[dict]:
    budget = int(CTX * 0.6)
    if estimate_tokens(history) <= budget:
        return history
    keep_budget = int(CTX * 0.25)
    cut = None
    for i in range(len(history) - 1, 0, -1):
        if history[i].get("role") == "user" and estimate_tokens(history[i:]) > keep_budget:
            cut = i
            break
    if cut is None or cut < 2:
        return history
    # cut sits on a user message, so no tool call/result pair is split
    print(dim("  (compacting older conversation into memory...)"))
    try:
        note = summarize(history[:cut])
    except Exception as exc:
        print(dim(f"  (compaction failed: {exc})"))
        return history
    compacted = [{"role": "user", "content": "[Memory summary of the earlier conversation]\n" + note}] + history[cut:]
    with open(os.path.join(session_dir(), "compacted.jsonl"), "a", encoding="utf-8") as f:
        for m in history[:cut]:
            f.write(json.dumps(m, ensure_ascii=False) + "\n")
    rewrite_history(compacted)
    return compacted


# --------------------------------------------------------------------------- loop


def run_turn(history: list[dict], user_text: str) -> None:
    start = len(history)
    new = [{"role": "user", "content": user_text}]
    history.extend(new)
    committed = start
    try:
        for _ in range(MAX_STEPS):
            history[:] = compact_if_needed(history)
            committed = min(committed, len(history))
            text, calls = chat_stream(history)
            assistant: dict = {"role": "assistant", "content": text}
            if calls:
                assistant["tool_calls"] = calls
            step = [assistant]
            if text:
                print()
            for call in calls:
                fn = call["function"]
                try:
                    args = json.loads(fn["arguments"]) if fn["arguments"] else {}
                except json.JSONDecodeError:
                    args = {}
                result = run_tool(fn["name"], args if isinstance(args, dict) else {})
                step.append({"role": "tool", "tool_call_id": call["id"], "content": result})
            history.extend(step)
            if not calls:
                break
        append_history(history[committed:])
    except KeyboardInterrupt:
        del history[start:]
        print(dim("\n  (interrupted)"))
    except (urllib.error.URLError, OSError) as exc:
        del history[start:]
        print(c("31", f"\n  model endpoint error: {exc}"))
        print(dim(f"  endpoint: {BASE_URL}  model: {MODEL}"))


HELP = """/new      start a fresh chat (the old one is archived)
/memory   show the notes loaded from CSLS.md files
/history  show how many messages the agent remembers
/help     this help
/exit     leave (Ctrl-D also works)"""


def main() -> int:
    os.makedirs(HOME, exist_ok=True)
    hist_path = os.path.join(HOME, "input_history")
    try:
        readline.read_history_file(hist_path)
    except OSError:
        pass

    history = load_history()
    print(bold("csls") + dim(f"  {MODEL}  {os.getcwd()}"))
    if history:
        print(dim(f"  resumed chat: {len(history)} messages remembered. /new for a fresh one."))
    print()

    try:
        while True:
            try:
                line = input(c("36", "> "))
            except EOFError:
                print()
                break
            except KeyboardInterrupt:
                print()
                continue
            while line.endswith("\\"):
                line = line[:-1] + "\n" + input(c("36", ". "))
            line = line.strip()
            if not line:
                continue
            if line in ("/exit", "/quit"):
                break
            if line == "/help":
                print(HELP)
                continue
            if line == "/new":
                archive_session()
                history = []
                print(dim("  fresh chat started"))
                continue
            if line == "/history":
                print(dim(f"  {len(history)} messages, about {estimate_tokens(history)} tokens of {CTX}"))
                continue
            if line == "/memory":
                print(memory_notes() or dim("  no CSLS.md found (create one in the project or in ~/.csls)"))
                continue
            run_turn(history, line)
            print()
    finally:
        try:
            readline.write_history_file(hist_path)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
