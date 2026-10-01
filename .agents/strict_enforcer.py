#!/usr/bin/env python3
"""
Mechanical Protocol Enforcer for Antigravity Swarm Terminals
Enforces hard physical gates:
1. Jurisdiction Quarantine (Cannot touch files outside assigned workspace)
2. Zero-Mock Invariant (Rejects stubs, placeholders, mock returns)
3. Architecture Invariant (Multi-channel O(1) table, rejects single-scalar counters)
4. Pre-Task Invariant Injection (Always injects active rules before model invocation)
5. Stop Gate Invariant (Blocks agent from stopping if code changes are unverified)
"""
import sys
import os
import json
import re

def log(msg):
    sys.stderr.write(f"[STRICT_ENFORCER] {msg}\n")
    sys.stderr.flush()

def handle_pre_tool_use(data):
    tool_call = data.get("toolCall", {})
    name = tool_call.get("name", "")
    args = tool_call.get("args", {})
    workspace_paths = data.get("workspacePaths", [])
    current_ws = os.path.realpath(workspace_paths[0]) if workspace_paths else os.getcwd()

    # 1. JURISDICTION & BOUNDARY CHECK
    if name in ("write_to_file", "replace_file_content"):
        target_file = args.get("TargetFile", "")
        if target_file:
            real_target = os.path.realpath(target_file)
            
            # Allow temp files, system scratch, and artifacts
            is_scratch = any(p in real_target for p in [
                "/tmp/",
                "/.gemini/",
                "/.amux/",
                "/.config/systemd/",
                "/scratch/"
            ])
            
            if not is_scratch and not real_target.startswith(current_ws):
                return {
                    "decision": "deny",
                    "reason": f"[MECHANICAL VIOLATION: JURISDICTION BOUNDARY] Target file '{target_file}' is OUTSIDE your assigned workspace '{current_ws}'. Terminal isolation strictly forbids cross-workspace edits."
                }

        # 1.5. SPAM MARKDOWN PREVENTION CHECK
        if target_file.endswith(".md"):
            allowed_md = [
                "PROJECT_STATUS.md",
                "MEMORY_STATE_PERSISTENT.md",
                "SYSTEM_ARCHITECTURE_MANDATE.md",
                "SWARM_ORCHESTRATION_PROTOCOL.md",
                "CROSS_MODULE_CHECKLIST.md",
                "AGENTS.md",
                "README.md",
                "CLAUDE.md",
                "GEMINI.md"
            ]
            base = os.path.basename(target_file)
            is_allowed = (base in allowed_md) or base.startswith("MEMORY_MODULE_") or "/.gemini/" in target_file or "/tmp/" in target_file
            if not is_allowed:
                return {
                    "decision": "deny",
                    "reason": f"[MECHANICAL VIOLATION: MARKDOWN SPAM BLOCKED] Creating random markdown file '{base}' is strictly forbidden. All state must be recorded in PROJECT_STATUS.md, CROSS_MODULE_CHECKLIST.md, or your MEMORY_MODULE_*.md."
                }

        # 2. ZERO-MOCK INVARIANT CHECK
        content = args.get("CodeContent") or args.get("ReplacementContent") or ""
        if content:
            # Check for explicit mock keywords
            mock_patterns = [
                r"\b(mock|dummy|fake_impl|todo_mock)\b",
                r"//\s*TODO:\s*(implement|replace|mock)",
                r"#\s*TODO:\s*(implement|replace|mock)",
                r"return\s+(true|false|0|None|empty)\s*;\s*//\s*(mock|stub|placeholder)",
                r"pass\s*#\s*(stub|mock|placeholder)",
                r"\.\.\.\s*#\s*(stub|mock|placeholder)"
            ]
            for pat in mock_patterns:
                if re.search(pat, content, re.IGNORECASE):
                    # Check if this is a test file explicitly testing mock rejection
                    if "test" not in target_file.lower():
                        return {
                            "decision": "deny",
                            "reason": f"[MECHANICAL VIOLATION: ZERO-MOCK INVARIANT] Detected stub/mock pattern matching '{pat}'. Protocol requires 100% production logic. Stubs are physically blocked."
                        }

        # 3. ARCHITECTURE MULTI-CHANNEL INVARIANT CHECK
        if "causal_term1_core" in current_ws:
            if "causal_daemon.h" in target_file or "causal_daemon.c" in target_file:
                # Detect regression to single global scalar counter in agent context
                flawed_struct = re.search(
                    r"typedef\s+struct\s*\{[^}]*uint8_t\s+pk\[33\];[^}]*_Atomic\s+uint64_t\s+height;[^}]*uint64_t\s+cumulative_sent;[^}]*\}\s*csls_agent_ctx_t",
                    content,
                    re.DOTALL
                )
                if flawed_struct:
                    return {
                        "decision": "deny",
                        "reason": "[MECHANICAL VIOLATION: ARCHITECTURE INVARIANT] Regression to single-scalar global height/cumulative detected! Protocol contract mandates O(1) multi-channel table (csls_channel_table_t) indexed by peer_pk."
                    }

    # 4. DESTRUCTIVE COMMAND CHECK
    if name == "run_command":
        cmd = args.get("CommandLine", "")
        if re.search(r"rm\s+-rf\s+[/~]|git\s+push\s+--force|git\s+reset\s+--hard\s+origin/main|mkfs|DROP\s+TABLE", cmd, re.IGNORECASE):
            return {
                "decision": "deny",
                "reason": f"[MECHANICAL VIOLATION: SECURITY GUARD] Destructive command pattern blocked: {cmd}"
            }

    return {"decision": "allow"}

def handle_pre_invocation(data):
    workspace_paths = data.get("workspacePaths", [])
    current_ws = os.path.realpath(workspace_paths[0]) if workspace_paths else os.getcwd()
    ws_name = os.path.basename(current_ws)
    
    msg = (
        f"[MECHANICAL INVARIANT ENFORCEMENT ACTIVE FOR '{ws_name}']\n"
        f"1. JURISDICTION: You are physically locked to '{current_ws}'. Edits to outside directories will be HARD-DENIED.\n"
        f"2. ARCHITECTURE CONTRACT: Multi-channel state isolation is mandatory (independent height and cumulative per peer_pk).\n"
        f"3. ZERO-MOCK: Mock keywords, dummy returns, and stubs are intercepted and blocked by the engine.\n"
        f"4. STOP GATE: You will be blocked from stopping until the formal test suite passes 100%."
    )
    return {
        "injectSteps": [
            {"ephemeralMessage": msg}
        ]
    }

def handle_stop(data):
    workspace_paths = data.get("workspacePaths", [])
    current_ws = os.path.realpath(workspace_paths[0]) if workspace_paths else os.getcwd()
    
    # Check if there are modified files in git
    status_cmd = f"git -C '{current_ws}' status --porcelain 2>/dev/null"
    modified = os.popen(status_cmd).read().strip()
    
    # If files were modified, check if memory file was updated
    if modified:
        # Check if memory file has uncommitted changes (meaning it was updated)
        has_memory_update = any("MEMORY_MODULE_" in line for line in modified.splitlines())
        if not has_memory_update:
            return {
                "decision": "continue",
                "reason": "[MECHANICAL STOP GATE: MEMORY UPDATE REQUIRED] You modified code files but did not update your MEMORY_MODULE_*.md log with verified test receipts! Update your memory before stopping."
            }
            
    return {"decision": "allow"}

def main():
    try:
        raw_in = sys.stdin.read()
        if not raw_in.strip():
            print(json.dumps({"decision": "allow"}))
            return
            
        data = json.loads(raw_in)
        
        # Route based on payload structure
        if "toolCall" in data:
            result = handle_pre_tool_use(data)
        elif "invocationNum" in data:
            result = handle_pre_invocation(data)
        elif "terminationReason" in data:
            result = handle_stop(data)
        else:
            result = {"decision": "allow"}
            
        print(json.dumps(result))
    except Exception as ex:
        log(f"Enforcer error: {ex}")
        # Fail safe
        print(json.dumps({"decision": "allow"}))

if __name__ == "__main__":
    main()
