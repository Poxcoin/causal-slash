# CSLS PROTOCOL: COMPREHENSIVE AGENT ENFORCEMENT & ARCHITECTURAL INTEGRITY AUDIT
> Document Reference: `docs/agent-audit.md`  
> Principle: **DOCUMENTATION != ENFORCEMENT**  
> Focus: Forensic Analysis of Agent Rules, Hook Behaviors, Bypass Loops, and Minimal Hard Enforcement Architecture  
> Date: October 2026 Production Standard  

---

## 1. EXECUTIVE SUMMARY & AUDIT SCOPE

This audit evaluates the architectural gap between what is written in the project documentation (`AGENT_COORDINATION_BOARD.md`, `ARCHITECTURE_MANDATE.md`, `ROLE_MANDATE.md`, `SKILL.md`) and what is **physically and technically enforced** by the runtime environment (Antigravity CLI hooks, MCP configurations, shell parsers, and git gates).

### Key Findings
1. **90% of Architectural Rules Exist Only in Markdown:** Invariants such as "Zero Emojis", "Zero Client Web2 API Keys", "Zero SQLite", "Zero Localhost Daemons", "Language Constraints per Track", and "Pure Interactive TUI" rely 100% on model instruction-following. There is currently zero technical blocking mechanism preventing any agent from violating them.
2. **The "Browser Shield" Was Dead Code Due to Matcher Mismatch:** The global hook `hooks.json` only matched `"write_to_file|replace_file_content|run_command"`. It **never matched `call_mcp_tool`**, meaning all browser MCP tools (`playwright`, `puppeteer`, `chrome-devtools`) completely bypassed `strict_enforcer.py`.
3. **The `run_command` and MCP `fs` Super-Bypasses:** While `write_to_file` and `replace_file_content` had basic path and "read-before-edit" checks, an agent could bypass 100% of these checks in one step via `run_command` (e.g. `cat << 'EOF' > file`) or `call_mcp_tool` with `ServerName: "fs"`.
4. **The Stop-Hook Infinite Browser Loop:** The `Stop` hook in `strict_enforcer.py` blocked termination if git was dirty and tests had not run. When an agent was forced to continue (`decision: "continue"`), it looked at its available tools, saw Playwright/Puppeteer/DevTools, launched a browser to "verify" the site, generated new untracked artifacts, and was blocked again by the Stop hook on next exit—creating an infinite browser execution loop.
5. **Stale Path Matching in Existing Hooks:** Existing hooks referenced deprecated directory names (`causal-slash-site` instead of `csls_site`, `causal_term2_sdk` instead of `csls_terminal`), causing path checks to either fail silently or falsely block authorized workspaces.

---

## 2. INVENTORY OF EXISTING RULES & CURRENT ENFORCEMENT STATUS

| # | Rule / Invariant Description | Stated In | Current Technical Enforcement | Reality / Status |
| :--- | :--- | :--- | :--- | :--- |
| **R1** | **Zero Emojis** (Code, commits, docs, logs) | `AGENT_COORDINATION_BOARD.md`, `ARCHITECTURE_MANDATE.md` | **None** | **UNENFORCED.** No regex check in pre-commit, no check in pre-tool hook. |
| **R2** | **Zero Client Web2 API Keys** | `AGENT_COORDINATION_BOARD.md`, `user_strict_rules.yaml` | **None** | **UNENFORCED.** Hardcoded keys were previously committed in `upstream.go` without any gate blocking them. |
| **R3** | **Zero SQLite** (Pure atomic JSON with flock) | `AGENT_COORDINATION_BOARD.md` | **None** | **UNENFORCED.** Any agent can import `sqlite3` in Python or Go; zero gates block it. |
| **R4** | **Zero Localhost Daemons** for user client | `AGENT_COORDINATION_BOARD.md`, `user_strict_rules.yaml` | **None** | **UNENFORCED.** Rogue gateways previously spawned on port 8402 without technical intervention. |
| **R5** | **Pure Interactive TUI (`csls`)** (No CLI flags/pipes) | User Prompts, `ROLE_MANDATE.md` | **Partial** (`tools/verify_interactive_pty.py`) | **PARTIAL.** Tested in PTY suite, but NOT wired into git `pre-commit` or AGY hooks. |
| **R6** | **Language per Track** (Go in client, C11 core, Sol contracts) | `AGENT_COORDINATION_BOARD.md`, `ROLE_MANDATE.md` | **None** | **UNENFORCED.** Agents previously generated a Python CLI inside the Go client workspace. |
| **R7** | **Single-Writer Track Ownership** | `AGENT_COORDINATION_BOARD.md`, `ROLE_MANDATE.md` | **Broken** (`strict_enforcer.py`) | **BROKEN / BYPASSABLE.** Uses stale folder names (`causal_term2_sdk`). 100% bypassable via `run_command` and MCP `fs`. |
| **R8** | **Zero Browser Tools in Backend Tracks** | `strict_enforcer.py` (attempted) | **Dead Code** (`hooks.json` matcher bug) | **UNENFORCED.** `hooks.json` does not match `call_mcp_tool`. Browsers run via MCP or bash without restriction. |
| **R9** | **Read-Before-Edit** (Must `view_file` first) | `strict_enforcer.py` | **Partial** (checks transcript for edit tools) | **PARTIAL.** Enforced for `write_to_file` and `replace_file_content`, but bypassed via bash `run_command`. |
| **R10** | **Stop Gate** (Tests must run before stopping) | `strict_enforcer.py` (`handle_stop`) | **Partial** (`forge test`, `pytest`, `make test`) | **DANGEROUS.** Forces infinite continuation loops when dirty files exist. Missing `go test` check. |
| **R11** | **Pre-Commit Gate** (Zero stubs, 100% test pass) | `.git/hooks/pre-commit` | **Partial** (`forge test`, `make test`) | **PARTIAL.** Only tests Solidity and C11. Ignores Go tests, PTY suite, Python pytest, and npm build. |
| **R12** | **Axiom 1, 2, 4, 6** (Slashing math & contract invariants) | Contracts, `ARCHITECTURE_MANDATE.md` | **Enforced** (`forge test`, `make test`) | **ENFORCED IN CI/TESTS.** 100/100 Foundry tests & 5.5M C11 swarm gate pass mathematically. |

---

## 3. FORENSIC ANALYSIS: WHY HOOKS CAUSED CONTINUOUS BROWSER LAUNCHES

A deep forensic trace of previous conversations (e.g. `004d3ef5-3eb0-4374-b30b-4bca0f69fb12`) and hook configurations identified the exact chain of failure:

### Root Cause 1: The Matcher Flaw in `hooks.json`
In `/home/minus/.gemini/config/hooks.json`:
```json
"PreToolUse": [
  {
    "matcher": "write_to_file|replace_file_content|run_command",
    "hooks": [{ "command": ".../strict_enforcer.py" }]
  }
]
```
* **The Failure:** The matcher regex was explicitly restricted to `write_to_file`, `replace_file_content`, and `run_command`.
* **The Result:** When the agent called MCP tools (`call_mcp_tool` with `playwright`, `puppeteer`, or `chrome-devtools`), the AGY runtime **did not invoke `PreToolUse` at all**.
* The "BROWSER PARASITE SHIELD" written inside `strict_enforcer.py` (lines 15-21) was **never executed** for MCP tool calls!

### Root Cause 2: Stale Workspace Path Matching
In `strict_enforcer.py` line 16:
```python
if "causal-slash-site" not in current_ws:
    if name.startswith("browser_") or (name == "call_mcp_tool" and args.get("ServerName") in ("playwright", "puppeteer", "chrome-devtools")):
        return {"decision": "deny", ...}
```
* **The Failure:** On October 5, 2026, the frontend workspace was renamed from `causal-slash-site` to `csls_site`.
* **The Result:** Even if the matcher had fired, `current_ws` for `csls_site` did not contain `"causal-slash-site"`. The hook would have classified the legitimate frontend workspace as a backend workspace, while failing to detect worktrees properly.

### Root Cause 3: The Stop-Hook Feedback Loop
In `strict_enforcer.py` line 124:
```python
if not ran_test:
    return {
        "decision": "continue",
        "reason": "[STOP BLOCKED: CODE MODIFIED WITHOUT TEST RUN] You modified production code files but did not execute tests... Run verification before stopping!"
    }
```
* **The Failure:** When an agent modified frontend files (or untracked build artifacts remained in `csls_site/dist`), the agent attempted to finish. The `Stop` hook returned `"decision": "continue"`.
* **The Escalation:** The LLM, forced to continue and told to "verify before stopping", looked at its globally exposed tool palette. It saw Playwright and Puppeteer.
* **The Loop:** The agent launched a browser to verify `http://localhost:5173` or `kadoclub.net`, created temporary screenshots (`screenshot.png`), which kept git status dirty. The next stop attempt was blocked again, triggering another browser launch.

### Root Cause 4: Unrestricted Bash Scripting of Headless Browsers
When native MCP tools were delayed or failed, models resorted to `run_command` with inline scripts:
```bash
cat << 'EOF' > scrape.js
const puppeteer = require('puppeteer');
(async () => { const b = await puppeteer.launch(); ... })();
EOF
node scrape.js
```
`strict_enforcer.py` inspected only dangerous OS commands (`rm -rf /`, `mkfs`, `DROP TABLE`). It did not inspect `node`, `puppeteer`, `playwright`, or `chrome` execution inside `run_command`.

### Root Cause 5: External Plugin Flow Triggering Browser Auth
The SonarQube plugin (`/home/minus/.gemini/config/plugins/sonarqube/`) contains skills like `sonar-integrate` which instruct the agent:
> "Run `sonar auth login` once to authenticate (opens a browser; credentials stored in your system keychain)"
When agents invoked SonarQube skills, it physically spawned GUI browser windows on the user's desktop.

---

## 4. SKILLS & TOOLS EXPOSURE PER TRACK

### Current Reality: Global Exposure to All Agents
Currently, **every single agent in every single terminal receives 100% of all tools, MCP servers, and skills**:

```
[Agent in csls_blueteam] ──► Sees Playwright, Puppeteer, DevTools, FS, GitHub, SonarQube
[Agent in csls_terminal] ──► Sees Playwright, Puppeteer, DevTools, FS, GitHub, SonarQube
[Agent in csls_redteam]  ──► Sees Playwright, Puppeteer, DevTools, FS, GitHub, SonarQube
[Agent in Hub (main)]    ──► Sees Playwright, Puppeteer, DevTools, FS, GitHub, SonarQube
```

### Tool Exposure Matrix

| Capability / Tool Group | Hub (`main`) | Track 1 (`csls_blueteam`) | Track 2 (`csls_terminal`) | Track 3 (`csls_redteam`) | Track 4 (`csls_marketing`) | Track 5 (`csls_site`) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **File Read (`view_file`)** | Allowed | Allowed | Allowed | Allowed | Allowed | Allowed |
| **File Write / Edit (`write_to_file`, `replace_file_content`)** | Hub only | `src/*`, `Makefile`, `tests/c/*` | `client/*`, `tools/*` | `tests/*` | `integrations/*`, `docs/*` | `src/*`, `public/*`, configs |
| **Shell Command (`run_command`)** | Audited | Audited (C build/test) | Audited (Go build/test) | Audited (Forge test) | Audited (NPM/Python) | Audited (Vite/Wrangler) |
| **Browser MCP (`playwright`, `puppeteer`, `devtools`)** | **DENIED** | **DENIED** | **DENIED** | **DENIED** | **DENIED** | **ALLOWED (Restricted)** |
| **Filesystem MCP (`fs`)** | **DENIED** | **DENIED** | **DENIED** | **DENIED** | **DENIED** | **DENIED** |
| **Task / Process (`manage_task`, `schedule`)** | Allowed | Allowed | Allowed | Allowed | Allowed | Allowed |
| **Subagent Spawning (`invoke_subagent`, `define_subagent`)** | Allowed | **DENIED** | **DENIED** | **DENIED** | **DENIED** | **DENIED** |

---

## 5. SECURITY & INVARIANT VIOLATIONS INVENTORY

### 1. Ownership & Single-Writer Violations
* **Vulnerability:** Worktrees are physically located on the filesystem. Nothing prevents an agent in `csls_terminal` from running `echo "" > ../csls_blueteam/src/causal_daemon.c`.
* **Current Enforcement:** Stale check in `strict_enforcer.py` only checked `causal_term2_sdk`, which never matched active worktrees. `run_command` has zero path boundary enforcement.
* **Severity:** **CRITICAL**.

### 2. Language Violations
* **Vulnerability:** Track 2 is strictly Go Bubble Tea. Track 1 is strictly C11. An agent can introduce Python scripts or packages in Track 2 or C code in Track 4.
* **Current Enforcement:** None.
* **Severity:** **HIGH**.

### 3. API-Key Exposure
* **Vulnerability:** Agents writing code may embed API keys or bearer tokens (`sk-`, `gsk_`, `ghp_`) directly in source code.
* **Current Enforcement:** None. Hardcoded keys were previously found in `client/internal/agent/upstream.go`.
* **Severity:** **CRITICAL**.

### 4. SQLite / Localhost Daemon Violations
* **Vulnerability:** Agents often add SQLite dependencies or start background HTTP services (`python3 -m http.server 8000`, `scripts/launch_b2b_gateway.py --host 127.0.0.1`).
* **Current Enforcement:** None.
* **Severity:** **HIGH**.

### 5. Browser / Playwright Parasite
* **Vulnerability:** Background and core terminals launch browsers, consuming RAM, popping GUI windows on the user's displays, and entering infinite retry loops.
* **Current Enforcement:** Failed due to matcher mismatch in `hooks.json`.
* **Severity:** **CRITICAL**.

---

## 6. PROPOSED MINIMAL ENFORCEMENT ARCHITECTURE

### Core Architecture Paradigm:
```
agent ──► action request ──► PERMISSION CHECK (Hook) ──► ALLOW / DENY
```
**Deny-by-Default:** Any action, tool, language, or path not explicitly authorized for the active track is immediately and hard-blocked with an unambiguous diagnostic rejection.

```
                                 [ACTION REQUEST]
                                        │
                                        ▼
                         ┌─────────────────────────────┐
                         │   PreToolUse Hard Gate      │
                         │   (hooks.json: matcher "*") │
                         └──────────────┬──────────────┘
                                        │
                ┌───────────────────────┴───────────────────────┐
                ▼                                               ▼
     [TOOL RESTRICTIONS]                             [PATH & CONTENT AUDIT]
     • Is tool allowed for this Track?               • Is target inside Track boundary?
     • Is browser tool outside Track 5?              • Is language authorized for Track?
     • Is MCP "fs" invoked? (Blocked globally)       • Does content contain API keys / SQLite?
     • Is run_command spawning background daemons?   • Was file viewed before edit?
                │                                               │
                └───────────────────────┬───────────────────────┘
                                        │
                        ┌───────────────┴───────────────┐
                        ▼                               ▼
                 [VIOLATION DETECTED]           [PASSED ALL CHECKS]
                        │                               │
                        ▼                               ▼
               {"decision": "deny"}            {"decision": "allow"}
```

### Component 1: Role-Based Track Identification
The hook dynamically resolves the active track by inspecting `current_ws`:
```python
TRACK_RULES = {
    "Causal_Slash_Protocol": {
        "name": "Track 0: Hub / Orchestrator",
        "allowed_write_prefixes": [
            "/home/minus/Рабочий стол/Causal_Slash_Protocol/docs/",
            "/home/minus/Рабочий стол/Causal_Slash_Protocol/.agents/",
            "/home/minus/Рабочий стол/Causal_Slash_Protocol/Makefile",
            "/home/minus/Рабочий стол/Causal_Slash_Protocol/README.md",
            "/home/minus/Рабочий стол/Causal_Slash_Protocol/ROLE_MANDATE.md",
            "/home/minus/Рабочий стол/Causal_Slash_Protocol/.internal/"
        ],
        "allowed_languages": [".md", ".sh"],
        "allow_browser": False,
        "required_tests": ["forge test", "make test"]
    },
    "csls_blueteam": {
        "name": "Track 1: C11 Core",
        "allowed_write_prefixes": [
            "/home/minus/Рабочий стол/csls_blueteam/src/",
            "/home/minus/Рабочий стол/csls_blueteam/tests/c/",
            "/home/minus/Рабочий стол/csls_blueteam/Makefile"
        ],
        "allowed_languages": [".c", ".h", ".sh"],
        "allow_browser": False,
        "required_tests": ["make test"]
    },
    "csls_terminal": {
        "name": "Track 2: Go Interactive Terminal",
        "allowed_write_prefixes": [
            "/home/minus/Рабочий стол/csls_terminal/client/",
            "/home/minus/Рабочий стол/csls_terminal/tools/"
        ],
        "allowed_languages": [".go", ".mod", ".sum", ".py"],
        "allow_browser": False,
        "required_tests": ["go test", "verify_interactive_pty.py"]
    },
    "csls_redteam": {
        "name": "Track 3: Invariant & Adversarial Critic",
        "allowed_write_prefixes": [
            "/home/minus/Рабочий стол/csls_redteam/tests/",
            "/home/minus/Рабочий стол/csls_redteam/test/"
        ],
        "allowed_languages": [".sol", ".c", ".py"],
        "allow_browser": False,
        "required_tests": ["forge test"]
    },
    "csls_marketing": {
        "name": "Track 4: Ecosystem Integrations",
        "allowed_write_prefixes": [
            "/home/minus/Рабочий стол/csls_marketing/integrations/",
            "/home/minus/Рабочий стол/csls_marketing/docs/"
        ],
        "allowed_languages": [".ts", ".json", ".md"],
        "allow_browser": False,
        "required_tests": ["npm test"]
    },
    "csls_site": {
        "name": "Track 5: Frontend & Edge Gateway",
        "allowed_write_prefixes": [
            "/home/minus/Рабочий стол/csls_site/src/",
            "/home/minus/Рабочий стол/csls_site/public/",
            "/home/minus/Рабочий стол/csls_site/"
        ],
        "allowed_languages": [".ts", ".tsx", ".css", ".html", ".json", ".jsonc"],
        "allow_browser": True,
        "required_tests": ["npm run build"]
    }
}
```

### Component 2: PreToolUse Hard Interception
In `hooks.json`, change matcher to `"*"`. In `strict_enforcer.py`:
1. **MCP "fs" Server:** Permanently denied. Native `view_file`, `write_to_file`, `replace_file_content` must be used.
2. **Browser MCP Tools (`playwright`, `puppeteer`, `chrome-devtools`):** Hard-denied unless `track == "csls_site"`.
3. **Shell Command Inspection (`run_command`):**
   - Block execution of `puppeteer`, `playwright`, `chromium`, `google-chrome` in bash unless in `csls_site`.
   - Block background server spawning (`nohup`, `&`, `python3 -m http.server`, `python3 scripts/launch_b2b_gateway.py` without `--verify`).
   - Block shell redirection writing outside the active track (`> /path/to/other/track`).
   - Block destructive commands (`rm -rf /`, `git push --force`, `git reset --hard origin/main`).
4. **Content & Invariant Inspection on File Writes:**
   - Scan proposed code content for API key patterns: `sk-ant-`, `sk-or-v1-`, `gsk_`, `ghp_`, `0x[a-fA-F0-9]{64}` (private keys).
   - Scan proposed code content for `import sqlite3`, `sqlite3.h`, `database/sql/sqlite`.
   - Scan for unicode emojis: reject immediately with clear error.

### Component 3: Git Pre-Commit Hook Hardening
Update `.git/hooks/pre-commit` to act as an automated gate on every commit:
1. **Zero Emojis:** Check staged commit message and diff for emoji codepoints.
2. **Zero Secrets:** Run regex scan for API keys in staged files.
3. **Zero SQLite:** Check for sqlite imports.
4. **Zero Stubs:** Grep for `TODO.*implement`, `mock_dummy`, `fake_stub`.
5. **Comprehensive Test Suite:**
   - Run `forge test` (Solidity).
   - Run `make test` (C11).
   - Run `cd client && go test ./...` (Go client, if client modified).
   - Run `python3 tools/verify_interactive_pty.py` (PTY harness, if terminal modified).

### Component 4: Stop Hook Hardening
To prevent infinite continue loops:
- If git status is dirty, check if the required test command for the *specific active track* was run in the transcript.
- If not, return `"continue"` with the exact command to run (e.g. `Run 'forge test' to verify changes`).
- Set a maximum continuation limit: if the agent attempts to stop 3 times without modifying files further, terminate cleanly to prevent infinite loops.

---

## 7. INFRASTRUCTURE GAPS (PLATFORM LIMITATIONS)

Per user directive: *Do not invent workarounds for platform gaps; label them as GAP and report.*

| Gap ID | Platform Limitation | Technical Reason | Recommended Solution |
| :--- | :--- | :--- | :--- |
| **GAP-01** | **No Per-Workspace MCP Scoping in AGY** | AGY loads `~/.gemini/config/mcp_config.json` globally for all sessions. An MCP server cannot be enabled for one folder and disabled for another via config. | **Enforce via PreToolUse Hook:** The hook inspects `ServerName` in `call_mcp_tool` and `workspacePaths`. If `ServerName in ("playwright", "puppeteer")` and `workspacePaths != csls_site`, return `decision: "deny"`. |
| **GAP-02** | **No Native Subagent Tool Inheritance Control** | When `invoke_subagent` is called, subagents inherit parent tools unless explicitly redefined. A subagent could attempt browser calls. | **Enforce via PreToolUse Hook:** Hooks execute on all subagents as well because they share `hooks.json`. Deny-by-default catches subagent calls identically. |
| **GAP-03** | **Non-Git Frontend Directory (`csls_site`)** | `csls_site` is a standalone Desktop directory, not a git worktree. Git `pre-commit` hooks do not execute in `csls_site`. | **Enforce via PreToolUse Hook & Stop Hook:** Track 5 requires `npm run build` in the `Stop` hook before exit. |

---

## 8. SEVERITY CLASSIFICATION & PROPOSED ACTIONS

```
CRITICAL
────────
1. [File: ~/.gemini/config/hooks.json]
   Cause: Matcher regex excludes "call_mcp_tool", rendering browser shield completely dead.
   Fix: Expand matcher to "*" so PreToolUse evaluates all tool calls, including MCP and shell.

2. [File: ~/.gemini/config/hooks/strict_enforcer.py]
   Cause: Stale paths ("causal-slash-site", "causal_term2_sdk") break path containment; run_command has zero jurisdiction or browser checks.
   Fix: Update paths to active 5 tracks; add command line parser in run_command to block bash browser launches and cross-track writes.

3. [File: ~/.gemini/config/mcp_config.json]
   Cause: Browser MCP servers (playwright, puppeteer, chrome-devtools) and filesystem MCP (fs) are enabled globally for all agents.
   Fix: Disable "fs" MCP server; enforce strict track-5-only access for browsers via PreToolUse hook.

HIGH
────
4. [File: .git/hooks/pre-commit]
   Cause: Pre-commit hook only runs forge test and make test. Ignores Go tests, PTY harness, emojis, and API keys.
   Fix: Add checks for emojis, API keys, SQLite, and run Go test + PTY suite when client/ is modified.

5. [File: ~/.gemini/config/hooks/strict_enforcer.py - handle_stop]
   Cause: Stop hook triggers infinite loops when non-code files or untracked assets remain dirty.
   Fix: Scope dirty file check strictly to track source extensions; add iteration guard.

MEDIUM
──────
6. [File: ~/.gemini/antigravity-cli/rules/user_strict_rules.yaml]
   Cause: Contains stale directory names ("causal-slash-site") and does not list new tracks.
   Fix: Synchronize workspace list with canonical 5-worktree layout.

LOW
───
7. [File: ~/.gemini/config/plugins/sonarqube/skills/sonar-integrate/SKILL.md]
   Cause: Instructs browser-based login ("sonar auth login").
   Fix: Document that sonar auth should use non-interactive token flag.
```
