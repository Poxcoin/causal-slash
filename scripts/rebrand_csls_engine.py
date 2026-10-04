#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers

import os
import sys

def main():
    cli_path = "/home/minus/.local/share/csls/engine/cli.js"
    if not os.path.exists(cli_path):
        print(f"Error: {cli_path} not found", file=sys.stderr)
        sys.exit(1)

    with open(cli_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Prepend default environment configuration
    env_header = """process.env.ANTHROPIC_BASE_URL = process.env.ANTHROPIC_BASE_URL || "http://127.0.0.1:8402";
process.env.ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || "csls_key_uwjBYsnRPkg-6mUjkwAA";
process.env.CLAUDE_CONFIG_DIR = process.env.CLAUDE_CONFIG_DIR || (process.env.HOME + "/.csls");
"""

    if "CSLS_ENV_INITIALIZED" not in content:
        lines = content.splitlines(True)
        if lines and lines[0].startswith("#!"):
            content = lines[0] + "// CSLS_ENV_INITIALIZED\n" + env_header + "".join(lines[1:])
        else:
            content = "// CSLS_ENV_INITIALIZED\n" + env_header + content

    replacements = [
        # CLI command & description
        ('q.name("claude").description("Claude Code - starts an interactive session by default, use -p/--print for non-interactive output")',
         'q.name("csls").description("CSLS - Causal-Slash Autonomous Frontier Terminal (0 Gas, Base L2, 167-B Session MAC)")'),
        # Version option
        ('(Claude Code)', '(CSLS Autonomous Frontier)'),
        ('VERSION:"2.1.50"', 'VERSION:"2.2.0"'),
        # Prompt box header
        ('title:`Claude Code v', 'title:`CSLS Sovereign Terminal v'),
        ('Math.max(M-"Claude Code v".length,6)', 'Math.max(M-"CSLS v".length,6)'),
        # Welcome message
        ('"Welcome to Claude Code"', '"Welcome to CSLS (Causal-Slash Protocol)"'),
        # System prompts
        ('W28="You are Claude Code, Anthropic\'s official CLI for Claude."',
         'W28="You are CSLS, the sovereign autonomous terminal coding agent for Causal-Slash Protocol on Base L2."'),
        ('Uk7="You are Claude Code, Anthropic\'s official CLI for Claude, running within the Claude Agent SDK."',
         'Uk7="You are CSLS, the sovereign autonomous terminal coding agent for Causal-Slash Protocol on Base L2."'),
        ('dk7="You are a Claude agent, built on Anthropic\'s Claude Agent SDK."',
         'dk7="You are CSLS, the autonomous coding agent powered by Causal-Slash Protocol."'),
        # Disable and remove print mode (-p / --print) entirely
        ('I=$.print,', 'I=!1,'),
        ('.option("-p, --print","Print response and exit (useful for pipes). Note: The workspace trust dialog is skipped when Claude is run with the -p mode. Only use this flag in directories you trust.",()=>!0)', ''),
        # URLs
        ('FEEDBACK_CHANNEL:"https://github.com/anthropics/claude-code/issues"',
         'FEEDBACK_CHANNEL:"https://github.com/Poxcoin/causal-slash/issues"'),
        ('PACKAGE_URL:"@anthropic-ai/claude-code"',
         'PACKAGE_URL:"@causal-slash/csls-terminal"'),
    ]

    applied = 0
    for old, new in replacements:
        if old in content:
            content = content.replace(old, new)
            applied += 1
            print(f"Applied replacement: {old[:40]}...")
        else:
            print(f"Notice: replacement target not found: {old[:40]}...")

    with open(cli_path, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"Rebranding completed: {applied}/{len(replacements)} replacements applied to {cli_path}")

if __name__ == "__main__":
    main()
