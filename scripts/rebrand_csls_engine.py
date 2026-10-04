#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers

import os
import re
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
        # Box titles and headers
        ('title:`Claude Code v', 'title:`CSLS Sovereign Terminal v'),
        ('Math.max(M-"Claude Code v".length,6)', 'Math.max(M-"CSLS v".length,6)'),
        ('l=` ${IA("claude",U)("Claude Code")} ${IA("inactive",U)(`v${y}`)} `,n=IA("claude",U)(" Claude Code ");',
         'l=` ${IA("claude",U)("CSLS Sovereign Terminal")} ${IA("inactive",U)(`v${y}`)} `,n=IA("claude",U)(" CSLS Sovereign Terminal ");'),
        ('eA.createElement(f,{bold:!0},"Claude Code")',
         'eA.createElement(f,{bold:!0},"CSLS Sovereign")'),
        # Model & Billing display
        ('w=Sb8(z),_=O7()?uT1():"API Usage Billing"',
         'w="Qwen 2.5 Coder 14B",_="Base L2 (0 Gas)"'),
        # Welcome message
        ('"Welcome to Claude Code"', '"Welcome to CSLS (Causal-Slash Protocol)"'),
        # System prompts
        ('W28="You are Claude Code, Anthropic\'s official CLI for Claude."',
         'W28="You are CSLS, the sovereign autonomous terminal coding agent for Causal-Slash Protocol on Base L2."'),
        ('Uk7="You are Claude Code, Anthropic\'s official CLI for Claude, running within the Claude Agent SDK."',
         'Uk7="You are CSLS, the sovereign autonomous terminal coding agent for Causal-Slash Protocol on Base L2."'),
        ('dk7="You are a Claude agent, built on Anthropic\'s Claude Agent SDK."',
         'dk7="You are CSLS, the autonomous coding agent powered by Causal-Slash Protocol."'),
        # Disable print mode (-p / --print) entirely
        ('I=$.print,', 'I=!1,'),
        ('.option("-p, --print","Print response and exit (useful for pipes). Note: The workspace trust dialog is skipped when Claude is run with the -p mode. Only use this flag in directories you trust.",()=>!0)', ''),
        # Disable marketplace auto-install notice
        ('function evq(){let A=K6(3),{addNotification:q}=Pq(),K=YE.useRef(!1),Y,z;if(A[0]!==q)Y=()=>{if(kq())return;if(K.current)return;',
         'function evq(){return;let A=K6(3),{addNotification:q}=Pq(),K=YE.useRef(!1),Y,z;if(A[0]!==q)Y=()=>{if(kq())return;if(K.current)return;'),
        # Disable Opus 4.6 notice
        ('BcY={id:"opus-4.6-available",type:"info",isActive:(A)=>A.showOpus46Notice===!0',
         'BcY={id:"opus-4.6-available",type:"info",isActive:(A)=>!1'),
        # Disable npm deprecation nag
        ('function ikq(){let A=K6(3),{addNotification:q}=Pq(),K=cL1.useRef(!1),Y,z;if(A[0]!==q)Y=()=>{if(kq())return;if(K.current||v9()||w1(process.env.DISABLE_INSTALLATION_CHECKS))return;',
         'function ikq(){return;let A=K6(3),{addNotification:q}=Pq(),K=cL1.useRef(!1),Y,z;if(A[0]!==q)Y=()=>{if(kq())return;if(K.current||v9()||w1(process.env.DISABLE_INSTALLATION_CHECKS))return;'),
        ('function rkq(){let A=K6(3),{addNotification:q}=Pq(),K=lL1.useRef(!1),Y,z;',
         'function rkq(){return;let A=K6(3),{addNotification:q}=Pq(),K=lL1.useRef(!1),Y,z;'),
        # Terminal window title
        ('function KY4(){Hg6("Claude Code")}',
         'function KY4(){Hg6("CSLS Sovereign Terminal")}'),
        # Tips
        ('text:"Run /init to create a CLAUDE.md file with instructions for Claude"',
         'text:"Run /init to create a CSLS.md file with instructions for CSLS"'),
        # Mascot animation stabilization
        ('marginBottom:Y', 'marginBottom:0'),
        ('X=D?9:5,M=v1()', 'X=D?9:7,M=v1()'),
        ('minHeight:D?13:9', 'minHeight:D?13:11'),
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
            print(f"Notice: replacement target already replaced or not found: {old[:40]}...")

    # CSLS Native 4-Layer Vector Glyph from PNG
    csls_glyph_v4 = '''function hb8(){return v4.createElement(b,{flexDirection:"column",alignItems:"center"},v4.createElement(f,{color:"claude"},"████████████"),v4.createElement(f,{color:"claude"}," ◥█         "),v4.createElement(f,{color:"claude"},"████████████"),v4.createElement(f,{color:"claude"},"            "),v4.createElement(f,{color:"claude"},"████████████"),v4.createElement(f,{color:"claude"},"          ██"),v4.createElement(f,{color:"claude"},"████████████"))}'''
    csls_glyph_ea = '''function KlY(){return eA.createElement(b,{flexDirection:"column",alignItems:"center"},eA.createElement(f,{color:"claude"},"████████████"),eA.createElement(f,{color:"claude"}," ◥█         "),eA.createElement(f,{color:"claude"},"████████████"),eA.createElement(f,{color:"claude"},"            "),eA.createElement(f,{color:"claude"},"████████████"),eA.createElement(f,{color:"claude"},"          ██"),eA.createElement(f,{color:"claude"},"████████████"))}'''

    content = re.sub(r"function hb8\(\)\{.+?return w\}", lambda m: csls_glyph_v4, content, count=1)
    content = re.sub(r"function ncY\(\)\{.+?return w\}", lambda m: csls_glyph_v4, content, count=1)
    content = re.sub(r"function KlY\(\)\{.+?return _\}", lambda m: csls_glyph_ea, content, count=1)

    with open(cli_path, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"Rebranding completed: {applied}/{len(replacements)} replacements applied to {cli_path}")

if __name__ == "__main__":
    main()
