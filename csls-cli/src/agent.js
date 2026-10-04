// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

import { SovereignModelClient } from "./client.js";
import { executeTool } from "./tools.js";
import {
  printToolInvocation,
  printToolResult,
  printSettlementNotice,
  printError,
  colors,
} from "./ui.js";

export class CslsAgent {
  constructor(wallet, options = {}) {
    this.wallet = wallet;
    this.cwd = options.cwd || process.cwd();
    this.model = options.model || "qwen2.5-coder:14b";
    this.client = new SovereignModelClient({
      model: this.model,
      endpoint: options.endpoint,
      gatewayUrl: options.gatewayUrl,
    });
    this.history = [];
    this.initSystemPrompt();
  }

  initSystemPrompt() {
    this.systemPrompt = {
      role: "system",
      content: `You are CSLS, the sovereign autonomous coding agent powered by Causal-Slash Protocol.
Current workspace directory: ${this.cwd}
You have native tools to inspect, modify, and build real projects:
- bash: execute shell commands, run tests, install packages, check git status
- read_file: read full file contents or line ranges
- write_file: create or overwrite code files
- edit_file: precise string replace in existing files
- glob: search files matching patterns
- grep: search code for strings or regexes
- list_dir: view directory entries

Guidelines:
1. When asked to create, fix, refactor, or build projects, use your tools directly to inspect the code, write the files, run tests, and confirm success.
2. Be concise, direct, and pragmatic. Explain non-obvious design decisions.
3. Zero Web2 API keys or credit cards required: all compute settlement is funded autonomously via Base L2 collateral vault micro-cheques.
4. Do not output emojis.`,
    };
    this.history = [this.systemPrompt];
  }

  clearHistory() {
    this.initSystemPrompt();
  }

  async runTurn(userPrompt, onToken) {
    this.history.push({ role: "user", content: userPrompt });

    let turnCostTotal = 0;
    let turnHeight = 0;
    let maxIterations = 15;
    let iteration = 0;

    while (iteration < maxIterations) {
      iteration++;

      // Sign 167-byte Session MAC micro-cheque for this turn step
      const costPerStep = 0.000010;
      const cheque = this.wallet.generateSessionCheque(null, costPerStep);
      turnCostTotal += costPerStep;
      turnHeight = cheque.height;

      let assistantMessage;
      try {
        assistantMessage = await this.client.streamCompletion(
          this.history,
          cheque,
          onToken
        );
      } catch (err) {
        printError(err.message);
        break;
      }

      this.history.push(assistantMessage);

      // Check if model invoked any tools
      const toolCalls = assistantMessage.tool_calls;
      if (!toolCalls || toolCalls.length === 0) {
        // No further tool calls, turn completed!
        console.log("");
        break;
      }

      // Execute each tool call
      for (const tc of toolCalls) {
        const toolName = tc.function.name;
        let parsedArgs = {};
        try {
          parsedArgs = JSON.parse(tc.function.arguments);
        } catch {
          parsedArgs = { raw: tc.function.arguments };
        }

        printToolInvocation(toolName, parsedArgs);
        const result = await executeTool(toolName, parsedArgs, this.cwd);
        const isError = Boolean(result.error);
        printToolResult(toolName, result, isError);

        this.history.push({
          role: "tool",
          tool_call_id: tc.id,
          content: JSON.stringify(result),
        });
      }
    }

    const balance = this.wallet.getBalance();
    printSettlementNotice(turnCostTotal, balance.vaultDepositUsdc, turnHeight);
  }
}
