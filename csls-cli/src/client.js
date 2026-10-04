// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

import { toolDefinitions } from "./tools.js";

export class SovereignModelClient {
  constructor(options = {}) {
    this.model = options.model || process.env.CSLS_MODEL || "qwen2.5-coder:14b";
    this.endpoint = options.endpoint || process.env.CSLS_ENDPOINT || "http://127.0.0.1:11434";
    this.gatewayUrl = options.gatewayUrl || process.env.CSLS_GATEWAY || "http://127.0.0.1:8402";
  }

  async checkReachability() {
    // Check local inference server or gateway
    try {
      const res = await fetch(`${this.endpoint}/v1/models`, { method: "GET", signal: AbortSignal.timeout(1500) });
      if (res.ok) return { reachable: true, type: "direct_inference", url: this.endpoint };
    } catch {}

    try {
      const res = await fetch(`${this.gatewayUrl}/health`, { method: "GET", signal: AbortSignal.timeout(1500) });
      if (res.ok) return { reachable: true, type: "csls_gateway", url: this.gatewayUrl };
    } catch {}

    return { reachable: false, error: "Neither inference endpoint nor CSLS gateway reachable" };
  }

  async streamCompletion(messages, cheque, onToken) {
    const payload = {
      model: this.model,
      messages,
      tools: toolDefinitions,
      stream: true,
    };

    const headers = {
      "Content-Type": "application/json",
      "X-Causal-Cheque": cheque.hex,
      "X-Causal-Gas": "0",
      "X-Causal-Session-Height": String(cheque.height),
    };

    let url = `${this.endpoint}/v1/chat/completions`;
    // If endpoint is not responsive, try gateway
    let response;
    try {
      response = await fetch(url, {
        method: "POST",
        headers,
        body: JSON.stringify(payload),
      });
    } catch (err) {
      url = `${this.gatewayUrl}/v1/chat/completions`;
      response = await fetch(url, {
        method: "POST",
        headers,
        body: JSON.stringify(payload),
      });
    }

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`Inference request failed (${response.status}): ${errText}`);
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder("utf-8");

    let buffer = "";
    let fullContent = "";
    let toolCalls = [];

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() || "";

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith(":") || trimmed === "data: [DONE]") continue;

        if (trimmed.startsWith("data: ")) {
          const jsonStr = trimmed.slice(6);
          try {
            const data = JSON.parse(jsonStr);
            const choice = data.choices?.[0];
            if (!choice) continue;

            const delta = choice.delta;
            if (delta?.content) {
              fullContent += delta.content;
              if (onToken) onToken(delta.content);
            }

            if (delta?.tool_calls) {
              for (const tc of delta.tool_calls) {
                const index = tc.index || 0;
                if (!toolCalls[index]) {
                  toolCalls[index] = {
                    id: tc.id || `call_${Date.now()}_${index}`,
                    type: "function",
                    function: { name: "", arguments: "" },
                  };
                }
                if (tc.function?.name) toolCalls[index].function.name += tc.function.name;
                if (tc.function?.arguments) toolCalls[index].function.arguments += tc.function.arguments;
              }
            }
          } catch {}
        }
      }
    }

    // Inspect if content contains embedded JSON tool calls (common in Qwen coder responses)
    if (toolCalls.length === 0 && fullContent.includes('"name"') && (fullContent.includes('"arguments"') || fullContent.includes('"parameters"'))) {
      const jsonBlocks = [];
      const lines = fullContent.split("\n");
      for (const rawLine of lines) {
        const line = rawLine.trim().replace(/^```json/, "").replace(/^```/, "").trim();
        if (line.startsWith("{") && line.endsWith("}")) {
          try {
            const parsed = JSON.parse(line);
            if (parsed.name && (parsed.arguments || parsed.parameters)) {
              jsonBlocks.push(parsed);
            }
          } catch {}
        }
      }

      if (jsonBlocks.length === 0) {
        // Try parsing whole content as JSON
        try {
          const parsed = JSON.parse(fullContent.trim());
          if (parsed.name && (parsed.arguments || parsed.parameters)) {
            jsonBlocks.push(parsed);
          }
        } catch {}
      }

      if (jsonBlocks.length > 0) {
        jsonBlocks.forEach((parsed, idx) => {
          toolCalls.push({
            id: `call_${Date.now()}_${idx}`,
            type: "function",
            function: {
              name: parsed.name,
              arguments: typeof parsed.arguments === "string" ? parsed.arguments : JSON.stringify(parsed.arguments || parsed.parameters),
            },
          });
        });
        fullContent = ""; // Consumed as tool calls
      }
    }

    return {
      role: "assistant",
      content: fullContent,
      tool_calls: toolCalls.length > 0 ? toolCalls : undefined,
    };
  }
}
