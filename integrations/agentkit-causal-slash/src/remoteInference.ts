// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

import * as http from "http";
import * as https from "https";
import { URL } from "url";
import { CslsChequeWire, InferenceExecutionResult } from "./types";

export interface RemoteInferenceRequestOptions {
  endpointUrl: string;
  vendorPkHex: string;
  wireCheque: CslsChequeWire;
  model: string;
  prompt: string;
  maxTokens?: number;
  subagentId?: string;
  timeoutMs?: number;
  // When set, token deltas are forwarded as they arrive (SSE streaming,
  // stream: true). Per-token settlement is metered by the vendor node.
  onToken?: (delta: string) => void;
}

/**
 * Delivers the 95-byte SESSION_INIT packet (C2 gate bootstrap) to the vendor
 * node over POST /v1/session. The vendor authenticates the ECDH-derived tag
 * and arms its 128-bit SipHash session key; only then are 167-byte wire
 * cheques accepted. Fail-fast: any transport error surfaces immediately.
 */
export function deliverSessionInit(endpointUrl: string, sessionInitPacket: Buffer, agentPkHex: string): Promise<void> {
  const url = new URL(endpointUrl);
  const client = url.protocol === "https:" ? https : http;
  const sessionUrl = new URL("/v1/session", url.origin);

  return new Promise<void>((resolve, reject) => {
    const req = client.request(
      sessionUrl,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/octet-stream",
          "Content-Length": sessionInitPacket.length,
          "X-Causal-Agent-Pk": agentPkHex,
          "User-Agent": "CausalSlash-AgentKit/1.0.0 (Base L2 Sovereign M2M)"
        },
        timeout: 10000
      },
      (res) => {
        res.resume();
        res.on("end", () => {
          if ((res.statusCode ?? 500) >= 400) {
            reject(
              new Error(
                `[FAIL] Vendor rejected Session MAC bootstrap (HTTP ${res.statusCode})`
              )
            );
          } else {
            resolve();
          }
        });
      }
    );

    req.on("timeout", () => {
      req.destroy();
      reject(new Error("[FAIL] Session bootstrap to sovereign vendor node timed out"));
    });

    req.on("error", (err) => {
      reject(new Error(`[FAIL] Connection error during session bootstrap: ${err.message}`));
    });

    req.write(sessionInitPacket);
    req.end();
  });
}

/**
 * Invokes remote sovereign frontier compute without Web2 API keys.
 * Authenticates exclusively via 167-byte Session MAC micro-cheques
 * deposited in HTTP header X-Causal-Cheque. There is no local model and no
 * offline fallback: an unreachable vendor fails fast with a clean error.
 */
export async function executeRemoteSovereignInference(
  options: RemoteInferenceRequestOptions
): Promise<InferenceExecutionResult> {
  const url = new URL(options.endpointUrl);
  const isHttps = url.protocol === "https:";
  const client = isHttps ? https : http;
  const streaming = typeof options.onToken === "function";

  const payload = JSON.stringify({
    model: options.model,
    messages: [
      {
        role: "user",
        content: options.prompt
      }
    ],
    max_tokens: options.maxTokens || 1024,
    stream: streaming
  });

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload).toString(),
    "X-Causal-Cheque": options.wireCheque.rawHex.replace(/^0x/, ""),
    "X-Causal-Slash-Vendor-Pk": options.vendorPkHex,
    "User-Agent": "CausalSlash-AgentKit/1.0.0 (Base L2 Sovereign M2M)"
  };
  if (streaming) {
    headers["Accept"] = "text/event-stream";
  }

  if (options.subagentId) {
    headers["X-Causal-Subagent-Id"] = options.subagentId;
  }

  return new Promise<InferenceExecutionResult>((resolve, reject) => {
    const req = client.request(
      url,
      {
        method: "POST",
        headers,
        timeout: options.timeoutMs || 30000
      },
      (res) => {
        const statusCode = res.statusCode || 500;
        if (statusCode >= 400) {
          // Fail fast on cheques rejected by the vendor gate (bad MAC,
          // replay, exposure cap) and on any upstream vendor error.
          let errorBody = "";
          res.on("data", (chunk) => { errorBody += chunk.toString("utf8"); });
          res.on("end", () =>
            reject(
              new Error(
                `[FAIL] Vendor Node Rejected Cheque Or Request (HTTP ${statusCode}): ${errorBody.slice(0, 256)}`
              )
            )
          );
          return;
        }

        if (streaming && (res.headers["content-type"] ?? "").includes("text/event-stream")) {
          // Server-sent events: data: {"choices":[{"delta":{"content":"..."}}]}
          let content = "";
          let settledUsdc = "";
          let sse = "";
          res.on("data", (chunk) => {
            sse += chunk.toString("utf8");
            let sep: number;
            while ((sep = sse.indexOf("\n\n")) >= 0) {
              const frame = sse.slice(0, sep);
              sse = sse.slice(sep + 2);
              for (const line of frame.split("\n")) {
                if (!line.startsWith("data:")) continue;
                const data = line.slice(5).trim();
                if (data === "[DONE]") continue;
                try {
                  const evt = JSON.parse(data);
                  const delta = evt.choices?.[0]?.delta?.content;
                  if (typeof delta === "string" && delta.length > 0) {
                    content += delta;
                    options.onToken?.(delta);
                  }
                } catch {
                  reject(new Error("[FAIL] Vendor sent malformed SSE payload"));
                  req.destroy();
                  return;
                }
              }
            }
          });
          res.on("end", () => {
            resolve({
              status: "settled",
              model: options.model,
              response: content,
              chequeHeight: (res.headers["x-causal-slash-cheque-height"] as string) || options.wireCheque.height.toString(),
              cumulativeUsdc:
                (res.headers["x-causal-slash-settled-usdc"] as string) ||
                options.wireCheque.cumulativeUsdc.toFixed(6) ||
                settledUsdc,
              gasSpentUsdc: (res.headers["x-causal-gas"] as string) || "0",
              chequeWireHex: options.wireCheque.rawHex
            });
          });
          return;
        }

        let responseBody = "";
        res.on("data", (chunk) => {
          responseBody += chunk.toString("utf8");
        });

        res.on("end", () => {
          // Extract sovereign settlement receipt headers
          const chequeHeight = (res.headers["x-causal-slash-cheque-height"] as string) || options.wireCheque.height.toString();
          const settledUsdc = (res.headers["x-causal-slash-settled-usdc"] as string) || options.wireCheque.cumulativeUsdc.toFixed(6);
          const gasSpent = (res.headers["x-causal-gas"] as string) || "0";

          let outputText = responseBody;
          try {
            const parsed = JSON.parse(responseBody);
            if (parsed.choices && parsed.choices[0]?.message?.content) {
              outputText = parsed.choices[0].message.content;
            } else if (parsed.content && Array.isArray(parsed.content)) {
              outputText = parsed.content.map((b: any) => b.text || "").join("");
            } else if (parsed.response) {
              outputText = parsed.response;
            }
          } catch {
            // Keep raw text if not JSON
          }

          resolve({
            status: "settled",
            model: options.model,
            response: outputText,
            chequeHeight,
            cumulativeUsdc: settledUsdc,
            gasSpentUsdc: gasSpent,
            chequeWireHex: options.wireCheque.rawHex
          });
        });
      }
    );

    req.on("timeout", () => {
      req.destroy();
      reject(new Error("[FAIL] Request to sovereign vendor node timed out"));
    });

    req.on("error", (err) => {
      reject(new Error(`[FAIL] Connection error to sovereign vendor node: ${err.message}`));
    });

    req.write(payload);
    req.end();
  });
}
