// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

import {
  Action,
  IAgentRuntime,
  Memory,
  State,
  HandlerCallback
} from "../types";
import { CausalSettlementService } from "../services/causalService";

export const getChannelBalanceAction: Action = {
  name: "GET_CHANNEL_BALANCE",
  similes: [
    "CHECK_M2M_BALANCE",
    "INSPECT_CHANNEL_HEIGHT",
    "VIEW_VENDOR_SESSION",
    "GET_STREAM_METRICS"
  ],
  description:
    "Query the active micro-settlement channel height, cumulative volume, and credit window against a sovereign vendor node.",
  validate: async (runtime: IAgentRuntime, _message: Memory, _state?: State) => {
    return runtime.getService<CausalSettlementService>("causal_slash_settlement") !== undefined;
  },
  handler: async (
    runtime: IAgentRuntime,
    message: Memory,
    _state?: State,
    options?: any,
    callback?: HandlerCallback
  ): Promise<boolean> => {
    const service = runtime.getService<CausalSettlementService>("causal_slash_settlement");
    if (!service) {
      if (callback) {
        callback({ text: "[FAIL] CausalSettlementService not found." });
      }
      return false;
    }

    const vendorPk = options?.vendorPk || message.content?.vendorPk || "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const summary = service.getChannelSummary(vendorPk);

    if (!summary) {
      if (callback) {
        callback({
          text: `[INFO] No active session currently found for vendor ${vendorPk}. Ready to initialize session.`
        });
      }
      return true;
    }

    const text =
      `[OK] Channel State for Vendor ${summary.vendorPkHex.slice(0, 16)}...\n` +
      `- Monotonic Height: ${summary.height}\n` +
      `- Cumulative Micro-USDC: ${summary.cumulativeMicro}\n` +
      `- Total Settled Volume: $${summary.cumulativeUsdc} USDC\n` +
      `- Tokens Streamed: ${summary.tokensProcessed}\n` +
      `- Active: ${summary.active ? "YES" : "NO"}\n` +
      `- Settlement Channel: Base L2 Collateral Vault (${service.vaultAddress})`;

    if (callback) {
      callback({
        text,
        summary
      });
    }
    return true;
  },
  examples: [
    [
      {
        user: "{{user1}}",
        content: {
          text: "What is our current channel balance with vendor 0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798?"
        }
      },
      {
        user: "{{agentName}}",
        content: {
          text: "[OK] Monotonic Height: 48 | Settled: $0.002400 USDC | Tokens: 2,400 | Channel: Active on Base L2",
          action: "GET_CHANNEL_BALANCE"
        }
      }
    ]
  ]
};
