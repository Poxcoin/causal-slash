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

export const streamTokenSettlementAction: Action = {
  name: "STREAM_TOKEN_SETTLEMENT",
  similes: [
    "STREAM_M2M_PAYMENT",
    "PAY_FOR_TOKENS",
    "SETTLE_REMOTE_COMPUTE",
    "EMIT_SESSION_CHEQUE"
  ],
  description:
    "Emit a zero-gas 167-byte Session MAC micro-cheque for real-time per-token compute streaming backed by Base L2 collateral vaults.",
  validate: async (runtime: IAgentRuntime, _message: Memory, _state?: State) => {
    const service = runtime.getService<CausalSettlementService>("causal_slash_settlement");
    return service !== undefined;
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
        callback({
          text: "[FAIL] CausalSettlementService is not initialized on the runtime."
        });
      }
      return false;
    }

    const vendorPk = options?.vendorPk || message.content?.vendorPk || "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const tokenCount = Number(options?.tokens || message.content?.tokens || 100);

    try {
      const receipt = service.streamTokenSettlement(vendorPk, tokenCount, true);

      const responseText =
        `[OK] Streamed ${tokenCount} tokens settled with 167-byte Session MAC micro-cheque.\n` +
        `- Cheque Height: ${receipt.chequeHeight}\n` +
        `- Incremental Amount: $${receipt.deltaUsdc.toFixed(6)} USDC\n` +
        `- Cumulative Channel Balance: $${receipt.cumulativeUsdc.toFixed(6)} USDC\n` +
        `- Blockchain Gas: ${receipt.gasSpent}\n` +
        `- Local Verification Latency: ${receipt.latencyMicroseconds.toFixed(2)} us\n` +
        `- Wire Cheque: ${receipt.wireChequeHex.slice(0, 34)}... (167 bytes)`;

      if (callback) {
        callback({
          text: responseText,
          receipt
        });
      }
      return true;
    } catch (err: any) {
      if (callback) {
        callback({
          text: `[FAIL] Stream settlement error: ${err.message}`
        });
      }
      return false;
    }
  },
  examples: [
    [
      {
        user: "{{user1}}",
        content: {
          text: "Stream micropayment for 250 LLM completion tokens to vendor node 0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        }
      },
      {
        user: "{{agentName}}",
        content: {
          text: "[OK] Emitted 167-byte Session MAC micro-cheque for 250 tokens at height 12 with $0.00 gas on Base L2.",
          action: "STREAM_TOKEN_SETTLEMENT"
        }
      }
    ]
  ]
};
