// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

import { z } from "zod";

/**
 * Protocol Magic & Constants
 */
export const CSLS_MAGIC = 0x43534c53; // "CSLS"
export const CSLS_PKT_CHEQUE = 0x01;
export const CSLS_PKT_SESSION_INIT = 0x05;
export const CSLS_PKT_WELCOME = 0x06;

export const CHEQUE_PACKET_SIZE = 151; // 151-byte zero-copy cheque
export const SESSION_MAC_SIZE = 16;    // 16-byte SipHash-2-4 / 128-bit MAC
export const WIRE_CHEQUE_SIZE = 167;   // 167-byte wire packet
export const SESSION_INIT_PACKET_SIZE = 95; // csls_session_init_pkt_t (C2 bootstrap)
export const WELCOME_PACKET_SIZE = 38; // csls_welcome_pkt_t (vendor identity)
export const ACK_PACKET_SIZE = 22;     // csls_ack_pkt_t

export const SECP256K1_Q = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

/**
 * Error Codes (negative returns matching C11 core)
 */
export enum CslsErrorCode {
  OK = 0,
  ERR_INVALID_PACKET = -10,
  ERR_DECREASING_AMOUNT = -11,
  ERR_EXPOSURE_CAP = -12,
  ERR_FRAUD = -20,
  ERR_REPLAY = -21,
  ERR_OUT_OF_ORDER = -22,
  ERR_FORGED_CHALLENGE = -23,
  ERR_BAD_MAC = -24,
  ERR_NO_SESSION = -25,
  ERR_WAL_FATAL = -27
}

/**
 * Human-readable status names for vendor decisions (parity with the C11 core)
 */
export function cslsStatusName(code: number): string {
  switch (code) {
    case CslsErrorCode.OK:
      return "OK";
    case CslsErrorCode.ERR_INVALID_PACKET:
      return "INVALID_PACKET";
    case CslsErrorCode.ERR_DECREASING_AMOUNT:
      return "DECREASING_AMOUNT_ATTACK";
    case CslsErrorCode.ERR_EXPOSURE_CAP:
      return "EXPOSURE_BUFFER_EXCEEDED";
    case CslsErrorCode.ERR_FRAUD:
      return "FRAUD_EQUIVOCATION_DETECTED";
    case CslsErrorCode.ERR_REPLAY:
      return "REPLAY_PACKET_IGNORED";
    case CslsErrorCode.ERR_OUT_OF_ORDER:
      return "OUT_OF_ORDER_OR_OLD_REPLAY";
    case CslsErrorCode.ERR_FORGED_CHALLENGE:
      return "FORGED_CHALLENGE_HASH";
    case CslsErrorCode.ERR_BAD_MAC:
      return "BAD_SESSION_MAC";
    case CslsErrorCode.ERR_NO_SESSION:
      return "NO_SESSION";
    default:
      return `STATUS_${code}`;
  }
}

/**
 * Binary Cheque Packet Structure (151 bytes in RAM, 167 bytes on Wire)
 */
export interface CslsChequePkt {
  magic: number;             // 4 bytes uint32 LE
  type: number;              // 1 byte uint8
  agentPk: Buffer;           // 33 bytes compressed secp256k1
  vendorPk: Buffer;          // 33 bytes compressed secp256k1
  height: bigint;            // 8 bytes uint64 LE monotonic sequence
  cumulativeAmt: bigint;     // 8 bytes uint64 LE micro-USDC (6 decimals)
  challengeE: Buffer;        // 32 bytes scalar e mod q
  sigS: Buffer;              // 32 bytes scalar s = (k + e * sk) mod q
}

export interface CslsChequeWire {
  pkt: CslsChequePkt;
  mac: Buffer;               // 16 bytes SipHash-2-4 tag
  rawPacket: Buffer;         // 167 bytes wire binary
  rawHex: string;            // 334 hex characters
  height: bigint;
  cumulativeUsdc: number;
}

/**
 * Action Parameter Schemas for Coinbase AgentKit
 */
export const CreateChannelSchema = z.object({
  vendorAddress: z.string().describe("Compressed secp256k1 public key (0x-hex, 66 chars) or Base L2 vendor address."),
  depositUsdc: z.number().positive().describe("USDC performance collateral allocated for this session in SwarmDelegationVault."),
  vendorEndpoint: z.string().url().optional().describe("HTTP endpoint URL for the sovereign vendor node gateway.")
});

export type CreateChannelParams = z.infer<typeof CreateChannelSchema>;

export const SignStreamChequeSchema = z.object({
  vendorAddress: z.string().describe("Target vendor compressed secp256k1 public key (0x-hex, 66 chars)."),
  amountUsdc: z.number().positive().describe("Incremental micro-payment in USDC (e.g. 0.0001 for 100 generated tokens)."),
  purpose: z.string().optional().describe("Metering label (e.g. llm.inference, vector.query, search.crawl).")
});

export type SignStreamChequeParams = z.infer<typeof SignStreamChequeSchema>;

export const InvokePaidInferenceSchema = z.object({
  vendorAddress: z.string().describe("Target vendor compressed secp256k1 public key (0x-hex, 66 chars)."),
  endpointUrl: z.string().url().describe("Payee service HTTP endpoint for micropayment delivery."),
  model: z.string().describe("Remote sovereign frontier model identifier (e.g. claude-opus-5.5, deepseek-v4-pro, gemini-4-argon)."),
  prompt: z.string().describe("Prompt text or query instructions for remote sovereign compute execution."),
  costUsdc: z.number().positive().default(0.0005).describe("Micro-payment settlement budget in USDC for this request."),
  maxTokens: z.number().int().positive().optional().describe("Maximum completion tokens requested from vendor.")
});

export type InvokePaidInferenceParams = z.infer<typeof InvokePaidInferenceSchema>;

export const InspectVaultBondSchema = z.object({
  vaultAddress: z.string().optional().describe("Base L2 PerformanceCollateralVault or SwarmDelegationVault address.")
});

export type InspectVaultBondParams = z.infer<typeof InspectVaultBondSchema>;

/**
 * Return Types
 */
export interface ActionExecutionResult<T = any> {
  success: boolean;
  action: string;
  data: T;
  error?: string;
  timestamp: string;
}

export interface ChannelSessionState {
  vendorPk: string;
  height: bigint;
  cumulativeSentMicro: bigint;
  cumulativeSentUsdc: number;
  // C2 gate: static-static ECDH x-coordinate and the derived session key
  // session_key = HMAC-SHA256(ecdh_x, nonce_BE(8) || "CSLS-MAC-v1")
  ecdhX: Buffer;
  sessionNonce: bigint;
  sessionKey: Buffer;
  // 95-byte SESSION_INIT packet that must reach the vendor before the first
  // 167-byte wire cheque
  sessionInitPacket: Buffer;
  sessionDelivered: boolean;
  vendorEndpoint?: string;
}

export interface InferenceExecutionResult {
  status: "settled";
  model: string;
  response: string;
  chequeHeight: string;
  cumulativeUsdc: string;
  gasSpentUsdc: string;
  chequeWireHex: string;
}
