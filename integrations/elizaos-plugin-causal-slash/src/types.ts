// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

/**
 * Protocol Magic & Packet Sizes
 */
export const CSLS_MAGIC = 0x43534c53;
export const CSLS_PKT_CHEQUE = 0x01;
export const WIRE_CHEQUE_SIZE = 167;
export const CHEQUE_PACKET_SIZE = 151;
export const SESSION_MAC_SIZE = 16;
export const SECP256K1_Q = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

/**
 * Error Codes
 */
export enum CslsErrorCode {
  OK = 0,
  ERR_EXPOSURE_CAP = -12,
  ERR_FRAUD = -20,
  ERR_REPLAY = -21,
  ERR_OUT_OF_ORDER = -22,
  ERR_BAD_MAC = -24,
  ERR_NO_SESSION = -25,
  ERR_WAL_FATAL = -27
}

/**
 * ElizaOS Framework Interfaces (Type-Safe Native Compatibility)
 */
export interface IAgentRuntime {
  getSetting(key: string): string | undefined;
  getService<T>(serviceName: string): T | undefined;
  registerService(service: any): void;
}

export interface Memory {
  id?: string;
  userId?: string;
  agentId?: string;
  roomId?: string;
  content: {
    text: string;
    action?: string;
    [key: string]: any;
  };
}

export interface State {
  [key: string]: any;
}

export type HandlerCallback = (response: { text: string; [key: string]: any }) => void;

export interface ActionExample {
  user: string;
  content: {
    text: string;
    action?: string;
    [key: string]: any;
  };
}

export interface Action {
  name: string;
  similes?: string[];
  description: string;
  validate: (runtime: IAgentRuntime, message: Memory, state?: State) => Promise<boolean>;
  handler: (
    runtime: IAgentRuntime,
    message: Memory,
    state?: State,
    options?: any,
    callback?: HandlerCallback
  ) => Promise<boolean>;
  examples: ActionExample[][];
}

export interface Provider {
  get: (runtime: IAgentRuntime, message: Memory, state?: State) => Promise<string>;
}

export interface Plugin {
  name: string;
  description: string;
  actions: Action[];
  providers: Provider[];
  services: any[];
}

/**
 * Streaming Token Settlement Types
 */
export interface TokenMeteringRate {
  promptTokenMicroUsdc: number;     // e.g. 0.005 micro-USDC ($0.000005 per 1k prompt tokens)
  completionTokenMicroUsdc: number; // e.g. 0.020 micro-USDC ($0.000020 per 1k completion tokens)
}

export interface StreamSettlementSession {
  vendorPkHex: string;
  vendorEndpoint: string;
  // C2 gate key material: ecdh_x and session_key =
  // HMAC-SHA256(ecdh_x, nonce_BE(8) || "CSLS-MAC-v1") (C11 key schedule)
  ecdhX: Buffer;
  sessionNonce: bigint;
  sessionKey: Buffer;
  height: bigint;
  cumulativeMicro: bigint;
  tokensProcessed: number;
  creditWindowDeltaV: bigint;       // Max optimistic credit before ACK (e.g. 1,000,000 = $1.00 USDC)
  clearedMicro: bigint;             // Cumulative amount cleared on Base L2
  lastAckHeight: bigint;
  active: boolean;
}

export interface StreamTokenChequeReceipt {
  status: "settled" | "streaming";
  chequeHeight: string;
  tokensMetered: number;
  deltaUsdc: number;
  cumulativeUsdc: number;
  wireChequeHex: string;
  gasSpent: "0 wei";
  latencyMicroseconds: number;
}
