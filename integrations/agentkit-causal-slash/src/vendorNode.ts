// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers
//
// Sovereign vendor-side verification pipeline in TypeScript, mirroring
// csls_vendor_process_common() in src/causal_daemon.c with the exact check
// ordering (the ordering is a security property, Red Team P2):
//
//   1. Framing (magic/type)                       -> -10
//   2. C2 gate: session MAC (constant time)       -> -24
//   3. Equivocation trap BEFORE the exposure gate:
//      same height + differing challenge scalar   -> -20 (+ fraud proof)
//      same height + identical challenge scalar   -> -21 (exact replay)
//   4. Cumulative monotonicity                    -> -11
//   5. Unconfirmed exposure <= delta_v            -> -12
//   6. Height monotonicity                        -> -22
//   7. Challenge preimage recomputation           -> -23
//
// Cross-validated against the canonical C11 engine (test golden vectors are
// generated from src/causal_daemon.c).

import * as crypto from "crypto";
import {
  CSLS_MAGIC,
  CSLS_PKT_CHEQUE,
  CHEQUE_PACKET_SIZE,
  SESSION_MAC_SIZE,
  SESSION_INIT_PACKET_SIZE,
  CslsErrorCode,
  CslsChequePkt
} from "./types";
import {
  cslsMac128,
  verifyMacTag,
  recomputeChallengeScalar,
  extractPrivateKey,
  deriveCompressedPublicKey,
  vendorSessionKey
} from "./crypto";

export interface FraudProof {
  offenderPkHex: string;
  collisionHeight: bigint;
  extractedSkHex: string;
  cheque1: CslsChequePkt;
  cheque2: CslsChequePkt;
}

export interface VendorDecision {
  accepted: boolean;
  statusCode: number;
  height?: bigint;
  cumulativeAmt?: bigint;
  accumulatedMicro?: bigint;
  fraudProof?: FraudProof;
}

interface ChannelState {
  height: bigint;
  accumulated: bigint;
  cleared: bigint;
  // height -> recorded scalars (O(1) history ring in the C11 core)
  history: Map<bigint, { challengeE: Buffer; sigS: Buffer; cumulativeAmt: bigint; disputed: boolean }>;
}

// Ring capacity of the O(1) history table in the C11 engine (CSLS_HISTORY_SIZE)
const HISTORY_RING_SIZE = 65536;

export class CslsVendorNode {
  public readonly vendorPk: Buffer;
  public readonly vendorPkHex: string;
  private readonly sk32: Buffer;
  private readonly deltaVMicro: bigint;
  private readonly enforceMac: boolean;
  private readonly channels = new Map<string, ChannelState>();
  private readonly sessions = new Map<string, Buffer>(); // agentPkHex -> sessionKey

  constructor(opts: { sk32: Buffer; deltaVMicro?: bigint; enforceMac?: boolean }) {
    this.sk32 = opts.sk32;
    if (this.sk32.length !== 32) {
      throw new Error("[FAIL] Vendor secret key must be exactly 32 bytes");
    }
    this.deltaVMicro = opts.deltaVMicro ?? 1000000n; // $1.00 optimistic credit
    this.enforceMac = opts.enforceMac ?? true;
    this.vendorPk = deriveCompressedPublicKey(this.sk32);
    this.vendorPkHex = "0x" + this.vendorPk.toString("hex");
  }

  /**
   * csls_vendor_session_init: authenticate the agent's 95-byte SESSION_INIT
   * and arm the per-channel SipHash session key.
   */
  public sessionInit(packet95: Buffer): VendorDecision {
    if (packet95.length !== SESSION_INIT_PACKET_SIZE) {
      return { accepted: false, statusCode: CslsErrorCode.ERR_INVALID_PACKET };
    }
    if (packet95.readUInt32LE(0) !== CSLS_MAGIC || packet95[4] !== 0x05) {
      return { accepted: false, statusCode: CslsErrorCode.ERR_INVALID_PACKET };
    }
    const agentPk = packet95.subarray(5, 38);
    const vendorPk = packet95.subarray(38, 71);
    if (!vendorPk.equals(this.vendorPk)) {
      return { accepted: false, statusCode: CslsErrorCode.ERR_INVALID_PACKET };
    }
    const sessionNonce = packet95.readBigUInt64LE(71);
    const authMac = packet95.subarray(79, 95);

    const { expectedAuthMac, sessionKey } = vendorSessionKey(
      this.sk32,
      agentPk,
      this.vendorPk,
      sessionNonce
    );
    if (!verifyMacTag(expectedAuthMac, authMac)) {
      return { accepted: false, statusCode: CslsErrorCode.ERR_BAD_MAC };
    }
    this.sessions.set(agentPk.toString("hex"), sessionKey);
    return { accepted: true, statusCode: CslsErrorCode.OK };
  }

  /**
   * Process a full 167-byte Session MAC wire cheque.
   */
  public processWireCheque(wire167: Buffer): VendorDecision {
    if (wire167.length !== CHEQUE_PACKET_SIZE + SESSION_MAC_SIZE) {
      return { accepted: false, statusCode: CslsErrorCode.ERR_INVALID_PACKET };
    }
    return this.processCommon(
      parseChequePacket(wire167.subarray(0, CHEQUE_PACKET_SIZE)),
      wire167.subarray(CHEQUE_PACKET_SIZE)
    );
  }

  /**
   * csls_vendor_process_cheque_mac parity: packet and MAC transported apart.
   */
  public processChequeAndMac(pkt151: Buffer, mac16: Buffer): VendorDecision {
    return this.processCommon(parseChequePacket(pkt151), mac16);
  }

  /**
   * csls_vendor_advance_cleared: mark an on-chain settled slice as cleared,
   * releasing optimistic exposure headroom.
   */
  public advanceCleared(agentPkHex: string, amountMicro: bigint): boolean {
    const channel = this.channels.get(agentPkHex.replace(/^0x/, ""));
    if (!channel) return false;
    channel.cleared += amountMicro;
    if (channel.cleared > channel.accumulated) {
      channel.cleared = channel.accumulated;
    }
    return true;
  }

  private processCommon(pkt: CslsChequePkt, mac: Buffer): VendorDecision {
    // 1. Framing
    if (pkt.magic !== CSLS_MAGIC || pkt.type !== CSLS_PKT_CHEQUE) {
      return { accepted: false, statusCode: CslsErrorCode.ERR_INVALID_PACKET };
    }

    const agentPkHex = pkt.agentPk.toString("hex");
    const channel = this.channels.get(agentPkHex) ?? {
      height: 0n,
      accumulated: 0n,
      cleared: 0n,
      history: new Map()
    };

    // 2. C2 gate: session must exist and the MAC must verify in constant time.
    // Garbage-s packets from the wire die here without touching EC math.
    if (this.enforceMac) {
      const sessionKey = this.sessions.get(agentPkHex);
      if (!sessionKey) {
        this.channels.set(agentPkHex, channel);
        return { accepted: false, statusCode: CslsErrorCode.ERR_NO_SESSION };
      }
      const expected = cslsMac128(sessionKey, serialize151(pkt));
      if (!verifyMacTag(expected, mac)) {
        this.channels.set(agentPkHex, channel);
        return { accepted: false, statusCode: CslsErrorCode.ERR_BAD_MAC };
      }
    }

    // 3. Equivocation trap FIRST (before the exposure gate): a double-sign
    // hidden behind an oversized cheque must never evade detection.
    const prior = channel.history.get(pkt.height);
    if (prior) {
      if (!prior.challengeE.equals(pkt.challengeE)) {
        if (prior.disputed) {
          this.channels.set(agentPkHex, channel);
          return { accepted: false, statusCode: CslsErrorCode.ERR_FRAUD };
        }
        prior.disputed = true;
        const c1: CslsChequePkt = {
          magic: CSLS_MAGIC,
          type: CSLS_PKT_CHEQUE,
          agentPk: pkt.agentPk,
          vendorPk: this.vendorPk,
          height: pkt.height,
          cumulativeAmt: prior.cumulativeAmt,
          challengeE: prior.challengeE,
          sigS: prior.sigS
        };
        try {
          const extractedSk = extractPrivateKey(c1, pkt);
          const fraudProof: FraudProof = {
            offenderPkHex: "0x" + agentPkHex,
            collisionHeight: pkt.height,
            extractedSkHex: "0x" + extractedSk.toString("hex"),
            cheque1: c1,
            cheque2: pkt
          };
          this.channels.set(agentPkHex, channel);
          return { accepted: false, statusCode: CslsErrorCode.ERR_FRAUD, fraudProof };
        } catch {
          this.channels.set(agentPkHex, channel);
          return { accepted: false, statusCode: CslsErrorCode.ERR_FORGED_CHALLENGE };
        }
      }
      // Identical (agent, height, challenge): exact duplicate replay
      this.channels.set(agentPkHex, channel);
      return { accepted: false, statusCode: CslsErrorCode.ERR_REPLAY };
    }

    // 4. Cumulative monotonicity (Axiom 2)
    if (pkt.cumulativeAmt < channel.accumulated) {
      this.channels.set(agentPkHex, channel);
      return { accepted: false, statusCode: CslsErrorCode.ERR_DECREASING_AMOUNT };
    }

    // 5. Bounded optimistic exposure: unconfirmed credit hard-capped at delta_v
    const unconfirmed =
      pkt.cumulativeAmt >= channel.cleared ? pkt.cumulativeAmt - channel.cleared : 0n;
    if (unconfirmed > this.deltaVMicro) {
      this.channels.set(agentPkHex, channel);
      return { accepted: false, statusCode: CslsErrorCode.ERR_EXPOSURE_CAP };
    }

    // 6. Height monotonicity
    if (channel.height > 0n && pkt.height <= channel.height) {
      this.channels.set(agentPkHex, channel);
      return { accepted: false, statusCode: CslsErrorCode.ERR_OUT_OF_ORDER };
    }

    // 7. Challenge preimage recomputation
    const expectedE = recomputeChallengeScalar(pkt.agentPk, pkt.vendorPk, pkt.height, pkt.cumulativeAmt);
    if (!expectedE.equals(pkt.challengeE)) {
      this.channels.set(agentPkHex, channel);
      return { accepted: false, statusCode: CslsErrorCode.ERR_FORGED_CHALLENGE };
    }

    // Record state in the bounded history ring (mirrors CSLS_HISTORY_SIZE)
    channel.history.set(pkt.height, {
      challengeE: Buffer.from(pkt.challengeE),
      sigS: Buffer.from(pkt.sigS),
      cumulativeAmt: pkt.cumulativeAmt,
      disputed: false
    });
    if (channel.history.size > HISTORY_RING_SIZE) {
      const oldest = channel.history.keys().next().value;
      if (oldest !== undefined) channel.history.delete(oldest);
    }
    channel.height = pkt.height;
    channel.accumulated = pkt.cumulativeAmt;
    this.channels.set(agentPkHex, channel);

    return {
      accepted: true,
      statusCode: CslsErrorCode.OK,
      height: pkt.height,
      cumulativeAmt: pkt.cumulativeAmt,
      accumulatedMicro: channel.accumulated
    };
  }
}

/**
 * Parses a raw 151-byte cheque packet (framing validated by the caller).
 */
export function parseChequePacket(raw: Buffer): CslsChequePkt {
  if (raw.length !== CHEQUE_PACKET_SIZE) {
    throw new Error(`[FAIL] Cheque packet must be ${CHEQUE_PACKET_SIZE} bytes, got ${raw.length}`);
  }
  return {
    magic: raw.readUInt32LE(0),
    type: raw.readUInt8(4),
    agentPk: Buffer.from(raw.subarray(5, 38)),
    vendorPk: Buffer.from(raw.subarray(38, 71)),
    height: raw.readBigUInt64LE(71),
    cumulativeAmt: raw.readBigUInt64LE(79),
    challengeE: Buffer.from(raw.subarray(87, 119)),
    sigS: Buffer.from(raw.subarray(119, 151))
  };
}

/**
 * Re-serializes a parsed 151-byte cheque packet (canonical byte layout).
 */
export function serialize151(pkt: CslsChequePkt): Buffer {
  const buf = Buffer.alloc(CHEQUE_PACKET_SIZE);
  buf.writeUInt32LE(pkt.magic, 0);
  buf.writeUInt8(pkt.type, 4);
  pkt.agentPk.copy(buf, 5);
  pkt.vendorPk.copy(buf, 38);
  buf.writeBigUInt64LE(pkt.height, 71);
  buf.writeBigUInt64LE(pkt.cumulativeAmt, 79);
  pkt.challengeE.copy(buf, 87);
  pkt.sigS.copy(buf, 119);
  return buf;
}

// Re-export for vendor tooling that needs a random 32-byte node identity.
export function randomVendorSk(): Buffer {
  return crypto.randomBytes(32);
}
