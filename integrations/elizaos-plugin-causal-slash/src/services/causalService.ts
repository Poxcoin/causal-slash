// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

import * as crypto from "crypto";
import {
  CSLS_MAGIC,
  CSLS_PKT_CHEQUE,
  WIRE_CHEQUE_SIZE,
  CHEQUE_PACKET_SIZE,
  SESSION_MAC_SIZE,
  SECP256K1_Q,
  StreamSettlementSession,
  StreamTokenChequeReceipt,
  TokenMeteringRate
} from "../types";

const MASK64 = 0xffffffffffffffffn;

function rotl64(x: bigint, b: bigint): bigint {
  return (((x << b) & MASK64) | (x >> (64n - b))) & MASK64;
}

function sipround(v: [bigint, bigint, bigint, bigint]): void {
  v[0] = (v[0] + v[1]) & MASK64;
  v[1] = rotl64(v[1], 13n) ^ v[0];
  v[0] = rotl64(v[0], 32n);

  v[2] = (v[2] + v[3]) & MASK64;
  v[3] = rotl64(v[3], 16n) ^ v[2];

  v[0] = (v[0] + v[3]) & MASK64;
  v[3] = rotl64(v[3], 21n) ^ v[0];

  v[2] = (v[2] + v[1]) & MASK64;
  v[1] = rotl64(v[1], 17n) ^ v[2];
  v[2] = rotl64(v[2], 32n);
}

function siphash24(keyBuf: Buffer, msgBuf: Buffer, finXor = 0n): bigint {
  const k0 = keyBuf.readBigUInt64LE(0);
  const k1 = keyBuf.readBigUInt64LE(8);

  const v: [bigint, bigint, bigint, bigint] = [
    0x736f6d6570736575n ^ k0,
    0x646f72616e646f6dn ^ k1,
    0x6c7967656e657261n ^ k0,
    0x7465646279746573n ^ k1 ^ finXor
  ];

  const full = msgBuf.length & ~7;
  for (let off = 0; off < full; off += 8) {
    const b = msgBuf.readBigUInt64LE(off);
    v[3] ^= b;
    sipround(v);
    sipround(v);
    v[0] ^= b;
  }

  let b = BigInt(msgBuf.length & 7) << 56n;
  const rem = msgBuf.length & 7;
  for (let i = 0; i < rem; i++) {
    b |= BigInt(msgBuf[full + i]) << BigInt(8 * i);
  }

  v[3] ^= b;
  sipround(v);
  sipround(v);
  v[0] ^= b;

  v[2] ^= 0xffn;
  sipround(v);
  sipround(v);
  sipround(v);
  sipround(v);

  return (v[0] ^ v[1] ^ v[2] ^ v[3]) & MASK64;
}

function cslsMac128(keyBuf: Buffer, dataBuf: Buffer): Buffer {
  const k16 = keyBuf.subarray(0, 16);
  const a = siphash24(k16, dataBuf, 0n);
  const b = siphash24(k16, dataBuf, 0xEen);

  const out = Buffer.alloc(SESSION_MAC_SIZE);
  out.writeBigUInt64LE(a, 0);
  out.writeBigUInt64LE(b, 8);
  return out;
}

/**
 * Sovereign Settlement Service for ElizaOS Agents
 * Backed by Base L2 collateral vaults (PerformanceCollateralVault / SwarmDelegationVault)
 */
export class CausalSettlementService {
  public static serviceType = "causal_slash_settlement";

  public readonly agentSk: Buffer;
  public readonly agentPk: Buffer;
  public readonly agentPkHex: string;
  public readonly vaultAddress: string;

  private sessions = new Map<string, StreamSettlementSession>();
  private defaultRates: TokenMeteringRate = {
    promptTokenMicroUsdc: 2,     // 2 micro-USDC ($0.000002) per token
    completionTokenMicroUsdc: 10 // 10 micro-USDC ($0.000010) per token
  };

  // Local ledger of cheques SIGNED by this agent (not a vault mirror; live
  // bond state must be read from Base L2 over RPC, see docs/research).
  public totalClearedUsdc = 0.0;

  constructor(privateKeyHex?: string, vaultAddress?: string) {
    if (privateKeyHex) {
      this.agentSk = Buffer.from(privateKeyHex.replace(/^0x/, ""), "hex");
    } else {
      this.agentSk = crypto.randomBytes(32);
    }

    const ecdh = crypto.createECDH("secp256k1");
    ecdh.setPrivateKey(this.agentSk);
    this.agentPk = ecdh.getPublicKey(null, "compressed");
    this.agentPkHex = "0x" + this.agentPk.toString("hex");

    this.vaultAddress = vaultAddress || "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";
  }

  /**
   * Initializes or gets an active streaming session with a sovereign vendor node
   */
  public getOrCreateSession(
    vendorPkHex: string,
    vendorEndpoint = ""
  ): StreamSettlementSession {
    const cleanPk = "0x" + vendorPkHex.replace(/^0x/, "");
    let session = this.sessions.get(cleanPk);

    if (!session) {
      const vendorPkBuf = Buffer.from(cleanPk.replace(/^0x/, ""), "hex");
      // C2 gate key schedule, bit-exact with the C11 core:
      //   ecdh_x      = static-static secp256k1 ECDH x-coordinate (32 B, padded)
      //   session_key = HMAC-SHA256(ecdh_x, nonce_BE(8) || "CSLS-MAC-v1")
      // A raw ECDH x-coordinate is NOT a valid session key: MAC-mandating
      // vendors reject cheques signed with it (-24).
      const ecdh = crypto.createECDH("secp256k1");
      ecdh.setPrivateKey(this.agentSk);
      const secret = ecdh.computeSecret(vendorPkBuf);
      const ecdhX = secret.length === 32 ? Buffer.from(secret) : Buffer.concat([Buffer.alloc(32 - secret.length), secret]);
      const sessionNonce = BigInt("0x" + crypto.randomBytes(8).toString("hex"));
      const sessionKey = crypto
        .createHmac("sha256", ecdhX)
        .update(Buffer.concat([be64(sessionNonce), Buffer.from("CSLS-MAC-v1", "ascii")]))
        .digest();

      session = {
        vendorPkHex: cleanPk,
        vendorEndpoint,
        sessionKey,
        sessionNonce,
        ecdhX,
        height: 0n,
        cumulativeMicro: 0n,
        tokensProcessed: 0,
        creditWindowDeltaV: 1000000n, // $1.00 USDC optimistic credit
        clearedMicro: 0n,
        lastAckHeight: 0n,
        active: true
      };

      this.sessions.set(cleanPk, session);
    }

    return session;
  }

  /**
   * Streams a per-token settlement cheque for newly generated tokens
   */
  public streamTokenSettlement(
    vendorPkHex: string,
    tokenCount: number,
    isCompletion = true
  ): StreamTokenChequeReceipt {
    const startHr = process.hrtime.bigint();
    const session = this.getOrCreateSession(vendorPkHex);

    const rateMicro = isCompletion
      ? this.defaultRates.completionTokenMicroUsdc
      : this.defaultRates.promptTokenMicroUsdc;

    const deltaMicro = BigInt(Math.max(1, Math.round(tokenCount * rateMicro)));

    // Optimistic exposure cap bounded by delta_v: unconfirmed credit is the
    // cumulative amount not yet cleared by on-chain settlement.
    const pendingCredit = session.cumulativeMicro + deltaMicro - session.clearedMicro;
    if (pendingCredit > session.creditWindowDeltaV) {
      throw new Error(`[FAIL] Optimistic credit cap exceeded: pending ${pendingCredit} > delta_v ${session.creditWindowDeltaV}`);
    }

    session.height += 1n;
    session.cumulativeMicro += deltaMicro;
    session.tokensProcessed += tokenCount;

    const vendorPkBuf = Buffer.from(session.vendorPkHex.replace(/^0x/, ""), "hex");

    // 1. Nonce k = HMAC-SHA256(sk, vendor_pk(33) || height_BE(8) || counter) mod q
    //    RFC 6979-style H3 counter loop: the counter byte is appended only on
    //    retries (first hash covers 41 bytes). A fabricated k = 1 would break
    //    the deterministic nonce invariant.
    const hBe = Buffer.alloc(8);
    hBe.writeBigUInt64BE(session.height, 0);
    const kBase = Buffer.concat([vendorPkBuf, hBe]);
    let k: bigint;
    let counter = 0;
    for (;;) {
      const data = counter === 0 ? kBase : Buffer.concat([kBase, Buffer.from([counter])]);
      const kHash = crypto.createHmac("sha256", this.agentSk).update(data).digest();
      k = BigInt("0x" + kHash.toString("hex"));
      if (k >= SECP256K1_Q) k %= SECP256K1_Q;
      if (k !== 0n) break;
      counter++;
      if (counter > 0xff) throw new Error("[FAIL] Nonce counter exhausted");
    }

    // 2. Challenge e = SHA256(agent_pk || vendor_pk || height || cumulative_amt) mod q
    const cumBe = Buffer.alloc(8);
    cumBe.writeBigUInt64BE(session.cumulativeMicro, 0);
    const preimage = Buffer.concat([this.agentPk, vendorPkBuf, hBe, cumBe]);
    const eHash = crypto.createHash("sha256").update(preimage).digest();
    const e = BigInt("0x" + eHash.toString("hex")) % SECP256K1_Q;

    // 3. Signature scalar s = (k + e * sk) mod q
    const skVal = BigInt("0x" + this.agentSk.toString("hex"));
    const s = (k + (e * skVal)) % SECP256K1_Q;

    // 4. Serialize 151-byte cheque packet
    const pktBuf = Buffer.alloc(CHEQUE_PACKET_SIZE);
    pktBuf.writeUInt32LE(CSLS_MAGIC, 0);
    pktBuf.writeUInt8(CSLS_PKT_CHEQUE, 4);
    this.agentPk.copy(pktBuf, 5, 0, 33);
    vendorPkBuf.copy(pktBuf, 38, 0, 33);
    pktBuf.writeBigUInt64LE(session.height, 71);
    pktBuf.writeBigUInt64LE(session.cumulativeMicro, 79);

    const eBuf = Buffer.alloc(32);
    eBuf.write(e.toString(16).padStart(64, "0"), "hex");
    eBuf.copy(pktBuf, 87, 0, 32);

    const sBuf = Buffer.alloc(32);
    sBuf.write(s.toString(16).padStart(64, "0"), "hex");
    sBuf.copy(pktBuf, 119, 0, 32);

    // 5. Append 16-byte Session MAC (167 bytes wire total)
    const mac = cslsMac128(session.sessionKey, pktBuf);
    const wireBuf = Buffer.concat([pktBuf, mac], WIRE_CHEQUE_SIZE);

    const deltaUsdc = Number(deltaMicro) / 1e6;
    const cumulativeUsdc = Number(session.cumulativeMicro) / 1e6;
    this.totalClearedUsdc += deltaUsdc;

    const endHr = process.hrtime.bigint();
    const latencyUs = Number(endHr - startHr) / 1000;

    return {
      status: "settled",
      chequeHeight: session.height.toString(),
      tokensMetered: tokenCount,
      deltaUsdc,
      cumulativeUsdc,
      wireChequeHex: "0x" + wireBuf.toString("hex"),
      gasSpent: "0 wei",
      latencyMicroseconds: latencyUs
    };
  }

  /**
   * Returns current active channel summary
   */
  public getChannelSummary(vendorPkHex: string) {
    const session = this.sessions.get("0x" + vendorPkHex.replace(/^0x/, ""));
    if (!session) {
      return null;
    }

    return {
      vendorPkHex: session.vendorPkHex,
      height: session.height.toString(),
      cumulativeMicro: session.cumulativeMicro.toString(),
      cumulativeUsdc: (Number(session.cumulativeMicro) / 1e6).toFixed(6),
      tokensProcessed: session.tokensProcessed,
      active: session.active
    };
  }
}

// Big-endian uint64 serialization (hash preimages in the C11 core are BE)
function be64(v: bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(v, 0);
  return b;
}
