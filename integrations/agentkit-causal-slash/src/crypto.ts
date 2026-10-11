// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

import * as crypto from "crypto";
import {
  CSLS_MAGIC,
  CSLS_PKT_CHEQUE,
  CSLS_PKT_SESSION_INIT,
  CHEQUE_PACKET_SIZE,
  SESSION_MAC_SIZE,
  SESSION_INIT_PACKET_SIZE,
  WIRE_CHEQUE_SIZE,
  SECP256K1_Q,
  CslsChequePkt,
  CslsChequeWire,
  CslsErrorCode
} from "./types";

const MASK64 = 0xffffffffffffffffn;

/**
 * 64-bit bitwise left rotation
 */
function rotl64(x: bigint, b: bigint): bigint {
  return (((x << b) & MASK64) | (x >> (64n - b))) & MASK64;
}

/**
 * SipHash single round
 */
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

/**
 * SipHash-2-4 64-bit primitive matching C11 csls_siphash24
 */
export function siphash24(keyBuf: Buffer, msgBuf: Buffer, finXor = 0n): bigint {
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

/**
 * 128-bit Session MAC over the raw 151-byte cheque packet
 * Matches C11 csls_mac128 in src/causal_daemon.c
 */
export function cslsMac128(keyBuf: Buffer, dataBuf: Buffer): Buffer {
  const k16 = keyBuf.subarray(0, 16);
  const a = siphash24(k16, dataBuf, 0n);
  const b = siphash24(k16, dataBuf, 0xEen);

  const out = Buffer.alloc(SESSION_MAC_SIZE);
  out.writeBigUInt64LE(a, 0);
  out.writeBigUInt64LE(b, 8);
  return out;
}

/**
 * Constant-time comparison for MAC authentication tags
 */
export function verifyMacTag(computedMac: Buffer, receivedMac: Buffer): boolean {
  if (computedMac.length !== SESSION_MAC_SIZE || receivedMac.length !== SESSION_MAC_SIZE) {
    return false;
  }
  return crypto.timingSafeEqual(computedMac, receivedMac);
}

/**
 * Static-static ECDH derivation on secp256k1
 * Derives shared secret x-coordinate from agent private key and peer public key.
 * The result is left-padded to exactly 32 bytes (BN_bn2binpad semantics in the
 * C11 core); a raw node secret may be shorter when the x-coordinate has
 * leading zero bytes.
 */
export function deriveEcdhSharedSecret(privateKey32: Buffer, peerPublicKey33: Buffer): Buffer {
  const ecdh = crypto.createECDH("secp256k1");
  ecdh.setPrivateKey(privateKey32);
  const secret = ecdh.computeSecret(peerPublicKey33);
  if (secret.length > 32) {
    throw new Error("[FAIL] ECDH shared secret longer than 32 bytes");
  }
  if (secret.length === 32) {
    return secret;
  }
  const padded = Buffer.alloc(32);
  secret.copy(padded, 32 - secret.length);
  return padded;
}

/**
 * Session key derivation, bit-exact mirror of C11 csls_session_kdf:
 *   session_key = HMAC-SHA256(ecdh_x, session_nonce_BE(8) || "CSLS-MAC-v1")
 * The 32-byte output keys the 128-bit SipHash-2-4 session MAC (first 16 bytes).
 */
export function deriveChannelSessionKey(ecdhX32: Buffer, sessionNonce: bigint): Buffer {
  const nonceBe = Buffer.alloc(8);
  nonceBe.writeBigUInt64BE(sessionNonce, 0);
  return crypto
    .createHmac("sha256", ecdhX32)
    .update(Buffer.concat([nonceBe, Buffer.from("CSLS-MAC-v1", "ascii")]))
    .digest();
}

/**
 * SESSION_INIT authentication tag, bit-exact mirror of C11 csls_session_auth:
 *   auth_mac = HMAC-SHA256(ecdh_x, agent_pk(33) || vendor_pk(33) || nonce_BE(8))[0..16]
 * Proves the ECDH secret belongs to the claimed agent identity.
 */
export function sessionAuthMac(
  ecdhX32: Buffer,
  agentPk33: Buffer,
  vendorPk33: Buffer,
  sessionNonce: bigint
): Buffer {
  const nonceBe = Buffer.alloc(8);
  nonceBe.writeBigUInt64BE(sessionNonce, 0);
  const full = crypto
    .createHmac("sha256", ecdhX32)
    .update(Buffer.concat([agentPk33, vendorPk33, nonceBe]))
    .digest();
  return full.subarray(0, 16);
}

/**
 * Builds the 95-byte csls_session_init_pkt_t (C2 gate bootstrap) that must be
 * delivered to the vendor before the first 167-byte wire cheque:
 * raw TCP framing, POST /v1/session, or any transport the vendor publishes.
 */
export function buildSessionInitPacket(
  agentPk33: Buffer,
  vendorPk33: Buffer,
  sessionNonce: bigint,
  authMac16: Buffer
): Buffer {
  const buf = Buffer.alloc(95);
  buf.writeUInt32LE(CSLS_MAGIC, 0);
  buf.writeUInt8(CSLS_PKT_SESSION_INIT, 4);
  agentPk33.copy(buf, 5);
  vendorPk33.copy(buf, 38);
  buf.writeBigUInt64LE(sessionNonce, 71);
  authMac16.copy(buf, 79);
  return buf;
}

/**
 * Vendor-side derivation of the expected session state from its own secret:
 * used by sovereign vendor nodes to authenticate inbound SESSION_INIT packets
 * and to arm the MAC verification key.
 */
export function vendorSessionKey(
  vendorSk32: Buffer,
  agentPk33: Buffer,
  vendorPk33: Buffer,
  sessionNonce: bigint
): { ecdhX: Buffer; expectedAuthMac: Buffer; sessionKey: Buffer } {
  const ecdhX = deriveEcdhSharedSecret(vendorSk32, agentPk33);
  const expectedAuthMac = sessionAuthMac(ecdhX, agentPk33, vendorPk33, sessionNonce);
  const sessionKey = deriveChannelSessionKey(ecdhX, sessionNonce);
  return { ecdhX, expectedAuthMac, sessionKey };
}

/**
 * Recompute the challenge preimage exactly like the C11 vendor hot path:
 *   e = SHA256(agent_pk || vendor_pk || h_BE(8) || cumulative_BE(8)) mod q
 * Fast path: the raw digest is used when already below q (probability 1 - 1.4e-38).
 */
export function recomputeChallengeScalar(
  agentPk: Buffer,
  vendorPk: Buffer,
  height: bigint,
  cumulativeAmt: bigint
): Buffer {
  return computeChallengeScalar(agentPk, vendorPk, height, cumulativeAmt);
}

/**
 * O(1) Algebraic Private Key Extraction (EOTS trap), mirror of
 * csls_extract_private_key: for two cheques at the SAME height with differing
 * challenge scalars, sk = (s1 - s2) * (e1 - e2)^(-1) mod q. The extracted key
 * is verified against the claimed agent identity before returning.
 */
export function extractPrivateKey(c1: CslsChequePkt, c2: CslsChequePkt): Buffer {
  if (c1.height !== c2.height) {
    throw new Error("[FAIL] Extraction requires identical heights");
  }
  if (!c1.agentPk.equals(c2.agentPk)) {
    throw new Error("[FAIL] Extraction requires the same agent key");
  }
  if (!c1.vendorPk.equals(c2.vendorPk)) {
    throw new Error("[FAIL] Equivocation is strictly per-vendor channel");
  }
  if (c1.challengeE.equals(c2.challengeE)) {
    throw new Error("[FAIL] No equivocation: identical challenge scalars");
  }

  const s1 = BigInt("0x" + c1.sigS.toString("hex"));
  const s2 = BigInt("0x" + c2.sigS.toString("hex"));
  const e1 = BigInt("0x" + c1.challengeE.toString("hex"));
  const e2 = BigInt("0x" + c2.challengeE.toString("hex"));

  const deltaS = ((s1 - s2) % SECP256K1_Q + SECP256K1_Q) % SECP256K1_Q;
  const deltaE = ((e1 - e2) % SECP256K1_Q + SECP256K1_Q) % SECP256K1_Q;
  const skVal = (deltaS * modInverse(deltaE, SECP256K1_Q)) % SECP256K1_Q;

  const out = Buffer.from(skVal.toString(16).padStart(64, "0"), "hex");
  const derivedPk = deriveCompressedPublicKey(out);
  if (!derivedPk.equals(c1.agentPk)) {
    throw new Error("[FAIL] Extracted key does not match agent identity");
  }
  return out;
}

/**
 * Extended Euclid modular inverse
 */
export function modInverse(a: bigint, m: bigint): bigint {
  let [oldR, r] = [((a % m) + m) % m, m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const quotient = oldR / r;
    [oldR, r] = [r, oldR - quotient * r];
    [oldS, s] = [s, oldS - quotient * s];
  }
  if (oldR !== 1n) {
    throw new Error("[FAIL] Modular inverse does not exist");
  }
  return ((oldS % m) + m) % m;
}

/**
 * Derive 33-byte compressed secp256k1 public key from private key
 */
export function deriveCompressedPublicKey(privateKey32: Buffer): Buffer {
  const ecdh = crypto.createECDH("secp256k1");
  ecdh.setPrivateKey(privateKey32);
  return ecdh.getPublicKey(null, "compressed");
}

/**
 * Deterministic Nonce Derivation:
 * k = HMAC-SHA256(sk, vendor_pk || height) mod q
 */
export function deriveDeterministicNonce(sk: Buffer, vendorPk: Buffer, height: bigint): bigint {
  const hBe = Buffer.alloc(8);
  hBe.writeBigUInt64BE(height, 0);

  const kPreimage = Buffer.concat([vendorPk, hBe]);
  let counter = 0;

  while (counter < 256) {
    const data = counter === 0 ? kPreimage : Buffer.concat([kPreimage, Buffer.from([counter])]);
    const kHash = crypto.createHmac("sha256", sk).update(data).digest();
    let kVal = BigInt("0x" + kHash.toString("hex"));

    if (kVal >= SECP256K1_Q) {
      kVal %= SECP256K1_Q;
    }
    if (kVal !== 0n) {
      return kVal;
    }
    counter++;
  }

  throw new Error("Nonce counter exhausted during derivation");
}

/**
 * Challenge Scalar e Calculation:
 * e = SHA256(agent_pk || vendor_pk || height || cumulative_amt) mod q
 */
export function computeChallengeScalar(
  agentPk: Buffer,
  vendorPk: Buffer,
  height: bigint,
  cumulativeAmt: bigint
): Buffer {
  const hBe = Buffer.alloc(8);
  hBe.writeBigUInt64BE(height, 0);

  const cumBe = Buffer.alloc(8);
  cumBe.writeBigUInt64BE(cumulativeAmt, 0);

  const preimage = Buffer.concat([agentPk, vendorPk, hBe, cumBe]);
  const digest = crypto.createHash("sha256").update(preimage).digest();

  let eVal = BigInt("0x" + digest.toString("hex"));
  if (eVal >= SECP256K1_Q) {
    eVal %= SECP256K1_Q;
  }

  const eBuf = Buffer.alloc(32);
  const hex = eVal.toString(16).padStart(64, "0");
  eBuf.write(hex, "hex");
  return eBuf;
}

/**
 * Schnorr EOTS Signature Scalar:
 * s = (k + e * sk) mod q
 */
export function computeSignatureScalar(k: bigint, eBuf: Buffer, sk: Buffer): Buffer {
  const eVal = BigInt("0x" + eBuf.toString("hex"));
  const skVal = BigInt("0x" + sk.toString("hex"));

  const sVal = (k + (eVal * skVal)) % SECP256K1_Q;

  const sBuf = Buffer.alloc(32);
  const hex = sVal.toString(16).padStart(64, "0");
  sBuf.write(hex, "hex");
  return sBuf;
}

/**
 * Serializes a 151-byte cheque packet
 */
export function serializeChequePacket(pkt: CslsChequePkt): Buffer {
  const buf = Buffer.alloc(CHEQUE_PACKET_SIZE);

  buf.writeUInt32LE(pkt.magic, 0);
  buf.writeUInt8(pkt.type, 4);
  pkt.agentPk.copy(buf, 5, 0, 33);
  pkt.vendorPk.copy(buf, 38, 0, 33);
  buf.writeBigUInt64LE(pkt.height, 71);
  buf.writeBigUInt64LE(pkt.cumulativeAmt, 79);
  pkt.challengeE.copy(buf, 87, 0, 32);
  pkt.sigS.copy(buf, 119, 0, 32);

  return buf;
}

/**
 * Serializes a 167-byte Session MAC wire cheque
 */
export function serializeWireCheque(pkt: CslsChequePkt, mac: Buffer): Buffer {
  const rawPkt = serializeChequePacket(pkt);
  return Buffer.concat([rawPkt, mac.subarray(0, SESSION_MAC_SIZE)], WIRE_CHEQUE_SIZE);
}

/**
 * Parses and validates a 167-byte wire cheque
 */
export function parseWireCheque(raw: Buffer): CslsChequeWire {
  if (raw.length !== WIRE_CHEQUE_SIZE) {
    throw new Error(`Invalid wire cheque length: expected ${WIRE_CHEQUE_SIZE} bytes, received ${raw.length}`);
  }

  const magic = raw.readUInt32LE(0);
  if (magic !== CSLS_MAGIC) {
    throw new Error(`Invalid protocol magic: 0x${magic.toString(16)} != 0x${CSLS_MAGIC.toString(16)}`);
  }

  const type = raw.readUInt8(4);
  if (type !== CSLS_PKT_CHEQUE) {
    throw new Error(`Invalid packet type: ${type}`);
  }

  const agentPk = Buffer.from(raw.subarray(5, 38));
  const vendorPk = Buffer.from(raw.subarray(38, 71));
  const height = raw.readBigUInt64LE(71);
  const cumulativeAmt = raw.readBigUInt64LE(79);
  const challengeE = Buffer.from(raw.subarray(87, 119));
  const sigS = Buffer.from(raw.subarray(119, 151));
  const mac = Buffer.from(raw.subarray(151, 167));

  const pkt: CslsChequePkt = {
    magic,
    type,
    agentPk,
    vendorPk,
    height,
    cumulativeAmt,
    challengeE,
    sigS
  };

  return {
    pkt,
    mac,
    rawPacket: raw,
    rawHex: "0x" + raw.toString("hex"),
    height,
    cumulativeUsdc: Number(cumulativeAmt) / 1e6
  };
}

/**
 * Complete Zero-Gas 167-Byte Wire Cheque Construction
 */
export function createWireCheque(
  sk: Buffer,
  agentPk: Buffer,
  vendorPk: Buffer,
  height: bigint,
  cumulativeAmt: bigint,
  sessionKey: Buffer
): CslsChequeWire {
  const k = deriveDeterministicNonce(sk, vendorPk, height);
  const challengeE = computeChallengeScalar(agentPk, vendorPk, height, cumulativeAmt);
  const sigS = computeSignatureScalar(k, challengeE, sk);

  const pkt: CslsChequePkt = {
    magic: CSLS_MAGIC,
    type: CSLS_PKT_CHEQUE,
    agentPk,
    vendorPk,
    height,
    cumulativeAmt,
    challengeE,
    sigS
  };

  const rawPkt = serializeChequePacket(pkt);
  const mac = cslsMac128(sessionKey, rawPkt);
  const rawWire = Buffer.concat([rawPkt, mac], WIRE_CHEQUE_SIZE);

  return {
    pkt,
    mac,
    rawPacket: rawWire,
    rawHex: "0x" + rawWire.toString("hex"),
    height,
    cumulativeUsdc: Number(cumulativeAmt) / 1e6
  };
}
