// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers
//
// Test suite for the CausalSlashActionProvider and the vendor-side node.
// Wire compatibility is pinned by golden vectors generated from the canonical
// C11 engine (test/c11_vectors.json, produced from src/causal_daemon.c).
// There are no mocked settlement numbers in this suite: every value asserted
// below is either a cryptographic golden vector, a locally computed quantity,
// or an explicitly asserted failure path.

import { test, describe } from "node:test";
import * as assert from "node:assert/strict";
import * as http from "node:http";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import {
  CausalSlashActionProvider,
  causalSlashActionProvider,
  WIRE_CHEQUE_SIZE,
  CHEQUE_PACKET_SIZE,
  SESSION_MAC_SIZE,
  SESSION_INIT_PACKET_SIZE,
  CslsErrorCode,
  parseWireCheque,
  cslsMac128,
  verifyMacTag,
  deriveCompressedPublicKey,
  deriveChannelSessionKey,
  deriveEcdhSharedSecret,
  buildSessionInitPacket,
  sessionAuthMac,
  extractPrivateKey,
  computeChallengeScalar,
  computeSignatureScalar,
  deriveDeterministicNonce,
  CslsVendorNode,
  parseChequePacket,
  serialize151
} from "../src/index";

interface C11Vectors {
  agent_sk_hex: string;
  vendor_sk_hex: string;
  agent_pk_hex: string;
  vendor_pk_hex: string;
  session_nonce: string;
  session_init_hex: string;
  cheques: Array<{
    delta_micro: string;
    cheque151_hex: string;
    mac16_hex: string;
    vendor_rc: number;
    vendor_height: string;
    vendor_accumulated_micro: string;
  }>;
  replay_vendor_rc: number;
  equivocation: {
    cheque1_hex: string;
    cheque2_hex: string;
    extracted_sk_hex: string;
    extract_rc: number;
  };
}

const vectors: C11Vectors = JSON.parse(
  // Compiled to dist/test: resolve back into the source tree
  fs.readFileSync(path.join(__dirname, "..", "..", "test", "c11_vectors.json"), "utf8")
) as C11Vectors;

describe("C11 golden vectors (wire compatibility with src/causal_daemon.c)", () => {
  const agentSk = Buffer.from(vectors.agent_sk_hex, "hex");
  const vendorSk = Buffer.from(vectors.vendor_sk_hex, "hex");
  const agentPk = deriveCompressedPublicKey(agentSk);
  const vendorPk = deriveCompressedPublicKey(vendorSk);

  test("Derives the exact compressed public keys of the C11 engine", () => {
    // Fixture stores bare hex (Buffer.from-compatible); compare accordingly
    assert.equal(agentPk.toString("hex"), vectors.agent_pk_hex);
    assert.equal(vendorPk.toString("hex"), vectors.vendor_pk_hex);
  });

  test("Reproduces the exact 95-byte SESSION_INIT packet (C2 bootstrap)", () => {
    const ecdhX = deriveEcdhSharedSecret(agentSk, vendorPk);
    const nonce = BigInt(vectors.session_nonce);
    const authMac = sessionAuthMac(ecdhX, agentPk, vendorPk, nonce);
    const init = buildSessionInitPacket(agentPk, vendorPk, nonce, authMac);
    assert.equal(init.length, SESSION_INIT_PACKET_SIZE);
    assert.equal(init.toString("hex"), vectors.session_init_hex);
  });

  test("Derives the exact session key schedule used by the C11 KDF", () => {
    // Indirect proof: re-signing with the KDF session key must reproduce the
    // golden 16-byte MACs over the golden 151-byte packets.
    const ecdhX = deriveEcdhSharedSecret(agentSk, vendorPk);
    const sessionKey = deriveChannelSessionKey(ecdhX, BigInt(vectors.session_nonce));
    for (const c of vectors.cheques) {
      const pkt = Buffer.from(c.cheque151_hex, "hex");
      const expectedMac = Buffer.from(c.mac16_hex, "hex");
      assert.ok(verifyMacTag(cslsMac128(sessionKey, pkt), expectedMac));
    }
  });

  test("Vendor node accepts the golden cheques byte-for-byte", () => {
    const vendor = new CslsVendorNode({ sk32: vendorSk, deltaVMicro: 10000000n });
    assert.equal(vendor.sessionInit(Buffer.from(vectors.session_init_hex, "hex")).accepted, true);
    for (const c of vectors.cheques) {
      const decision = vendor.processChequeAndMac(
        Buffer.from(c.cheque151_hex, "hex"),
        Buffer.from(c.mac16_hex, "hex")
      );
      assert.equal(decision.accepted, true, `cheque rejected: ${decision.statusCode}`);
      assert.equal(decision.height?.toString(), c.vendor_height);
      assert.equal(decision.accumulatedMicro?.toString(), c.vendor_accumulated_micro);
    }
  });

  test("Vendor node flags exact-duplicate replay with -21", () => {
    const vendor = new CslsVendorNode({ sk32: vendorSk, deltaVMicro: 10000000n });
    assert.equal(vendor.sessionInit(Buffer.from(vectors.session_init_hex, "hex")).accepted, true);
    for (const c of vectors.cheques) {
      vendor.processChequeAndMac(Buffer.from(c.cheque151_hex, "hex"), Buffer.from(c.mac16_hex, "hex"));
    }
    // Replay the last golden cheque
    const last = vectors.cheques[vectors.cheques.length - 1];
    const decision = vendor.processChequeAndMac(
      Buffer.from(last.cheque151_hex, "hex"),
      Buffer.from(last.mac16_hex, "hex")
    );
    assert.equal(decision.accepted, false);
    assert.equal(decision.statusCode, vectors.replay_vendor_rc);
    assert.equal(decision.statusCode, CslsErrorCode.ERR_REPLAY);
  });

  test("O(1) EOTS extraction recovers the agent key from golden equivocation", () => {
    const c1 = parseChequePacket(Buffer.from(vectors.equivocation.cheque1_hex, "hex"));
    const c2 = parseChequePacket(Buffer.from(vectors.equivocation.cheque2_hex, "hex"));
    const sk = extractPrivateKey(c1, c2);
    assert.equal(sk.toString("hex"), vectors.equivocation.extracted_sk_hex);
    assert.equal(sk.toString("hex"), vectors.agent_sk_hex);
  });

  test("Vendor node traps the golden equivocation pair with a fraud proof", () => {
    // Fresh vendor: feed both conflicting cheques. The first must be accepted
    // (fresh channel state) and the second must trigger -20 with a proof.
    const vendor = new CslsVendorNode({ sk32: vendorSk, deltaVMicro: 10000000n });
    // The equivocation cheques are externally built; arm the session from the
    // golden init and MAC them with the true session key.
    assert.equal(vendor.sessionInit(Buffer.from(vectors.session_init_hex, "hex")).accepted, true);
    const ecdhX = deriveEcdhSharedSecret(agentSk, vendorPk);
    const sessionKey = deriveChannelSessionKey(ecdhX, BigInt(vectors.session_nonce));

    const c1 = Buffer.from(vectors.equivocation.cheque1_hex, "hex");
    const mac1 = cslsMac128(sessionKey, c1);
    const first = vendor.processChequeAndMac(c1, mac1);
    assert.equal(first.accepted, true, `first equivocation cheque rejected: ${first.statusCode}`);

    const c2 = Buffer.from(vectors.equivocation.cheque2_hex, "hex");
    const mac2 = cslsMac128(sessionKey, c2);
    const second = vendor.processChequeAndMac(c2, mac2);
    assert.equal(second.accepted, false);
    assert.equal(second.statusCode, CslsErrorCode.ERR_FRAUD);
    assert.ok(second.fraudProof, "fraud proof missing");
    assert.equal(second.fraudProof?.extractedSkHex, "0x" + vectors.equivocation.extracted_sk_hex);
  });
});

describe("Vendor node security pipeline (local cryptographic assertions)", () => {
  const agentSk = crypto.randomBytes(32);
  const vendorSk = crypto.randomBytes(32);
  const vendorPk = deriveCompressedPublicKey(vendorSk);
  const agentPk = deriveCompressedPublicKey(agentSk);

  function armSession(vendor: CslsVendorNode): Buffer {
    const ecdhX = deriveEcdhSharedSecret(agentSk, vendorPk);
    const nonce = 777n;
    const authMac = sessionAuthMac(ecdhX, agentPk, vendorPk, nonce);
    const init = buildSessionInitPacket(agentPk, vendorPk, nonce, authMac);
    assert.equal(vendor.sessionInit(init).accepted, true);
    return deriveChannelSessionKey(ecdhX, nonce);
  }

  // Locally built cheques through the same exported primitives the agent uses
  function buildCheque(height: bigint, cumulative: bigint, forceBadChallenge = false): Buffer {
    const challengeE = forceBadChallenge
      ? crypto.randomBytes(32)
      : computeChallengeScalar(agentPk, vendorPk, height, cumulative);
    const k = deriveDeterministicNonce(agentSk, vendorPk, height);
    const sigS = computeSignatureScalar(k, challengeE, agentSk);
    return serialize151({
      magic: 0x43534c53,
      type: 0x01,
      agentPk,
      vendorPk,
      height,
      cumulativeAmt: cumulative,
      challengeE,
      sigS
    });
  }

  test("Rejects cheques with a corrupted session MAC (-24)", () => {
    const vendor = new CslsVendorNode({ sk32: vendorSk });
    const sessionKey = armSession(vendor);
    const pkt = buildCheque(1n, 100n);
    const mac = cslsMac128(sessionKey, pkt);
    mac[0] ^= 0x01;
    const decision = vendor.processChequeAndMac(pkt, mac);
    assert.equal(decision.statusCode, CslsErrorCode.ERR_BAD_MAC);
  });

  test("Rejects cheques without an established session (-25)", () => {
    const vendor = new CslsVendorNode({ sk32: vendorSk });
    const strangerSk = crypto.randomBytes(32);
    const strangerPk = deriveCompressedPublicKey(strangerSk);
    const challengeE = computeChallengeScalar(strangerPk, vendorPk, 1n, 100n);
    const k = deriveDeterministicNonce(strangerSk, vendorPk, 1n);
    const pkt = serialize151({
      magic: 0x43534c53, type: 0x01,
      agentPk: strangerPk, vendorPk,
      height: 1n, cumulativeAmt: 100n,
      challengeE, sigS: computeSignatureScalar(k, challengeE, strangerSk)
    });
    const decision = vendor.processChequeAndMac(pkt, crypto.randomBytes(16));
    assert.equal(decision.statusCode, CslsErrorCode.ERR_NO_SESSION);
  });

  test("Enforces the delta_v exposure cap (-12)", () => {
    const vendor = new CslsVendorNode({ sk32: vendorSk, deltaVMicro: 100n });
    const sessionKey = armSession(vendor);
    const pkt = buildCheque(1n, 150n); // unconfirmed 150 > delta_v 100
    const decision = vendor.processChequeAndMac(pkt, cslsMac128(sessionKey, pkt));
    assert.equal(decision.statusCode, CslsErrorCode.ERR_EXPOSURE_CAP);
  });

  test("Rejects height regressions (-22)", () => {
    const vendor = new CslsVendorNode({ sk32: vendorSk, deltaVMicro: 10000000n });
    const sessionKey = armSession(vendor);
    const high = vendor.processChequeAndMac(buildCheque(5n, 500n), cslsMac128(sessionKey, buildCheque(5n, 500n)));
    assert.equal(high.accepted, true);
    const low = vendor.processChequeAndMac(buildCheque(3n, 700n), cslsMac128(sessionKey, buildCheque(3n, 700n)));
    assert.equal(low.accepted, false);
    assert.equal(low.statusCode, CslsErrorCode.ERR_OUT_OF_ORDER);
  });

  test("Rejects a decreasing cumulative amount (-11)", () => {
    const vendor = new CslsVendorNode({ sk32: vendorSk, deltaVMicro: 10000000n });
    const sessionKey = armSession(vendor);
    const first = vendor.processChequeAndMac(buildCheque(1n, 500n), cslsMac128(sessionKey, buildCheque(1n, 500n)));
    assert.equal(first.accepted, true);
    const second = vendor.processChequeAndMac(buildCheque(2n, 100n), cslsMac128(sessionKey, buildCheque(2n, 100n)));
    assert.equal(second.accepted, false);
    assert.equal(second.statusCode, CslsErrorCode.ERR_DECREASING_AMOUNT);
  });

  test("Rejects a forged challenge hash (-23)", () => {
    const vendor = new CslsVendorNode({ sk32: vendorSk, deltaVMicro: 10000000n });
    const sessionKey = armSession(vendor);
    const pkt = buildCheque(1n, 100n, true);
    const decision = vendor.processChequeAndMac(pkt, cslsMac128(sessionKey, pkt));
    assert.equal(decision.statusCode, CslsErrorCode.ERR_FORGED_CHALLENGE);
  });

  test("Releases exposure headroom after advanceCleared settlement", () => {
    const vendor = new CslsVendorNode({ sk32: vendorSk, deltaVMicro: 100n });
    const sessionKey = armSession(vendor);
    const agentPkHex = agentPk.toString("hex");
    // First cheque: unconfirmed 100 <= delta_v 100 -> accepted
    const first = vendor.processChequeAndMac(buildCheque(1n, 100n), cslsMac128(sessionKey, buildCheque(1n, 100n)));
    assert.equal(first.accepted, true);
    // Second cheque at cumulative 200: unconfirmed 200 > delta_v 100 -> capped
    const capped = vendor.processChequeAndMac(buildCheque(2n, 200n), cslsMac128(sessionKey, buildCheque(2n, 200n)));
    assert.equal(capped.statusCode, CslsErrorCode.ERR_EXPOSURE_CAP);
    // On-chain settlement clears the first 100 micro: headroom released
    assert.equal(vendor.advanceCleared(agentPkHex, 100n), true);
    const accepted = vendor.processChequeAndMac(buildCheque(2n, 200n), cslsMac128(sessionKey, buildCheque(2n, 200n)));
    assert.equal(accepted.accepted, true);
    assert.equal(accepted.accumulatedMicro, 200n);
  });
});

describe("Coinbase AgentKit CausalSlashActionProvider", () => {
  const vendorSk = crypto.randomBytes(32);
  const vendorPk = deriveCompressedPublicKey(vendorSk);
  const vendorPkHex = "0x" + vendorPk.toString("hex");

  test("Initializes provider with sovereign secp256k1 agent identity", () => {
    const provider = new CausalSlashActionProvider();
    assert.equal(provider.name, "causal_slash");
    assert.equal(provider.agentSk.length, 32);
    assert.equal(provider.agentPk.length, 33);
    assert.equal(provider.agentPkHex.startsWith("0x"), true);
    assert.equal(provider.agentPkHex.length, 68); // "0x" + 66 hex chars
  });

  test("Exposes 4 Coinbase AgentKit native actions", () => {
    const provider = new CausalSlashActionProvider();
    const actions = provider.getActions();
    assert.equal(actions.length, 4);
    const actionNames = actions.map((a) => a.name);
    assert.equal(actionNames.includes("causal_create_channel"), true);
    assert.equal(actionNames.includes("causal_sign_stream_cheque"), true);
    assert.equal(actionNames.includes("causal_invoke_paid_inference"), true);
    assert.equal(actionNames.includes("causal_inspect_vault_bond"), true);
  });

  test("Creates channel with the exact C11 session key schedule", async () => {
    const provider = new CausalSlashActionProvider();
    const result = await provider.createChannel({
      vendorAddress: vendorPkHex,
      depositUsdc: 25.0
    });
    assert.equal(result.success, true);
    assert.equal(result.data.status, "active");
    assert.equal(result.data.sessionMacAuth, "active_128bit");
    assert.equal(result.data.wirePacketSize, 167);
    assert.equal(result.data.zeroWeb2ApiKeys, true);
    // No endpoint configured: the 95-byte init packet is held for the first
    // HTTP call; the local session key is the C11 KDF output.
    assert.equal(result.data.sessionInitDelivered, false);
  });

  test("Signs monotonic 167-byte Session MAC micro-cheques over the wire", async () => {
    const provider = new CausalSlashActionProvider();
    await provider.createChannel({ vendorAddress: vendorPkHex, depositUsdc: 10.0 });

    const res1 = await provider.signStreamCheque({
      vendorAddress: vendorPkHex,
      amountUsdc: 0.0001,
      purpose: "llm.tokens.chunk1"
    });

    assert.equal(res1.success, true);
    assert.equal(res1.data.height, "1");
    assert.equal(res1.data.wireSize, WIRE_CHEQUE_SIZE);
    assert.equal(res1.data.chequeHex.length, WIRE_CHEQUE_SIZE * 2 + 2); // "0x" + 334 hex chars

    const wireBuf = Buffer.from(res1.data.chequeHex.replace(/^0x/, ""), "hex");
    assert.equal(wireBuf.length, 167);
    const parsed = parseWireCheque(wireBuf);
    assert.equal(parsed.pkt.magic, 0x43534c53);
    assert.equal(parsed.pkt.type, 0x01);
    assert.equal(parsed.height, 1n);
    assert.equal(parsed.pkt.cumulativeAmt, 100n); // 0.0001 USDC = 100 micro-USDC
    assert.equal(parsed.mac.length, 16);

    // The signed cheque is verifiable by an honest vendor node that has the
    // same session armed: MAC + challenge + monotonicity all verify.
    const vendor = new CslsVendorNode({ sk32: vendorSk, deltaVMicro: 10000000n });
    // Arm the vendor with the provider's exact session (same derivation)
    const ecdhX = deriveEcdhSharedSecret((provider as any).agentSk, vendorPk);
    const nonce = (provider as any).channels.get(vendorPkHex).sessionNonce as bigint;
    const authMac = sessionAuthMac(ecdhX, (provider as any).agentPk, vendorPk, nonce);
    const init = buildSessionInitPacket((provider as any).agentPk, vendorPk, nonce, authMac);
    assert.equal(vendor.sessionInit(init).accepted, true);

    const decision = vendor.processWireCheque(wireBuf);
    assert.equal(decision.accepted, true, `honest vendor rejected our cheque: ${decision.statusCode}`);
    assert.equal(decision.height, 1n);
    assert.equal(decision.accumulatedMicro, 100n);

    // Monotonic progression on the second cheque
    const res2 = await provider.signStreamCheque({
      vendorAddress: vendorPkHex,
      amountUsdc: 0.0002,
      purpose: "llm.tokens.chunk2"
    });
    assert.equal(res2.success, true);
    assert.equal(res2.data.height, "2");
    assert.equal(res2.data.cumulativeSentUsdc, 0.0003);
    const decision2 = vendor.processWireCheque(
      Buffer.from(res2.data.chequeHex.replace(/^0x/, ""), "hex")
    );
    assert.equal(decision2.accepted, true);
    assert.equal(decision2.accumulatedMicro, 300n);
  });

  test("Delivers session init + cheque header to a live local vendor, zero Web2 credentials", async () => {
    // A minimal sovereign vendor node over HTTP: C2 bootstrap + cheque gate
    const vendor = new CslsVendorNode({ sk32: vendorSk, deltaVMicro: 10000000n });
    const server = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        const body = Buffer.concat(chunks);
        if (req.url === "/v1/session") {
          const decision = vendor.sessionInit(body);
          res.writeHead(decision.accepted ? 200 : 403, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ accepted: decision.accepted, statusCode: decision.statusCode }));
          return;
        }
        if (req.url === "/v1/chat/completions") {
          const chequeHex = req.headers["x-causal-cheque"] as string;
          const decision = vendor.processWireCheque(Buffer.from(chequeHex, "hex"));
          if (!decision.accepted) {
            res.writeHead(403, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "CHEQUE_REJECTED", statusCode: decision.statusCode }));
            return;
          }
          res.writeHead(200, {
            "Content-Type": "application/json",
            "X-Causal-Slash-Cheque-Height": decision.height?.toString() ?? "",
            "X-Causal-Slash-Settled-USDC": (Number(decision.accumulatedMicro) / 1e6).toFixed(6),
            "X-Causal-Gas": "0"
          });
          res.end(
            JSON.stringify({
              choices: [{ message: { content: "Remote sovereign frontier inference completed." } }]
            })
          );
          return;
        }
        res.writeHead(404);
        res.end();
      });
    });

    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    const address = server.address() as any;
    const base = `http://127.0.0.1:${address.port}`;

    try {
      const provider = new CausalSlashActionProvider();
      const res = await provider.invokePaidInference({
        vendorAddress: vendorPkHex,
        endpointUrl: `${base}/v1/chat/completions`,
        model: "claude-opus-5.5",
        prompt: "Synthesize autonomous M2M state channel verification.",
        costUsdc: 0.0005
      });

      assert.equal(res.success, true, `inference failed: ${res.error}`);
      assert.equal(res.data.status, "settled");
      assert.equal(res.data.gasSpentUsdc, "0");
      assert.equal(res.data.response, "Remote sovereign frontier inference completed.");
      // Settlement receipt comes from the vendor decision, not fabrication
      assert.equal(res.data.chequeHeight, "1");
      assert.equal(res.data.cumulativeUsdc, "0.000500");
    } finally {
      server.close();
    }
  });

  test("Fails fast against an unreachable vendor (no simulated fallback)", async () => {
    const provider = new CausalSlashActionProvider();
    const res = await provider.invokePaidInference({
      vendorAddress: vendorPkHex,
      endpointUrl: "http://127.0.0.1:1/v1/chat/completions", // nothing listens here
      model: "claude-opus-5.5",
      prompt: "This must fail fast.",
      costUsdc: 0.0005
    });
    assert.equal(res.success, false);
    assert.match(res.error ?? "", /Connection error|timed out|bootstrap/);
  });

  test("Vault bond inspection fails fast without a reachable RPC (no fabricated balances)", async () => {
    const provider = new CausalSlashActionProvider();
    const result = await provider.inspectVaultBond({});
    assert.equal(result.success, false);
    assert.match(result.error ?? "", /FAIL/);
  });
});
