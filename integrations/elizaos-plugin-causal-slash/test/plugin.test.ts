// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

import { test, describe } from "node:test";
import * as assert from "node:assert/strict";
import * as crypto from "node:crypto";
import {
  causalSlashPlugin,
  CausalSettlementService,
  streamTokenSettlementAction,
  getChannelBalanceAction,
  cslsCollateralProvider,
  IAgentRuntime,
  WIRE_CHEQUE_SIZE
} from "../src/index";

class MockElizaRuntime implements IAgentRuntime {
  private services = new Map<string, any>();
  private settings = new Map<string, string>();

  constructor() {
    this.registerService(new CausalSettlementService());
  }

  getSetting(key: string): string | undefined {
    return this.settings.get(key);
  }

  getService<T>(serviceName: string): T | undefined {
    return this.services.get(serviceName);
  }

  registerService(service: any): void {
    const type = (service.constructor as any).serviceType || "causal_slash_settlement";
    this.services.set(type, service);
  }
}

describe("ElizaOS @elizaos/plugin-causal-slash Test Suite", () => {
  const vendorSk = crypto.randomBytes(32);
  const vendorEcdh = crypto.createECDH("secp256k1");
  vendorEcdh.setPrivateKey(vendorSk);
  const vendorPk = vendorEcdh.getPublicKey(null, "compressed");
  const vendorPkHex = "0x" + vendorPk.toString("hex");

  test("Conforms to ElizaOS Plugin standard manifest", () => {
    assert.equal(causalSlashPlugin.name, "causal-slash");
    assert.equal(typeof causalSlashPlugin.description, "string");
    assert.equal(causalSlashPlugin.actions.length, 2);
    assert.equal(causalSlashPlugin.providers.length, 1);
    assert.equal(causalSlashPlugin.services.length, 1);

    const actionNames = causalSlashPlugin.actions.map((a) => a.name);
    assert.equal(actionNames.includes("STREAM_TOKEN_SETTLEMENT"), true);
    assert.equal(actionNames.includes("GET_CHANNEL_BALANCE"), true);
  });

  test("CausalSettlementService generates 167-byte Session MAC micro-cheques for streaming tokens", () => {
    const service = new CausalSettlementService();
    assert.equal(service.agentSk.length, 32);
    assert.equal(service.agentPk.length, 33);
    assert.equal(service.agentPkHex.length, 68);

    // Stream 150 prompt tokens
    const receipt1 = service.streamTokenSettlement(vendorPkHex, 150, false);
    assert.equal(receipt1.status, "settled");
    assert.equal(receipt1.chequeHeight, "1");
    assert.equal(receipt1.tokensMetered, 150);
    assert.equal(receipt1.gasSpent, "0 wei");
    assert.equal(receipt1.wireChequeHex.length, WIRE_CHEQUE_SIZE * 2 + 2); // "0x" + 334 hex

    // Stream 300 completion tokens
    const receipt2 = service.streamTokenSettlement(vendorPkHex, 300, true);
    assert.equal(receipt2.status, "settled");
    assert.equal(receipt2.chequeHeight, "2");
    assert.equal(receipt2.tokensMetered, 300);
    assert.equal(receipt2.cumulativeUsdc > receipt1.cumulativeUsdc, true);
  });

  test("STREAM_TOKEN_SETTLEMENT action executes against mock runtime", async () => {
    const runtime = new MockElizaRuntime();
    const isValid = await streamTokenSettlementAction.validate(runtime, { content: { text: "test" } });
    assert.equal(isValid, true);

    let callbackOutput: any = null;
    const handled = await streamTokenSettlementAction.handler(
      runtime,
      {
        content: {
          text: "Stream 500 completion tokens",
          vendorPk: vendorPkHex,
          tokens: 500
        }
      },
      undefined,
      undefined,
      (res) => {
        callbackOutput = res;
      }
    );

    assert.equal(handled, true);
    assert.notEqual(callbackOutput, null);
    assert.equal(callbackOutput.text.includes("[OK] Streamed 500 tokens settled"), true);
    assert.equal(callbackOutput.text.includes("Blockchain Gas: 0 wei"), true);
    assert.equal(callbackOutput.receipt.tokensMetered, 500);
  });

  test("Session keys follow the C11 KDF: same agent + vendor + nonce reproduce the daemon session key", () => {
    const service = new CausalSettlementService();
    const session = service.getOrCreateSession(vendorPkHex);
    const recomputed = crypto
      .createHmac("sha256", session.ecdhX)
      .update(Buffer.concat([(() => { const b = Buffer.alloc(8); b.writeBigUInt64BE(session.sessionNonce, 0); return b; })(), Buffer.from("CSLS-MAC-v1", "ascii")]))
      .digest();
    assert.ok(session.sessionKey.equals(recomputed));
    // A raw ECDH x-coordinate must NOT be used as the session key (C2 gate)
    assert.ok(!session.sessionKey.equals(session.ecdhX));
  });

  test("cslsCollateralProvider supplies Base L2 vault context to agent state", async () => {
    const runtime = new MockElizaRuntime();
    const context = await cslsCollateralProvider.get(runtime, { content: { text: "" } });

    assert.equal(context.includes("BASE L2 COLLATERAL STATUS"), true);
    // Without BASE_RPC_URL the provider reports how to get live state and
    // must NOT print fabricated balances
    assert.equal(context.includes("set BASE_RPC_URL"), true);
    assert.equal(context.includes("80% Morpho/Aave"), true);
    assert.equal(context.includes("Axiom 1 Active"), true);
    assert.equal(context.includes("Zero Web2 API Keys"), true);
    assert.equal(context.includes("Master Bond Locked"), false);
  });
});
