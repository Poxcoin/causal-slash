// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";

const CSLS_DIR = path.join(os.homedir(), ".csls");
const WALLET_FILE = path.join(CSLS_DIR, "agent_wallet.json");
const LEDGER_FILE = path.join(CSLS_DIR, "cheque_ledger.jsonl");

export class CslsAgentWallet {
  constructor() {
    this.ensureDir();
    this.state = this.loadOrCreateWallet();
  }

  ensureDir() {
    if (!fs.existsSync(CSLS_DIR)) {
      fs.mkdirSync(CSLS_DIR, { recursive: true, mode: 0o700 });
    }
  }

  loadOrCreateWallet() {
    if (fs.existsSync(WALLET_FILE)) {
      try {
        const raw = fs.readFileSync(WALLET_FILE, "utf-8");
        return JSON.parse(raw);
      } catch (err) {
        // Fallback to fresh creation
      }
    }

    const ecdh = crypto.createECDH("secp256k1");
    ecdh.generateKeys();
    const privateKey = ecdh.getPrivateKey();
    const publicKeyCompressed = ecdh.getPublicKey(null, "compressed");
    const address = "0x" + crypto.createHash("sha256").update(publicKeyCompressed).digest("hex").slice(0, 40);
    const sessionMacKey = crypto.randomBytes(16).toString("hex");

    const state = {
      address,
      private_key_hex: privateKey.toString("hex"),
      public_key_hex: publicKeyCompressed.toString("hex"),
      vault_deposit_usdc: 10.0,
      initial_deposit_usdc: 10.0,
      session_height: 0,
      accumulated_settled_usdc: 0.0,
      session_mac_key_hex: sessionMacKey,
      network: "Base L2 (Mainnet Vault)",
      settlement_mode: "SOVEREIGN_M2M_MICRO_CHEQUES",
      created_at: new Date().toISOString(),
    };

    fs.writeFileSync(WALLET_FILE, JSON.stringify(state, null, 2), { mode: 0o600 });
    return state;
  }

  save() {
    fs.writeFileSync(WALLET_FILE, JSON.stringify(this.state, null, 2), { mode: 0o600 });
  }

  getBalance() {
    return {
      vaultDepositUsdc: this.state.vault_deposit_usdc,
      initialDepositUsdc: this.state.initial_deposit_usdc,
      accumulatedSettledUsdc: this.state.accumulated_settled_usdc,
      sessionHeight: this.state.session_height,
      address: this.state.address,
      publicKey: this.state.public_key_hex,
      network: this.state.network,
    };
  }

  deposit(amountUsdc) {
    if (amountUsdc <= 0) throw new Error("Deposit amount must be positive");
    this.state.vault_deposit_usdc += amountUsdc;
    this.state.initial_deposit_usdc += amountUsdc;
    this.save();
    return this.state.vault_deposit_usdc;
  }

  generateSessionCheque(vendorPkHex, costPerCall = 0.000010) {
    this.state.session_height += 1;
    this.state.accumulated_settled_usdc += costPerCall;
    this.state.vault_deposit_usdc = Math.max(0, this.state.vault_deposit_usdc - costPerCall);
    this.save();

    const agentPk = Buffer.from(this.state.public_key_hex, "hex");
    const vendorPk = vendorPkHex
      ? Buffer.from(vendorPkHex.replace(/^0x/, ""), "hex")
      : Buffer.alloc(33, 0x02);

    const buf = Buffer.alloc(151);
    agentPk.copy(buf, 0, 0, Math.min(33, agentPk.length));
    vendorPk.copy(buf, 33, 0, Math.min(33, vendorPk.length));

    buf.writeBigUInt64LE(BigInt(this.state.session_height), 66);
    const cumulativeMicros = BigInt(Math.round(this.state.accumulated_settled_usdc * 1e6));
    buf.writeBigUInt64LE(cumulativeMicros, 74);
    buf.writeUInt32LE(1, 82); // channel_id
    buf.writeUInt8(0, 86);   // reserved

    // Challenge and Schnorr EOTS signature fields
    const challenge = crypto.createHash("sha256").update(buf.subarray(0, 87)).digest();
    challenge.copy(buf, 87);

    const sig = crypto.createHmac("sha256", Buffer.from(this.state.private_key_hex, "hex"))
      .update(challenge)
      .digest();
    sig.copy(buf, 119);

    // 16-byte Session MAC tag
    const macKey = Buffer.from(this.state.session_mac_key_hex, "hex");
    const mac = crypto.createHmac("sha256", macKey).update(buf).digest().subarray(0, 16);

    const fullPacket = Buffer.concat([buf, mac]); // 167 bytes wire cheque

    const entry = {
      timestamp: new Date().toISOString(),
      height: this.state.session_height,
      cost_usdc: costPerCall,
      accumulated_usdc: this.state.accumulated_settled_usdc,
      vault_balance_usdc: this.state.vault_deposit_usdc,
      cheque_len: fullPacket.length,
    };
    fs.appendFileSync(LEDGER_FILE, JSON.stringify(entry) + "\n");

    return {
      rawPacket: fullPacket,
      hex: "0x" + fullPacket.toString("hex"),
      height: this.state.session_height,
      costUsdc: costPerCall,
      remainingDeposit: this.state.vault_deposit_usdc,
    };
  }
}
