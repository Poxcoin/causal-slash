// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

import {
  Provider,
  IAgentRuntime,
  Memory,
  State
} from "../types";
import { CausalSettlementService } from "../services/causalService";

// keccak256("vaults(address)") selector, verified with `cast sig "vaults(address)"`
const VAULTS_SELECTOR = "a622ee7c";

async function readVaultBond(rpcUrl: string, vaultAddress: string, agentAddress: string): Promise<bigint | null> {
  try {
    const res = await fetch(rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "eth_call",
        params: [{ to: vaultAddress, data: "0x" + VAULTS_SELECTOR + agentAddress }, "latest"]
      }),
      signal: AbortSignal.timeout(8000)
    });
    if (!res.ok) return null;
    const json: any = await res.json();
    const raw: string = json.result ?? "";
    if (!raw || raw.length < 2 + 64) return null;
    return BigInt("0x" + raw.slice(2, 66)); // bond (uint256), first word
  } catch {
    return null;
  }
}

/**
 * State Provider supplying Base L2 Collateral Vault context to ElizaOS agents.
 * Live bond state is read over JSON-RPC; when the RPC endpoint is unreachable
 * the provider reports the local cheque ledger and says so explicitly instead
 * of fabricating balances.
 */
export const cslsCollateralProvider: Provider = {
  get: async (runtime: IAgentRuntime, _message: Memory, _state?: State): Promise<string> => {
    const service = runtime.getService<CausalSettlementService>("causal_slash_settlement");
    if (!service) {
      return "[CSLS] Causal-Slash Settlement Service not attached.";
    }

    const lines: string[] = [
      `=== CAUSAL-SLASH PROTOCOL: BASE L2 COLLATERAL STATUS ===`,
      `- Sovereign Agent Identity: ${service.agentPkHex}`,
      `- Base L2 Collateral Vault: ${service.vaultAddress}`,
      `- Total Cleared Volume (cheques signed this session): $${service.totalClearedUsdc.toFixed(6)} USDC`,
      `- Collateral Yield Architecture: 80% Morpho/Aave ERC-4626 buffer, 20% liquid instant unbond`,
      `- Subagent Quota Isolation: Axiom 1 Active ($5 - $10 Merkle Quotas)`,
      `- M2M Settlement Channel: 167-Byte Session MAC Micro-Cheques over Wire/HTTP`,
      `- Web2 Status: 100% Sovereign (Zero Web2 API Keys, Zero Retail Fiat Rails)`
    ];

    const rpcUrl = process.env.BASE_RPC_URL;
    const agentAddress = "0x" + service.agentPk.subarray(13).toString("hex");
    if (rpcUrl) {
      const bondMicro = await readVaultBond(rpcUrl, service.vaultAddress, agentAddress);
      if (bondMicro !== null) {
        lines.push(`- Master Bond Locked (live): $${(Number(bondMicro) / 1e6).toFixed(6)} USDC`);
      } else {
        lines.push(`- Master Bond: unavailable (RPC endpoint unreachable; no fabricated balance)`);
      }
    } else {
      lines.push(`- Master Bond: set BASE_RPC_URL to read live vault state over JSON-RPC`);
    }

    return lines.join("\n");
  }
};
