// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

import { Plugin } from "./types";
import { streamTokenSettlementAction } from "./actions/streamTokenSettlement";
import { getChannelBalanceAction } from "./actions/getChannelBalance";
import { cslsCollateralProvider } from "./providers/collateralProvider";
import { CausalSettlementService } from "./services/causalService";

export * from "./types";
export * from "./services/causalService";
export * from "./actions/streamTokenSettlement";
export * from "./actions/getChannelBalance";
export * from "./providers/collateralProvider";

/**
 * Standard ElizaOS Plugin Definition for Causal-Slash Protocol
 */
export const causalSlashPlugin: Plugin = {
  name: "causal-slash",
  description:
    "Sovereign Machine-to-Machine (M2M) micro-payment clearing and streaming compute settlement on Base L2.",
  actions: [
    streamTokenSettlementAction,
    getChannelBalanceAction
  ],
  providers: [
    cslsCollateralProvider
  ],
  services: [
    CausalSettlementService
  ]
};

export default causalSlashPlugin;
