// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

export * from "./types";
export * from "./crypto";
export * from "./remoteInference";
export * from "./actionProvider";
export * from "./vendorNode";

import { CausalSlashActionProvider, CausalSlashActionProviderOptions } from "./actionProvider";

/**
 * Factory helper for initializing CausalSlashActionProvider in Coinbase AgentKit
 */
export function causalSlashActionProvider(
  options?: CausalSlashActionProviderOptions
): CausalSlashActionProvider {
  return new CausalSlashActionProvider(options);
}

export default CausalSlashActionProvider;
