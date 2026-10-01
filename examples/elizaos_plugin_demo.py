#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Causal-Slash Protocol: ElizaOS Plugin Runtime Demo.

Runs a real embedded action-registry runtime (ElizaOS-shaped) on top of the
CausalAgentKit adapter. Every agent turn executes REAL 151-byte EOTS cheques
through the native C11 engine - no mocks, no external network, no LLM calls
(the turn policy is scripted and honestly labeled as such).

Highlights:
  1. Provider registration (LLM / VectorDB / WebScraper vendor nodes).
  2. 14 autonomous turns: compute purchases + provider commission payouts.
  3. reconcile_mesh_debt(): Kirchhoff netting with the 0.01% treasury fee.
  4. Third-party one-liner integration (from_bond + one payment).
  5. Plugin manifest export (JSON) for TS runtime binding.
"""

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(_ROOT, "sdk"))

from causal_slash import CausalVendorNode                    # noqa: E402
from causal_agentkit import CausalAgentKit                   # noqa: E402


class ElizaOSActionRegistry:
    """
    Minimal ElizaOS-shaped runtime: actions are bound by NAME to kit methods
    exactly as a TypeScript runtime would bind the exported manifest.
    """

    def __init__(self, kit: CausalAgentKit):
        self.kit = kit
        self._bindings = {
            "stream_micropayment": kit.stream_micropayment,
            "reconcile_mesh_debt": kit.reconcile_mesh_debt,
            "get_channel_balance": kit.get_channel_balance,
        }

    def execute(self, action_name: str, params: dict) -> dict:
        handler = self._bindings.get(action_name)
        if handler is None:
            raise ValueError(f"unknown action '{action_name}'")
        return handler(**params)


def main() -> None:
    print("=" * 78)
    print("CAUSAL-SLASH: ELIZAOS PLUGIN RUNTIME (real engine, scripted policy)")
    print("=" * 78)

    kit = CausalAgentKit.from_bond(bond_usdc=25.0, kit_label="elizaos-demo")
    print(f"[kit] agent identity : {kit.master.public_key_hex[:26]}...")
    print(f"[kit] master bond    : ${kit.bond_micro / 1e6:.2f} USDC on Base L2")
    print(f"[kit] prepay needed  : $0.00 (single bond covers every vendor)")

    providers = {
        "llm": CausalVendorNode(delta_v_usdc=5.0),
        "vectordb": CausalVendorNode(delta_v_usdc=5.0),
        "scraper": CausalVendorNode(delta_v_usdc=5.0),
    }
    for name, node in providers.items():
        pk = kit.register_provider(name, node)
        print(f"[provider] {name:<10} registered: {pk.hex()[:20]}...")

    registry = ElizaOSActionRegistry(kit)

    # ---- scripted policy: 14 autonomous turns (no external LLM involved) ----
    print("\n[runtime] executing 14 agent turns (scripted policy, real cheques):")
    turns = (
        [("stream_micropayment", {"vendor_pk": providers["llm"].public_key,
                                  "amount_usdc": 0.0001, "purpose": "llm.inference"})] * 6
        + [("stream_micropayment", {"vendor_pk": providers["vectordb"].public_key,
                                    "amount_usdc": 0.0020, "purpose": "vector.query"})] * 3
        + [("stream_micropayment", {"vendor_pk": providers["scraper"].public_key,
                                    "amount_usdc": 0.0050, "purpose": "web.scrape"})] * 2
    )
    for i, (action, params) in enumerate(turns, 1):
        receipt = registry.execute(action, params)
        assert receipt["status"] == "settled" and receipt["gas_paid"] == 0
        print(f"  turn {i:>2}: {params['purpose']:<14} h={receipt['height']:<4} "
              f"cum={receipt['cumulative_micro']} micro | gas 0")

    # Providers push commissions back -> mutual debts appear.
    print("\n[runtime] provider commission payouts (mutual debt creation):")
    for name, amount in (("llm", 0.0030), ("vectordb", 0.0020), ("scraper", 0.0010)):
        receipt = kit.provider_payout(name, amount)
        print(f"  {name:<10} paid ${amount:.4f} commission, h={receipt['height']}")

    # ---- Kirchhoff reconciliation ----
    print("\n[runtime] reconcile_mesh_debt():")
    report = registry.execute("reconcile_mesh_debt", {})
    s = report["summary"]
    print(f"  gross volume    : ${s.gross_volume_micro / 1e6:.6f}")
    print(f"  residual volume : ${s.residual_volume_micro / 1e6:.6f}")
    print(f"  compression     : {s.compression_ratio:.4%}")
    print(f"  cycles resolved : {s.cycles_resolved}")
    print(f"  treasury fee    : ${report['treasury_fee_micro'] / 1e6:.6f} (0.01%)")
    assert report["commercial_residual_micro"] == 0, "ledger did not close"

    for name in providers:
        bal = registry.execute("get_channel_balance",
                               {"vendor_pk": providers[name].public_key})
        print(f"  channel {name:<10}: paid={bal['paid_micro']} micro, "
              f"received={bal['received_micro']} micro, net={bal['net_micro']} micro")

    # ---- third-party one-liner integration ----
    print("\n[3rd-party] ONE-LINE integration by an external agent:")
    print("  >>> kit = CausalAgentKit.from_bond(bond_usdc=10.0)")
    print("  >>> kit.stream_micropayment(vendor_pk, 0.0001, 'llm.inference')")
    external = CausalAgentKit.from_bond(bond_usdc=10.0, kit_label="3rd-party")
    ext_vendor = CausalVendorNode(delta_v_usdc=5.0)
    external.register_provider("llm", ext_vendor)
    ext_receipt = external.stream_micropayment(ext_vendor.public_key, 0.0001,
                                               "llm.inference")
    assert ext_receipt["status"] == "settled"
    print(f"  external agent settled its first LLM cheque at h={ext_receipt['height']} "
          f"(cum {ext_receipt['cumulative_micro']} micro, 0 gas, 0 prepay)")

    # ---- pending-relay path: remote vendor not running locally ----
    remote_pk = b"\x02" + b"\x77" * 32
    queued = kit.stream_micropayment(remote_pk, 0.0010, "remote.api")
    assert queued["pending"] and queued["status"] == "queued_for_relay"
    print(f"\n[relay] remote vendor cheque queued offline-signed "
          f"(h={queued['height']}, {len(kit._channels[remote_pk].pending)} pending)")

    # ---- manifest export ----
    manifest = kit.manifest_json()
    import json as _json
    _json.loads(manifest)  # must be valid JSON for TS runtimes
    print("\n[manifest] ElizaOS/AgentKit plugin manifest (JSON-validated):")
    print("\n".join("  " + ln for ln in manifest.splitlines()[:14]))
    print("  ...")

    print("\n" + "=" * 78)
    print("ELIZAOS PLUGIN DEMO COMPLETE - all turns settled with real EOTS cheques")
    print("=" * 78)


if __name__ == "__main__":
    main()
