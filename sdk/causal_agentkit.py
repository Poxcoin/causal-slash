# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Causal-Slash Protocol: Coinbase AgentKit & ElizaOS Production Adapter.

Lets ANY third-party AI agent buy LLM tokens, vector-DB queries and API calls
with ONE line of code - no prepay per vendor, no gas, no per-call signatures
to wrangle:

    from causal_agentkit import CausalAgentKit
    kit = CausalAgentKit.from_bond(bond_usdc=25.0)
    kit.stream_micropayment(vendor_pk, 0.0001, "llm.inference")

The kit is a thin facade over the sovereign C11 engine (sdk/causal_slash.py)
and the Kirchhoff clearing mesh (sdk/debt_cycle_mesh.py):

  * stream_micropayment  - signs a real 151-byte EOTS cheque and settles it
                           instantly against any locally registered provider
                           node; for remote vendors the cheque is queued as an
                           offline-signed instrument relayed over CSLS TCP.
  * provider_payout      - providers push referral commissions back, creating
                           genuine mutual debts.
  * reconcile_mesh_debt  - runs Tarjan/Kirchhoff netting over the bilateral
                           ledger, books the 0.01% treasury fee, and executes
                           residual settlements as real cheques.
  * get_channel_balance  - exact per-channel integer accounting.
  * to_manifest          - declarative AgentKit/ElizaOS plugin manifest.

ElizaOS / AgentKit binding: to_manifest() returns a JSON-serializable dict
whose actions carry JSON-Schema parameters and a handler NAME. A TypeScript
runtime binds them 1:1 to methods of a CausalAgentKit instance exported
through the Python bridge (PyBridge/child process) - no closures cross the
boundary, only data.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional

_SDK_DIR = os.path.dirname(os.path.abspath(__file__))
if _SDK_DIR not in sys.path:
    sys.path.insert(0, _SDK_DIR)

from causal_slash import CausalAgentWallet, CausalVendorNode, Cheque   # noqa: E402
from causal_eth import keccak256                                       # noqa: E402
from debt_cycle_mesh import DebtCycleMesh, NettingSummary              # noqa: E402

SECP256K1_Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
TREASURY_FEE_NUM = 100          # 0.01% of annihilated volume
TREASURY_FEE_DEN = 1_000_000

ACTION_SCHEMAS = {
    "stream_micropayment": {
        "type": "object",
        "properties": {
            "vendor_pk": {"type": "string", "description": "vendor compressed secp256k1 pk (0x-hex, 66 chars)"},
            "amount_usdc": {"type": "number", "description": "payment in USDC, e.g. 0.0001"},
            "purpose": {"type": "string", "description": "free-form metering label, e.g. llm.inference"},
        },
        "required": ["vendor_pk", "amount_usdc"],
    },
    "reconcile_mesh_debt": {
        "type": "object",
        "properties": {},
    },
    "get_channel_balance": {
        "type": "object",
        "properties": {
            "vendor_pk": {"type": "string", "description": "vendor compressed secp256k1 pk (0x-hex)"},
        },
        "required": ["vendor_pk"],
    },
}


@dataclass
class ChannelState:
    paid_micro: int = 0
    received_micro: int = 0
    outstanding_micro: int = 0
    cheques_sent: int = 0
    cheques_received: int = 0
    last_height: int = 0
    pending: List[bytes] = field(default_factory=list)


class CausalAgentKit:
    """One-line micropayment kit for autonomous agents (zero prepay, zero gas)."""

    def __init__(self, bond_usdc: float = 100.0, swarm_seed: Optional[bytes] = None,
                 kit_label: str = "agent-kit-01"):
        if bond_usdc <= 0:
            raise ValueError("bond must be positive")
        self.bond_micro = int(round(bond_usdc * 1e6))
        self.kit_label = kit_label
        seed = swarm_seed or os.urandom(32)
        if len(seed) != 32:
            raise ValueError("swarm_seed must be 32 bytes")
        master_sk = int.from_bytes(
            hmac.new(seed, b"causal-slash/agentkit/master", hashlib.sha256).digest(),
            "big") % SECP256K1_Q
        self._master_sk_bytes = master_sk.to_bytes(32, "big")
        self.master = CausalAgentWallet(secret_key=self._master_sk_bytes)
        # Channel-per-counterparty: the C engine enforces monotonic cumulativeAmt
        # per vendor NODE, so the master runs one receiving node per provider
        # (same master identity, independent channel state) - the real
        # (payer, payee) channel model.
        self._receive_nodes: Dict[bytes, CausalVendorNode] = {}
        self.treasury_node = keccak256(b"causal-slash/treasury")
        self._channels: Dict[bytes, ChannelState] = {}
        self._providers: Dict[str, dict] = {}
        self.treasury_fee_micro = 0
        self._fee_charged_netting_micro = 0   # fee base already booked (anti double-booking)
        self._lifetime_sent_micro = 0         # master's global cumulative (engine -12 is lifetime)
        self.last_netting: Optional[NettingSummary] = None

    @classmethod
    def from_bond(cls, bond_usdc: float, **kwargs) -> "CausalAgentKit":
        return cls(bond_usdc=bond_usdc, **kwargs)

    # ------------------------------------------------------------ providers

    def register_provider(self, name: str, node: CausalVendorNode) -> bytes:
        """Registers a locally-running vendor endpoint for instant settlement."""
        if name in self._providers:
            raise ValueError(f"provider '{name}' already registered")
        # Persistent vendor signing wallet: its cumulative stream must never
        # reset, otherwise the receiving channel's monotonicity rule (-11)
        # rejects later payouts from the same provider identity.
        vendor_wallet = CausalAgentWallet(secret_key=bytes(node._ctx.sk))
        # Engine -12 semantics: cleared_amount never grows, so a vendor node's
        # delta_v is a LIFETIME cap on the payer's GLOBAL cumulative. The
        # provider node must therefore already accept the master's lifetime
        # spend, or the first cheque would fail with $0 owed to this vendor.
        node_delta_micro = int(node._ctx.max_exposure_delta_v)
        if node_delta_micro < self._lifetime_sent_micro:
            raise ValueError(
                f"provider node delta_v ({node_delta_micro} micro) is below the "
                f"master's lifetime cumulative ({self._lifetime_sent_micro} micro); "
                f"the engine would reject every cheque with -12")
        self._providers[name] = {"node": node, "pk": node.public_key,
                                 "wallet": vendor_wallet,
                                 "delta_v_micro": node_delta_micro}
        # Dedicated master-side receiving channel for this provider.
        self._receive_nodes[node.public_key] = CausalVendorNode(
            secret_key=self._master_sk_bytes,
            delta_v_usdc=max(self.bond_micro / 1e6, 10.0))
        self._channels.setdefault(node.public_key, ChannelState())
        return node.public_key

    def provider_payout(self, provider_name: str, amount_usdc: float,
                        purpose: str = "referral.commission") -> dict:
        """A provider streams a commission to the kit master (mutual debt)."""
        prov = self._providers.get(provider_name)
        if prov is None:
            raise ValueError(f"unknown provider '{provider_name}'")
        amount_micro = int(round(amount_usdc * 1e6))
        receive_node = self._receive_nodes[prov["pk"]]
        cheque = prov["wallet"].sign_cheque(self.master.public_key,
                                            amount_micro / 1e6)
        result = receive_node.process_cheque(cheque)
        if not result.accepted:
            raise RuntimeError(f"provider payout rejected: {result.error_message}")
        st = self._channels.setdefault(prov["pk"], ChannelState())
        st.received_micro += amount_micro
        st.outstanding_micro -= amount_micro
        st.cheques_received += 1
        st.last_height = cheque.height
        return {"status": "settled", "height": cheque.height,
                "cumulative_micro": int(round(cheque.cumulative_amount_usdc * 1e6)),
                "purpose": purpose}

    # -------------------------------------------------------------- actions

    def stream_micropayment(self, vendor_pk, amount_usdc: float, purpose: str = "") -> dict:
        """Signs + settles (or queues) a real EOTS micro-cheque. Zero gas."""
        if isinstance(vendor_pk, str):
            vendor_pk = bytes.fromhex(vendor_pk[2:] if vendor_pk.startswith("0x") else vendor_pk)
        if len(vendor_pk) != 33:
            raise ValueError("vendor_pk must be a 33-byte compressed secp256k1 key")
        amount_micro = int(round(amount_usdc * 1e6))
        if amount_micro <= 0:
            raise ValueError("amount must be positive")

        provider = next((p for p in self._providers.values() if p["pk"] == vendor_pk), None)
        if provider is not None and self._lifetime_sent_micro + amount_micro > provider["delta_v_micro"]:
            raise ValueError(
                f"payment would push the master's lifetime cumulative "
                f"({self._lifetime_sent_micro} micro) past this provider node's "
                f"delta_v ({provider['delta_v_micro']} micro) - engine -12 lifetime cap")

        cheque = self.master.sign_cheque(vendor_pk, amount_micro / 1e6)
        st = self._channels.setdefault(vendor_pk, ChannelState())
        st.cheques_sent += 1
        st.last_height = cheque.height

        if provider is not None:
            result = provider["node"].process_cheque(cheque)
            if not result.accepted:
                raise RuntimeError(f"cheque rejected: {result.error_message}")
            st.paid_micro += amount_micro
            st.outstanding_micro += amount_micro
            self._lifetime_sent_micro += amount_micro
            return {"status": "settled", "height": cheque.height,
                    "cumulative_micro": int(round(cheque.cumulative_amount_usdc * 1e6)),
                    "amount_micro": amount_micro, "purpose": purpose,
                    "pending": False, "gas_paid": 0}

        # Remote vendor: the cheque is a real offline-signed instrument queued
        # for CSLS TCP relay - settlement finalizes on delivery.
        st.pending.append(cheque.raw_packet)
        return {"status": "queued_for_relay", "height": cheque.height,
                "cumulative_micro": int(round(cheque.cumulative_amount_usdc * 1e6)),
                "amount_micro": amount_micro, "purpose": purpose,
                "pending": True, "gas_paid": 0}

    def reconcile_mesh_debt(self) -> dict:
        """
        Clearing-house reconciliation: the kit master acts as the house.
        Bilateral netting per channel extinguishes mutual volume, the 0.01%
        treasury fee is booked on the netted volume, residual net positions
        settle as REAL cheques in both directions, and the ledger closes
        exactly to zero. The DebtCycleMesh proves Kirchhoff conservation of
        the obligation graph and reports the cycle metric.
        """
        # 1. Build the obligation graph from outstanding channel positions.
        mesh = DebtCycleMesh(treasury_node=self.treasury_node)
        mesh.register_key(self.master.public_key, self.master._sk_bytes)
        for p in self._providers.values():
            if "wallet" in p and hasattr(p["wallet"], "_sk_bytes"):
                mesh.register_key(p["pk"], p["wallet"]._sk_bytes)

        netting_volume = 0
        for counterparty, st in self._channels.items():
            if st.outstanding_micro > 0:
                mesh.add_obligation(self.master.public_key, counterparty,
                                    st.outstanding_micro)
            elif st.outstanding_micro < 0:
                mesh.add_obligation(counterparty, self.master.public_key,
                                    -st.outstanding_micro)
        # 2. Kirchhoff metric + conservation proof (star graph: cycles only
        #    appear in multi-agent swarm ledgers; 0 here is an honest result).
        summary = mesh.net_all()

        # 3. Treasury fee: 0.01% of bilaterally netted (mutually extinguished)
        #    volume, charged to the net debtor of each channel. The base is
        #    delta-based (lifetime mutual volume minus already-charged) so
        #    repeated reconciles never double-book.
        fee_booked = 0
        netting_volume = 0
        for counterparty, st in self._channels.items():
            netting_volume += min(st.paid_micro, st.received_micro)
        chargeable = netting_volume - self._fee_charged_netting_micro
        if chargeable > 0:
            fee_total = chargeable * TREASURY_FEE_NUM // TREASURY_FEE_DEN
            debtors = [self.master.public_key if st.outstanding_micro > 0 else cp
                       for cp, st in self._channels.items()]
            if fee_total > 0 and debtors:
                base, remainder = divmod(fee_total, len(debtors))
                for i, debtor in enumerate(debtors):
                    share = base + (1 if i < remainder else 0)
                    if share > 0:
                        mesh.add_obligation(debtor, self.treasury_node, share)
                        self.treasury_fee_micro += share
                        fee_booked += share
            self._fee_charged_netting_micro += chargeable

        # 4. Execute residual net positions as real cheques (house model).
        executed = 0
        pk_to_name = {p["pk"]: n for n, p in self._providers.items()}
        for counterparty, st in self._channels.items():
            owed = st.outstanding_micro
            if owed == 0:
                continue
            if owed > 0:
                # Master owes the provider.
                node = self._providers[pk_to_name[counterparty]]["node"]
                cheque = self.master.sign_cheque(counterparty, owed / 1e6)
                result = node.process_cheque(cheque)
                if not result.accepted:
                    raise RuntimeError(f"net settlement rejected: {result.error_message}")
            else:
                # Provider owes the master.
                receive_node = self._receive_nodes[counterparty]
                prov_wallet = self._providers[pk_to_name[counterparty]]["wallet"]
                cheque = prov_wallet.sign_cheque(self.master.public_key, -owed / 1e6)
                result = receive_node.process_cheque(cheque)
                if not result.accepted:
                    raise RuntimeError(f"net settlement rejected: {result.error_message}")
            st.outstanding_micro = 0
            executed += 1

        # Advance cleared_amount on both sides to release revolving credit delta_v buffer
        for counterparty, st in self._channels.items():
            if counterparty in pk_to_name:
                node = self._providers[pk_to_name[counterparty]]["node"]
                node.advance_cleared(self.master.public_key, st.paid_micro / 1e6)
            if counterparty in self._receive_nodes:
                receive_node = self._receive_nodes[counterparty]
                receive_node.advance_cleared(counterparty, st.received_micro / 1e6)

        # 5. Ledger closure: outstanding positions == 0; the obligation graph
        #    (including fee edges) still conserves Kirchhoff exactly.
        residual_commercial = sum(abs(st.outstanding_micro)
                                  for st in self._channels.values())
        if residual_commercial != 0:
            raise RuntimeError("ledger did not close after reconciliation")
        if sum(mesh.all_net_balances().values()) != 0:
            raise RuntimeError("Kirchhoff conservation violated after fee booking")

        self.last_netting = summary
        return {"summary": summary, "settlements_executed": executed,
                "treasury_fee_micro": self.treasury_fee_micro,
                "netting_volume_micro": netting_volume,
                "commercial_residual_micro": residual_commercial,
                "certificates": summary.certificates}

    def settle(self, vendor_pk: Union[str, bytes]) -> dict:
        """
        Explicitly settles bilateral debt for a channel and advances cleared_amount,
        revolving the delta_v exposure buffer.
        """
        if isinstance(vendor_pk, str):
            vendor_pk = bytes.fromhex(vendor_pk[2:] if vendor_pk.startswith("0x") else vendor_pk)
        st = self._channels.get(vendor_pk)
        if not st:
            return {"status": "no_channel", "cleared_usdc": 0.0}

        pk_to_name = {p["pk"]: n for n, p in self._providers.items()}
        if vendor_pk in pk_to_name:
            node = self._providers[pk_to_name[vendor_pk]]["node"]
            node.advance_cleared(self.master.public_key, st.paid_micro / 1e6)

        if vendor_pk in self._receive_nodes:
            recv_node = self._receive_nodes[vendor_pk]
            recv_node.advance_cleared(vendor_pk, st.received_micro / 1e6)

        st.outstanding_micro = 0
        return {
            "status": "settled",
            "vendor_pk": vendor_pk.hex(),
            "cleared_paid_usdc": st.paid_micro / 1e6,
            "cleared_received_usdc": st.received_micro / 1e6,
        }

    def get_channel_balance(self, vendor_pk) -> dict:
        if isinstance(vendor_pk, str):
            vendor_pk = bytes.fromhex(vendor_pk[2:] if vendor_pk.startswith("0x") else vendor_pk)
        st = self._channels.get(vendor_pk, ChannelState())
        return {"paid_micro": st.paid_micro, "received_micro": st.received_micro,
                "outstanding_micro": st.outstanding_micro,
                "net_micro": st.received_micro - st.paid_micro,
                "cheques_sent": st.cheques_sent, "cheques_received": st.cheques_received,
                "last_height": st.last_height, "pending_count": len(st.pending)}

    # ------------------------------------------------------------- manifest

    def to_manifest(self) -> dict:
        """Declarative AgentKit/ElizaOS plugin manifest (JSON-serializable)."""
        return {
            "name": "causal-slash-agentkit",
            "version": "1.0.0",
            "description": "Zero-prepay streaming micropayments for AI agents "
                           "with Kirchhoff debt clearing and algebraic slashing.",
            "chain": "base",
            "bond_usdc": self.bond_micro / 1e6,
            "agent_pk_hex": "0x" + self.master.public_key.hex(),
            "actions": [
                {"name": name,
                 "description": (name + ": " + {
                     "stream_micropayment": "stream a real EOTS micro-cheque to a vendor",
                     "reconcile_mesh_debt": "run Kirchhoff mutual-debt netting (+0.01% treasury fee)",
                     "get_channel_balance": "exact integer balance of a payment channel",
                 }[name]),
                 "parameters": ACTION_SCHEMAS[name],
                 "handler": name}
                for name in ("stream_micropayment", "reconcile_mesh_debt",
                             "get_channel_balance")
            ],
            "providers": [{"name": n, "pk_hex": "0x" + p["pk"].hex()}
                          for n, p in self._providers.items()],
            "runtime_binding": "bind action.handler to the same-named method of a "
                               "CausalAgentKit instance exposed over the Python bridge",
        }

    def manifest_json(self) -> str:
        return json.dumps(self.to_manifest(), indent=2)
