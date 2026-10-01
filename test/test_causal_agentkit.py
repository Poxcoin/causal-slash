# SPDX-License-Identifier: Apache-2.0
import json
import os
import sys

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_TEST_DIR)
sys.path.insert(0, os.path.join(_PROJECT_ROOT, "sdk"))

from causal_slash import CausalVendorNode          # noqa: E402
from causal_agentkit import CausalAgentKit         # noqa: E402


def _kit_with_providers():
    kit = CausalAgentKit.from_bond(bond_usdc=25.0, swarm_seed=b"\xA7" * 32,
                                   kit_label="pytest")
    llm = CausalVendorNode(secret_key=b"\x11" * 32, delta_v_usdc=5.0)
    vec = CausalVendorNode(secret_key=b"\x22" * 32, delta_v_usdc=5.0)
    kit.register_provider("llm", llm)
    kit.register_provider("vectordb", vec)
    return kit, llm, vec


def test_stream_micropayment_settles_and_tracks_exact_balances():
    kit, llm, vec = _kit_with_providers()
    for _ in range(5):
        r = kit.stream_micropayment(llm.public_key, 0.0001, "llm.inference")
        assert r["status"] == "settled" and r["gas_paid"] == 0
    r = kit.stream_micropayment(vec.public_key, 0.0020, "vector.query")
    assert r["status"] == "settled"

    bal = kit.get_channel_balance(llm.public_key)
    assert bal["paid_micro"] == 500 and bal["received_micro"] == 0
    assert bal["outstanding_micro"] == 500
    assert bal["cheques_sent"] == 5 and bal["last_height"] == 5
    bal2 = kit.get_channel_balance(vec.public_key)
    assert bal2["paid_micro"] == 2000 and bal2["last_height"] == 6


def test_provider_payout_creates_mutual_debt_and_reconcile_closes_ledger():
    kit, llm, vec = _kit_with_providers()
    for _ in range(4):
        kit.stream_micropayment(llm.public_key, 0.0001, "llm.inference")   # 400
    receipt = kit.provider_payout("llm", 0.0030)                            # 3000 back
    assert receipt["status"] == "settled"

    bal = kit.get_channel_balance(llm.public_key)
    assert bal["paid_micro"] == 400 and bal["received_micro"] == 3000
    assert bal["outstanding_micro"] == -2600

    report = kit.reconcile_mesh_debt()
    assert report["settlements_executed"] >= 1
    assert report["commercial_residual_micro"] == 0, "ledger must close exactly"
    # Netted volume = min(400, 3000) = 400 micro -> fee floors to 0 at this scale.
    assert report["netting_volume_micro"] == 400
    assert report["treasury_fee_micro"] == 400 * 100 // 1_000_000
    # Repeated reconcile must NOT double-book the treasury fee.
    fee_once = report["treasury_fee_micro"]
    report2 = kit.reconcile_mesh_debt()
    assert report2["treasury_fee_micro"] == fee_once
    assert report2["settlements_executed"] == 0
    # After reconciliation the channel net is settled: outstanding == 0.
    assert kit.get_channel_balance(llm.public_key)["outstanding_micro"] == 0


def test_pending_relay_path_queues_real_signed_cheque():
    kit, llm, _ = _kit_with_providers()
    remote_pk = b"\x02" + b"\x77" * 32
    r = kit.stream_micropayment(remote_pk, 0.0010, "remote.api")
    assert r["pending"] is True and r["status"] == "queued_for_relay"
    bal = kit.get_channel_balance(remote_pk)
    assert bal["pending_count"] == 1
    raw = kit._channels[remote_pk].pending[0]
    # magic must be the CSLS u32LE constant and the packet must be well-formed
    assert len(raw) == 151
    assert int.from_bytes(raw[:4], "little") == 0x43534C53
    assert raw[4] == 0x01
    assert raw[5:38] == kit.master.public_key


def test_manifest_is_json_serializable_and_binds_methods():
    kit, _, _ = _kit_with_providers()
    manifest = kit.to_manifest()
    parsed = json.loads(kit.manifest_json())
    assert parsed["name"] == "causal-slash-agentkit" and parsed["chain"] == "base"
    names = {a["name"] for a in manifest["actions"]}
    assert names == {"stream_micropayment", "reconcile_mesh_debt", "get_channel_balance"}
    for action in manifest["actions"]:
        assert callable(getattr(kit, action["handler"]))
        assert "properties" in action["parameters"] or action["parameters"].get("type")


def test_from_bond_one_liner_end_to_end():
    kit = CausalAgentKit.from_bond(bond_usdc=10.0, swarm_seed=b"\xBB" * 32)
    vendor = CausalVendorNode(secret_key=b"\x33" * 32, delta_v_usdc=5.0)
    kit.register_provider("llm", vendor)
    r = kit.stream_micropayment(vendor.public_key, 0.0001, "llm.inference")
    assert r["status"] == "settled" and r["height"] == 1
    assert kit.get_channel_balance(vendor.public_key)["paid_micro"] == 100
