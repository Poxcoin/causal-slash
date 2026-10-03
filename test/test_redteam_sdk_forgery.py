# SPDX-License-Identifier: Apache-2.0
"""
BLUE TEAM remediation gate (V4): SDK default-configuration forgery campaign.

Threat model: csls_vendor_process_common verifies the challenge scalar e
(SHA256 preimage binding) but NEVER verifies the signature scalar sig_s
against the agent public key (no R-point exists on the 151-byte wire).
Without the Session MAC gate, nodes accept arbitrary garbage in sig_s,
enabling full impersonation of any agent from public data alone.

Remediation verified below:
  R1  a cheque whose sig_s is random garbage is REJECTED by a default vendor
      with BAD_MAC (-24): the Session MAC gate is ON by default;
  R2  a FULLY FABRICATED cheque for a public key whose secret key nobody
      holds is REJECTED: impersonation from public data alone is dead;
  R3  a forged cumulative cannot brick a real agent's channel: the forgery
      is rejected and the victim's honest payments keep flowing;
  R4  control: an honest authenticated (167-byte MAC) cheque is still
      accepted by a default vendor - the gate blocks only forgeries;
  R5  the legacy 151-byte path survives as a deliberate, explicit opt-out
      (enforce_mac=False) and documents the residual legacy exposure.

Zone compliance: sdk/ is imported read-only by this file; the secure
defaults themselves live in sdk/causal_slash.py and src/causal_daemon.c.
"""

import hashlib
import os
import struct
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(_ROOT, "sdk"))

from causal_slash import CausalAgentWallet, CausalVendorNode

CSLS_MAGIC = 0x43534C53
PKT_CHEQUE = 0x01


def make_node(i: int) -> bytes:
    return b"\x02" + hashlib.sha256(f"rt_forgery_{i}".encode()).digest()[:32]


def fabricate_cheque(agent_pk: bytes, vendor_pk: bytes, height: int, cumulative: int) -> bytes:
    """Builds a 151-byte wire cheque WITHOUT any secret key material.
    e is the honestly computed challenge (public data only); sig_s is noise."""
    preimage = (
        agent_pk + vendor_pk + struct.pack(">Q", height) + struct.pack(">Q", cumulative)
    )
    challenge_e = hashlib.sha256(preimage).digest()
    pkt = (
        struct.pack("<I", CSLS_MAGIC)
        + bytes([PKT_CHEQUE])
        + agent_pk
        + vendor_pk
        + struct.pack("<Q", height)
        + struct.pack("<Q", cumulative)
        + challenge_e
        + b"\x77" * 32  # garbage signature scalar
    )
    assert len(pkt) == 151
    return pkt


def test_r0_secure_default_is_enforced():
    """The SDK must ship CausalVendorNode with Session MAC enforcement ON."""
    node = CausalVendorNode(secret_key=b"\x44" * 32)
    try:
        assert node._enforce_mac is True, (
            "V4 regression: CausalVendorNode must mandate Session MAC by default"
        )
    finally:
        node.close()


def test_r1_default_vendor_rejects_garbage_signature():
    """Corrupting ONLY the sig_s field (or building a fresh cheque from public
    data with a noise scalar) must die at the Session MAC gate on a default
    vendor. The agent's key never touches the forged packet."""
    vendor = CausalVendorNode(secret_key=b"\x44" * 32, delta_v_usdc=50.0)
    agent = CausalAgentWallet(secret_key=b"\x33" * 32)
    assert vendor.init_session(agent.create_session(vendor.public_key))
    cheque = agent.sign_cheque(vendor.public_key, 0.01, session_mac=True)  # $0.01 honest cheque
    raw = bytearray(bytes(cheque.raw_packet[:151]))
    assert len(raw) == 151

    # honest authenticated cheque settles
    res = vendor.process_cheque(bytes(cheque.raw_packet))
    assert res.accepted is True

    # attack: a NEW cheque at the next height, built ONLY from public data
    # (agent_pk, vendor_pk, height+1, new cumulative, e = SHA256(preimage))
    # with a garbage sig_s and NO session MAC. (Mutating the SAME cheque's
    # sig_s would be a history replay: same height, same e.)
    height0 = int.from_bytes(raw[71:79], "little")  # wire is little-endian
    cum0 = int.from_bytes(raw[79:87], "little")
    forged = fabricate_cheque(bytes(raw[5:38]), vendor.public_key,
                              height0 + 1, cum0 + 10_000)
    res = vendor.process_cheque(forged)
    assert res.accepted is False, (
        "V4 regression: default vendor accepted a garbage signature "
        f"(status={res.status_code})"
    )
    assert res.status_code == -24, f"expected -24 BAD_MAC, got {res.status_code}"
    vendor.close()
    agent.close()


def test_r2_full_impersonation_without_any_secret_key_rejected():
    """A cheque for an agent whose secret key DOES NOT EXIST anywhere is
    rejected from public data alone. No key material was used."""
    vendor = CausalVendorNode(secret_key=b"\x44" * 32, delta_v_usdc=50.0)
    ghost_pk = make_node(666)  # ghost agent, no secret key ever existed
    vendor_pk = vendor.public_key
    forged = fabricate_cheque(ghost_pk, vendor_pk, height=1, cumulative=250_000)  # $0.25

    res = vendor.process_cheque(forged)
    assert res.accepted is False, f"V4 regression: impersonation accepted (status={res.status_code})"
    assert res.status_code == -24, f"expected -24 BAD_MAC, got {res.status_code}"
    assert vendor.get_channel_accumulated(ghost_pk) == 0, "ghost channel must stay empty"
    vendor.close()


def test_r3_forged_cumulative_cannot_brick_real_agent_channel():
    """A forged high cumulative is rejected, so the real agent's honest
    payments keep flowing: the vendor channel cannot be frozen for the victim
    by an attacker without key material."""
    vendor = CausalVendorNode(secret_key=b"\x44" * 32, delta_v_usdc=1.0)  # $1 buffer
    victim = CausalAgentWallet(secret_key=b"\x33" * 32)
    vendor_pk = vendor.public_key
    assert vendor.init_session(victim.create_session(vendor_pk))

    # attacker (no key material) fires a forged $0.90 cheque at height 2**32
    forged = fabricate_cheque(victim.public_key, vendor_pk, height=2**32, cumulative=900_000)
    res = vendor.process_cheque(forged)
    assert res.accepted is False, f"V4 regression: forged cumulative accepted (status={res.status_code})"
    assert res.status_code == -24, f"expected -24 BAD_MAC, got {res.status_code}"

    # the victim's honest payments are unaffected: the channel is alive
    cheque = victim.sign_cheque(vendor_pk, 0.01, session_mac=True)
    res = vendor.process_cheque(bytes(cheque.raw_packet))
    assert res.accepted is True, f"honest payment must flow, got {res.status_code}"
    cheque = victim.sign_cheque(vendor_pk, 0.5, session_mac=True)
    res = vendor.process_cheque(bytes(cheque.raw_packet))
    assert res.accepted is True, f"honest payment must flow, got {res.status_code}"
    vendor.close()
    victim.close()


def test_r4_honest_authenticated_cheque_accepted_by_default_vendor():
    """Control: an honest 167-byte Session MAC cheque is accepted by a default
    vendor. The gate blocks forgeries, never authenticated traffic."""
    vendor = CausalVendorNode(secret_key=b"\x44" * 32, delta_v_usdc=50.0)
    agent = CausalAgentWallet(secret_key=b"\x33" * 32)
    assert vendor.init_session(agent.create_session(vendor.public_key))

    for _ in range(3):
        cheque = agent.sign_cheque(vendor.public_key, 0.01, session_mac=True)
        assert len(cheque.raw_packet) == 167
        res = vendor.process_cheque(bytes(cheque.raw_packet))
        assert res.accepted is True, f"honest MAC cheque rejected: {res.error_message}"
    assert vendor.get_channel_accumulated(agent.public_key) == 30_000
    vendor.close()
    agent.close()


def test_r5_legacy_path_requires_explicit_opt_out():
    """Documenting the residual legacy exposure: with an EXPLICIT
    enforce_mac=False opt-out the legacy 151-byte wire behaves exactly as
    before (the unauthenticated forgery is accepted). The insecure mode can
    no longer be reached by default."""
    vendor = CausalVendorNode(secret_key=b"\x44" * 32, delta_v_usdc=50.0, enforce_mac=False)
    ghost_pk = make_node(777)
    forged = fabricate_cheque(ghost_pk, vendor.public_key, height=1, cumulative=250_000)
    res = vendor.process_cheque(forged)
    assert res.accepted is True, "legacy opt-out must keep legacy semantics"
    assert vendor.get_channel_accumulated(ghost_pk) == 250_000

    # and the C2 gate can be re-armed at runtime on the same node.
    vendor.enable_mac(True)
    forged2 = fabricate_cheque(make_node(778), vendor.public_key, height=1, cumulative=250_000)
    res = vendor.process_cheque(forged2)
    assert res.accepted is False and res.status_code == -24
    vendor.close()
