# SPDX-License-Identifier: Apache-2.0
"""
RED TEAM (Terminal 3): Kirchhoff Conservation attacks on sdk/debt_cycle_mesh.py.

Threat model: an adversarial participant (or adversarial input stream) tries to
(1) create or destroy value at boundary amounts (1-2 micro-USDC),
(2) abuse the 0.01% treasury commission rounding to mint or burn units,
(3) void the treasury commission by dragging fee obligations into the SCC
    netting fixpoint,
(4) break conservation with rejected/edge inputs (zero, negative, self-loop,
    overpayment, cheque replay/regression).

Zone compliance: sdk/ is imported read-only, never modified.
"""

import hashlib
import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(_ROOT, "sdk"))

import pytest

from debt_cycle_mesh import DebtCycleMesh, DebtCycleMeshError


def node(i: int) -> bytes:
    return b"\x02" + hashlib.sha256(f"rt_node_{i}".encode()).digest()[:32]


def net_sum(mesh: DebtCycleMesh) -> int:
    return sum(mesh.all_net_balances().values())


# ---------------------------------------------------------------------------
# M1. Conservation at boundary amounts
# ---------------------------------------------------------------------------

def test_m1_conservation_1_and_2_micro_cycles():
    """A 3-cycle of 1 micro each annihilates to zero without creating value."""
    m = DebtCycleMesh(treasury_node=node(99))
    a, b, c = node(1), node(2), node(3)
    m.add_obligation(a, b, 1)
    m.add_obligation(b, c, 1)
    m.add_obligation(c, a, 1)
    assert net_sum(m) == 0
    s = m.net_all()
    # 3 micro annihilated -> fee = 3 * 100 // 1_000_000 = 0 (floor).
    assert s.treasury_fee_micro == 0
    assert s.residual_volume_micro == 0
    assert all(v == 0 for v in m.all_net_balances().values())
    assert net_sum(m) == 0
    # Nobody was enriched: no settlements at all.
    assert m.generate_clearing_settlements() == []


def test_m1_conservation_mixed_boundary_amounts():
    """Cycle with edges 1, 2, 5: min-edge annihilation keeps balances fixed."""
    m = DebtCycleMesh()
    a, b, c = node(1), node(2), node(3)
    m.add_obligation(a, b, 1)
    m.add_obligation(b, c, 2)
    m.add_obligation(c, a, 5)
    before = m.all_net_balances()
    s = m.net_all()
    # Balances are preserved by annihilation (netting reallocates, never creates).
    assert m.all_net_balances() == before
    assert net_sum(m) == 0
    # balances: a: owed 5, owes 1 -> +4; b: owed 1, owes 2 -> -1; c: owed 2, owes 5 -> -3.
    # Minimal residual theorem: residual == sum(|net|)/2 == (4+1+3)/2 = 4.
    assert s.residual_volume_micro == 4
    assert s.annihilated_volume_micro == s.gross_volume_micro - s.residual_volume_micro
    assert s.treasury_fee_micro == 0


def test_m1_conservation_huge_amounts_no_overflow():
    """2**62-scale obligations conserve exactly (Python bigint domain)."""
    m = DebtCycleMesh()
    a, b, c = node(1), node(2), node(3)
    big = 2 ** 62
    m.add_obligation(a, b, big)
    m.add_obligation(b, c, big)
    m.add_obligation(c, a, big)
    s = m.net_all()
    assert net_sum(m) == 0
    assert s.residual_volume_micro == 0
    assert s.annihilated_volume_micro == 3 * big


# ---------------------------------------------------------------------------
# M2. 0.01% commission: exactness and rounding
# ---------------------------------------------------------------------------

def test_m2_fee_floor_and_remainder_never_creates_value():
    """fee = annihilated*100//1_000_000 (floor). A 3-cycle annihilates
    min_edge x 3 (every cycle edge is reduced), fee edges sum EXACTLY to it."""
    m = DebtCycleMesh(treasury_node=node(99))
    a, b, c = node(1), node(2), node(3)
    volume = 10_000_000  # annihilated = 3 x volume -> fee = 3000 micro
    m.add_obligation(a, b, volume)
    m.add_obligation(b, c, volume)
    m.add_obligation(c, a, volume)
    before_treasury = m.net_balance(node(99))
    s = m.net_all()
    assert s.treasury_fee_micro == 3000
    gained = m.net_balance(node(99)) - before_treasury
    # Treasury gained exactly the floor fee; participants owe exactly that sum.
    assert gained == 3000
    fee_edges = {k: v for k, v in m.edges.items() if k[1] == node(99)}
    assert sum(fee_edges.values()) == 3000
    assert net_sum(m) == 0


def test_m2_fee_below_one_micro_is_zero():
    """Annihilated volume 9998 micro (2-cycle x 4999) yields fee 0 (floor)."""
    m = DebtCycleMesh(treasury_node=node(99))
    a, b = node(1), node(2)
    m.add_obligation(a, b, 4999)
    m.add_obligation(b, a, 4999)  # 2-cycle, annihilated = 2 x 4999 = 9998
    s = m.net_all()
    assert s.treasury_fee_micro == 0
    assert m.net_balance(node(99)) == 0
    assert net_sum(m) == 0


def test_m2_fee_exact_at_threshold():
    """2-cycle annihilates 2V: V=499_999 -> 999_998 annihilated -> fee 99;
    V=500_000 -> 1_000_000 annihilated -> exactly 100 micro (0.01%)."""
    for volume, expected_fee in ((499_999, 99), (500_000, 100)):
        m = DebtCycleMesh(treasury_node=node(99))
        a, b = node(1), node(2)
        m.add_obligation(a, b, volume)
        m.add_obligation(b, a, volume)
        s = m.net_all()
        assert s.treasury_fee_micro == expected_fee
        assert m.net_balance(node(99)) == expected_fee
        assert net_sum(m) == 0


def test_m2_fee_remainder_split_exact():
    """divmod split: base*n + remainder == fee_total, unit-exact.
    3-cycle edge v=4_115_226 -> annihilated 12_345_678 -> fee 1234 = 412+411+411."""
    m = DebtCycleMesh(treasury_node=node(99))
    a, b, c = node(1), node(2), node(3)
    v = 12_345_678 // 3
    m.add_obligation(a, b, v)
    m.add_obligation(b, c, v)
    m.add_obligation(c, a, v)
    s = m.net_all()
    assert s.treasury_fee_micro == v * 3 * 100 // 1_000_000
    fee_edges = {k: val for k, val in m.edges.items() if k[1] == node(99)}
    assert sum(fee_edges.values()) == s.treasury_fee_micro
    assert net_sum(m) == 0


# ---------------------------------------------------------------------------
# M3. Commission leakage: fee obligations dragged into the SCC fixpoint
# ---------------------------------------------------------------------------

def test_m3_treasury_commercial_debt_nets_away_the_fee():
    """
    FINDING (documented): if the treasury node has commercial obligations to
    fee payers, the fee edges enter the same SCC netting fixpoint and are
    annihilated against real debt. Kirchhoff conservation HOLDS (no unit is
    created or destroyed) but the protocol's 0.01% commission revenue is
    voided for the overlapping nodes. Treasury's real creditors get paid less.
    """
    m = DebtCycleMesh(treasury_node=node(99))
    a, b, c = node(1), node(2), node(3)
    t = node(99)
    volume = 10_000_000  # annihilated 3 x volume -> fee 3000 (1000 per node)
    # Commercial mesh: cycle a->b->c->a plus treasury buying from all three.
    m.add_obligation(a, b, volume)
    m.add_obligation(b, c, volume)
    m.add_obligation(c, a, volume)
    m.add_obligation(t, a, volume)
    m.add_obligation(t, b, volume)
    m.add_obligation(t, c, volume)
    s = m.net_all()
    assert net_sum(m) == 0  # conservation never breaks
    fee_edges = {k: v for k, v in m.edges.items() if k[1] == t}
    # LEAKED: every fee edge was annihilated against treasury's real debt.
    assert sum(fee_edges.values()) == 0
    # The counter claims 3000 was collected, but the treasury's net position
    # shows zero commission retained: its real debts were reduced by the fee.
    assert s.treasury_fee_micro == 3000
    assert m.net_balance(t) == -(3 * volume - 3000)  # real debts minus refunded fee
    # Money did not vanish: the 3000 stayed with participants (their debt to
    # the treasury is smaller). Conservation + fee-voiding, exactly as analyzed.


def test_m3_fee_survives_when_treasury_is_not_a_counterparty():
    """Control group: without commercial overlap the fee is fully retained."""
    m = DebtCycleMesh(treasury_node=node(99))
    a, b, c = node(1), node(2), node(3)
    t = node(99)
    m.add_obligation(a, b, 10_000_000)
    m.add_obligation(b, c, 10_000_000)
    m.add_obligation(c, a, 10_000_000)
    s = m.net_all()
    assert m.net_balance(t) == 3000
    assert {k: v for k, v in m.edges.items() if k[1] == t} != {}
    assert s.treasury_fee_micro == 3000


# ---------------------------------------------------------------------------
# M4. Input validation and replay/regression of cheque records
# ---------------------------------------------------------------------------

def test_m4_obligation_validation_rejects_adversarial_input():
    m = DebtCycleMesh()
    a, b = node(1), node(2)
    with pytest.raises(DebtCycleMeshError):
        m.add_obligation(a, b, 0)
    with pytest.raises(DebtCycleMeshError):
        m.add_obligation(a, b, -5)
    with pytest.raises(DebtCycleMeshError):
        m.add_obligation(a, a, 10)  # self-obligation
    m.add_obligation(a, b, 10)
    with pytest.raises(DebtCycleMeshError):
        m.clear_edge(a, b, 11)  # overpayment
    # State untouched by every rejected call.
    assert net_sum(m) == 0
    assert m.total_system_debt() == 10


def test_m4_record_cheque_replay_and_regression_ignored():
    """Cumulative per (agent, vendor): replay adds nothing, regression adds
    nothing negative, honest progress adds the exact delta."""
    m = DebtCycleMesh()
    a, v = node(1), node(2)

    class Cheque:
        def __init__(self, pk_agent, pk_vendor, cum):
            self.agent_pk = pk_agent
            self.vendor_pk = pk_vendor
            self.cumulative_amt = cum

    m.record_cheque(Cheque(a, v, 100))
    m.record_cheque(Cheque(a, v, 100))  # replay
    m.record_cheque(Cheque(a, v, 50))   # regression attempt
    assert m.total_system_debt() == 100
    m.record_cheque(Cheque(a, v, 130))  # honest progress
    assert m.total_system_debt() == 130
    assert net_sum(m) == 0


# ---------------------------------------------------------------------------
# M5. Minimality of the residual fixpoint
# ---------------------------------------------------------------------------

def test_m5_residual_equals_sum_abs_net_over_two():
    """After net_all the graph is the provable minimum settlement set."""
    m = DebtCycleMesh()
    a, b, c, d = node(1), node(2), node(3), node(4)
    m.add_obligation(a, b, 700)
    m.add_obligation(b, c, 300)
    m.add_obligation(c, a, 900)   # cycle a->b->c->a
    m.add_obligation(d, a, 50)    # tail (no cycle)
    s = m.net_all()
    balances = m.all_net_balances()
    minimal = sum(abs(x) for x in balances.values()) // 2
    assert s.residual_volume_micro == minimal
    assert net_sum(m) == 0
    # Every residual edge is debtor->creditor only (DAG fixpoint).
    for (payer, payee), amount in m.edges.items():
        assert m.net_balance(payer) < 0
        assert m.net_balance(payee) > 0
        assert amount > 0
