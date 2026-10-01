# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Causal-Slash Protocol: DebtCycleMesh - in-RAM mutual debt clearing engine.

Implements Kirchhoff-style current-law netting over a directed obligation
graph denominated in integer micro-USDC (6 decimals):

  1. Tarjan SCC detection (iterative, recursion-safe for large swarms).
  2. Cycle annihilation to fixpoint: every directed cycle found inside an SCC
     is reduced by its minimum edge (the "Kirchhoff loop rule"), destroying
     reciprocal volume without moving a single sat of collateral.
  3. Bilateral netting of remaining opposite-direction pairs.
  4. Protocol monetization: 0.01% of every annihilated volume is booked as a
     treasury obligation edge, so conservation (sum of net balances == 0)
     holds to the last micro-USDC at every step.

Invariants asserted by construction:
  * edges are strictly positive, no self-loops;
  * sum(net_balance) == 0 after every mutation;
  * the fixpoint graph is a DAG (no SCC of size >= 2 survives);
  * residuals are minimal: post-netting volume == sum(|net_balance|).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Set, Tuple

FEE_NUMERATOR = 100        # 0.01% == 100 ppm
FEE_DENOMINATOR = 1_000_000

EdgeKey = Tuple[bytes, bytes]


class DebtCycleMeshError(RuntimeError):
    pass


@dataclass
class NettingSummary:
    gross_volume_micro: int = 0
    residual_volume_micro: int = 0
    annihilated_volume_micro: int = 0
    cycles_resolved: int = 0
    edges_before: int = 0
    edges_after: int = 0
    treasury_fee_micro: int = 0
    conservation_ok: bool = True

    @property
    def compression_ratio(self) -> float:
        if self.gross_volume_micro <= 0:
            return 0.0
        return 1.0 - self.residual_volume_micro / self.gross_volume_micro


class DebtCycleMesh:
    """
    Directed IOU ledger with Kirchhoff cycle netting. Keys are opaque hashable
    node ids (caller convention: 33-byte compressed secp256k1 public keys);
    all amounts are non-negative integer micro-USDC.
    """

    def __init__(self, treasury_node: Optional[bytes] = None,
                 fee_numerator: int = FEE_NUMERATOR,
                 fee_denominator: int = FEE_DENOMINATOR):
        if fee_denominator <= 0 or fee_numerator < 0:
            raise ValueError("invalid fee configuration")
        self._edges: Dict[EdgeKey, int] = {}
        self._nodes: Set[bytes] = set()
        self._gross_volume = 0
        self._annihilated_volume = 0
        self._cycles_resolved = 0
        self._treasury_fee = 0
        self.treasury_node = bytes(treasury_node) if treasury_node is not None else None
        self._fee_num = fee_numerator
        self._fee_den = fee_denominator

    # ------------------------------------------------------------------ ledger

    @staticmethod
    def _key(payer: bytes, payee: bytes) -> EdgeKey:
        payer, payee = bytes(payer), bytes(payee)
        if payer == payee:
            raise DebtCycleMeshError("self-obligations are not allowed")
        return (payer, payee)

    def ensure_node(self, node: bytes) -> None:
        self._nodes.add(bytes(node))

    def add_obligation(self, payer: bytes, payee: bytes, amount_micro: int) -> None:
        """Records payer owes payee `amount_micro`. Positive edges only."""
        if amount_micro <= 0:
            raise DebtCycleMeshError(f"obligation must be positive, got {amount_micro}")
        key = self._key(payer, payee)
        self._edges[key] = self._edges.get(key, 0) + amount_micro
        self._gross_volume += amount_micro
        self._nodes.update(key)
        self._assert_conservation()

    def clear_edge(self, payer: bytes, payee: bytes, amount_micro: int) -> None:
        """Removes volume from an edge when a real settlement executes on-chain/off-chain."""
        key = self._key(payer, payee)
        remaining = self._edges.get(key, 0) - amount_micro
        if remaining < 0:
            raise DebtCycleMeshError(
                f"settlement {amount_micro} exceeds outstanding edge {self._edges.get(key, 0)}")
        self._edges[key] = remaining
        self._gross_volume -= amount_micro
        if remaining == 0:
            del self._edges[key]

    # ------------------------------------------------------------- queries

    @property
    def nodes(self) -> Set[bytes]:
        return set(self._nodes)

    @property
    def edges(self) -> Dict[EdgeKey, int]:
        return dict(self._edges)

    def active_edges_count(self) -> int:
        return len(self._edges)

    def total_system_debt(self) -> int:
        return sum(self._edges.values())

    def gross_volume(self) -> int:
        return self._gross_volume

    def net_balance(self, node: bytes) -> int:
        """receivables - payables (positive => the swarm owes this node)."""
        node = bytes(node)
        balance = 0
        for (payer, payee), amount in self._edges.items():
            if payee == node:
                balance += amount
            if payer == node:
                balance -= amount
        return balance

    def all_net_balances(self) -> Dict[bytes, int]:
        return {node: self.net_balance(node) for node in sorted(self._nodes, key=repr)}

    def _assert_conservation(self) -> None:
        if sum(self.all_net_balances().values()) != 0:
            raise DebtCycleMeshError("Kirchhoff invariant violated: net balances do not sum to 0")

    # ------------------------------------------------------- Tarjan SCC (iterative)

    def _adjacency(self) -> Dict[bytes, List[bytes]]:
        adj: Dict[bytes, List[bytes]] = {node: [] for node in self._nodes}
        for (payer, payee) in self._edges:
            adj.setdefault(payer, []).append(payee)
        for node in adj:
            adj[node].sort(key=repr)
        return adj

    def tarjan_sccs(self) -> List[List[bytes]]:
        """Iterative Tarjan. Returns all SCCs; cycles live in SCCs of size >= 2."""
        adj = self._adjacency()
        index_counter = 0
        index: Dict[bytes, int] = {}
        low: Dict[bytes, int] = {}
        on_stack: Set[bytes] = set()
        stack: List[bytes] = []
        sccs: List[List[bytes]] = []

        for root in sorted(self._nodes, key=repr):
            if root in index:
                continue
            work: List[Tuple[bytes, Iterator[bytes]]] = [(root, iter(adj.get(root, ())))]
            index[root] = low[root] = index_counter
            index_counter += 1
            stack.append(root)
            on_stack.add(root)
            while work:
                node, successors = work[-1]
                advanced = False
                for succ in successors:
                    if succ not in index:
                        index[succ] = low[succ] = index_counter
                        index_counter += 1
                        stack.append(succ)
                        on_stack.add(succ)
                        work.append((succ, iter(adj.get(succ, ()))))
                        advanced = True
                        break
                    if succ in on_stack:
                        low[node] = min(low[node], index[succ])
                if advanced:
                    continue
                work.pop()
                if work:
                    parent = work[-1][0]
                    low[parent] = min(low[parent], low[node])
                if low[node] == index[node]:
                    scc: List[bytes] = []
                    while True:
                        member = stack.pop()
                        on_stack.discard(member)
                        scc.append(member)
                        if member == node:
                            break
                    sccs.append(scc)
        return sccs

    def find_cycle(self) -> Optional[List[bytes]]:
        """Deterministically finds one directed cycle (path closed to its head)."""
        for scc in self.tarjan_sccs():
            if len(scc) < 2:
                continue
            cycle = self._find_cycle_in_scc(set(scc), self._adjacency())
            if cycle:
                return cycle
        return None

    @staticmethod
    def _find_cycle_in_scc(scc_set: Set[bytes], adj: Dict[bytes, List[bytes]]) -> Optional[List[bytes]]:
        start = min(scc_set, key=repr)
        parent: Dict[bytes, Optional[bytes]] = {start: None}
        dfs_stack = [start]
        while dfs_stack:
            node = dfs_stack.pop()
            for succ in adj.get(node, ()):
                if succ not in scc_set:
                    continue
                if succ == start:
                    path = [node]
                    while parent[path[-1]] is not None:
                        path.append(parent[path[-1]])  # type: ignore[arg-type]
                    path.reverse()
                    return path + [start]
                if succ not in parent:
                    parent[succ] = node
                    dfs_stack.append(succ)
        return None

    # ------------------------------------------------------------ netting core

    def _annihilate_cycle(self, cycle: List[bytes]) -> int:
        """Reduces the cycle by its minimum edge; returns annihilated volume."""
        edge_keys: List[EdgeKey] = []
        for i in range(len(cycle) - 1):
            edge_keys.append(self._key(cycle[i], cycle[i + 1]))
        min_edge = min(self._edges[k] for k in edge_keys)
        for key in edge_keys:
            self._edges[key] -= min_edge
            self._gross_volume -= min_edge
            self._annihilated_volume += min_edge
            if self._edges[key] == 0:
                del self._edges[key]
        return min_edge * len(edge_keys)

    def _charge_treasury_fee(self, annihilated_volume: int, participants: List[bytes]) -> int:
        """Books 0.01% of annihilated volume as obligations into the treasury node."""
        if self.treasury_node is None or self._fee_num == 0 or annihilated_volume == 0:
            return 0
        fee_total = annihilated_volume * self._fee_num // self._fee_den
        if fee_total == 0:
            return 0
        base, remainder = divmod(fee_total, len(participants))
        for i, node in enumerate(participants):
            share = base + (1 if i < remainder else 0)
            if share == 0:
                continue
            key = self._key(node, self.treasury_node)
            self._edges[key] = self._edges.get(key, 0) + share
            self._gross_volume += share
            self._nodes.update((key[0], key[1]))
        self._treasury_fee += fee_total
        return fee_total

    # ------------------------------------------------- minimal settlements

    def _build_minimal_settlements(self) -> None:
        """
        Phase 2 of Kirchhoff netting (CLS-style multilateral netting):
        cycle annihilation preserves every node's net balance, so the minimal
        settlement set is a water-filling matching of net debtors to net
        creditors. Rebuilds the edge set as direct debtor->creditor edges,
        making residual volume exactly sum(|net_balance|) / 2.
        """
        balances = self.all_net_balances()
        debtors = sorted(((node) for node, b in balances.items() if b < 0), key=repr)
        creditors = sorted(((node) for node, b in balances.items() if b > 0), key=repr)
        credit_remaining = {node: balances[node] for node in creditors}
        new_edges: Dict[EdgeKey, int] = {}
        for debtor in debtors:
            need = -balances[debtor]
            for creditor in creditors:
                if need == 0:
                    break
                available = credit_remaining[creditor]
                if available <= 0:
                    continue
                take = min(need, available)
                key = self._key(debtor, creditor)
                new_edges[key] = new_edges.get(key, 0) + take
                credit_remaining[creditor] -= take
                need -= take
            if need != 0:
                raise DebtCycleMeshError("water-filling could not place debtor volume")
        if any(v > 0 for v in credit_remaining.values()):
            raise DebtCycleMeshError("unmatched creditor volume after water-filling")
        self._edges = new_edges

    def net_all(self) -> NettingSummary:
        """
        Runs cycle annihilation to fixpoint, then consolidates transit flows.
        The fixpoint graph is a DAG of direct debtor->creditor edges only;
        its volume equals sum(|net_balance|) / 2 (the provable minimum).
        """
        self._assert_conservation()
        edges_before = len(self._edges)
        residual_before = self.total_system_debt()

        # Phase 1: Tarjan SCC -> annihilate cycles -> repeat until DAG.
        while True:
            sccs = [scc for scc in self.tarjan_sccs() if len(scc) >= 2]
            if not sccs:
                break
            progress = False
            for scc in sccs:
                cycle = self._find_cycle_in_scc(set(scc), self._adjacency())
                if not cycle:
                    continue
                annihilated = self._annihilate_cycle(cycle)
                self._cycles_resolved += 1
                self._charge_treasury_fee(annihilated, cycle[:-1])
                self._assert_conservation()
                progress = True
            if not progress:  # defensive: cannot happen for SCC size >= 2
                raise DebtCycleMeshError("SCC found but no cycle reducible - internal error")

        # Phase 2: rebuild as minimal direct debtor->creditor settlements.
        self._build_minimal_settlements()
        self._assert_conservation()

        residual_volume = self.total_system_debt()
        minimal = sum(abs(balance) for balance in self.all_net_balances().values()) // 2
        if residual_volume != minimal:
            raise DebtCycleMeshError(
                f"non-minimal fixpoint: residual {residual_volume} != sum|net|/2 {minimal}")

        return NettingSummary(
            gross_volume_micro=residual_before,
            residual_volume_micro=residual_volume,
            annihilated_volume_micro=residual_before - residual_volume,
            cycles_resolved=self._cycles_resolved,
            edges_before=edges_before,
            edges_after=len(self._edges),
            treasury_fee_micro=self._treasury_fee,
            conservation_ok=True,
        )

    # ------------------------------------------------------------ settlements

    def generate_clearing_settlements(self) -> List[Tuple[bytes, bytes, int]]:
        """Residual DAG as a settlement list (payer, payee, amount), deterministic order."""
        return [(payer, payee, amount)
                for (payer, payee), amount in sorted(self._edges.items(), key=repr)]

    def summary(self) -> NettingSummary:
        return NettingSummary(
            gross_volume_micro=self._gross_volume,
            residual_volume_micro=self.total_system_debt(),
            annihilated_volume_micro=self._annihilated_volume,
            cycles_resolved=self._cycles_resolved,
            edges_before=len(self._edges),
            edges_after=len(self._edges),
            treasury_fee_micro=self._treasury_fee,
            conservation_ok=True,
        )
