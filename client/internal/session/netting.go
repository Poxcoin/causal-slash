// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package session

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// DebtEdge represents a directed obligation: Debtor owes Creditor amount in micro-USDC.
type DebtEdge struct {
	Debtor   string // 0x Address or Node ID
	Creditor string // 0x Address or Node ID
	Amount   uint64 // Micro-USDC (6 decimals)
}

// NettingResult summarizes the in-RAM cycle annihilation.
type NettingResult struct {
	InitialGrossMicro    uint64
	FinalGrossMicro      uint64
	CyclesEliminated     int
	VolumeAnnihilated    uint64
	VolumeAnnihilatedUSDC float64
	GrossSavedPercent    float64
	TreasuryFeeMicro     uint64
	CycleCertificates    []string
	ExecutionDuration    time.Duration
}

// DebtGraph manages the in-RAM directed obligation graph.
type DebtGraph struct {
	mu    sync.RWMutex
	edges map[string]map[string]uint64 // debtor -> creditor -> amount
}

// NewDebtGraph creates an empty in-RAM debt graph.
func NewDebtGraph() *DebtGraph {
	return &DebtGraph{
		edges: make(map[string]map[string]uint64),
	}
}

// AddObligation records or increments a directed obligation edge.
func (g *DebtGraph) AddObligation(debtor, creditor string, amount uint64) {
	if debtor == creditor || amount == 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, ok := g.edges[debtor]; !ok {
		g.edges[debtor] = make(map[string]uint64)
	}
	g.edges[debtor][creditor] += amount
}

// GrossVolume calculates total volume across all directed edges.
func (g *DebtGraph) GrossVolume() uint64 {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var total uint64
	for _, targets := range g.edges {
		for _, amt := range targets {
			total += amt
		}
	}
	return total
}

// EdgeCount returns number of active directed edges.
func (g *DebtGraph) EdgeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()

	count := 0
	for _, targets := range g.edges {
		count += len(targets)
	}
	return count
}

// ReduceKirchhoffCycles executes in-RAM Tarjan SCC cycle detection and cancels cyclic debt.
func (g *DebtGraph) ReduceKirchhoffCycles() *NettingResult {
	start := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()

	initialGross := uint64(0)
	for _, targets := range g.edges {
		for _, amt := range targets {
			initialGross += amt
		}
	}

	cyclesEliminated := 0
	totalAnnihilated := uint64(0)
	var certs []string

	// Iteratively find and eliminate cycles until graph is a DAG
	for {
		cycle := g.findSimpleCycle()
		if len(cycle) < 2 {
			break
		}

		// Find minimum edge in cycle
		minAmt := uint64(math.MaxUint64)
		for i := 0; i < len(cycle); i++ {
			u := cycle[i]
			v := cycle[(i+1)%len(cycle)]
			amt := g.edges[u][v]
			if amt < minAmt {
				minAmt = amt
			}
		}

		if minAmt == 0 || minAmt == math.MaxUint64 {
			break
		}

		// Annihilate minAmt along all edges of cycle
		for i := 0; i < len(cycle); i++ {
			u := cycle[i]
			v := cycle[(i+1)%len(cycle)]
			g.edges[u][v] -= minAmt
			if g.edges[u][v] == 0 {
				delete(g.edges[u], v)
			}
		}

		cyclesEliminated++
		annihilatedCycleVolume := minAmt * uint64(len(cycle))
		totalAnnihilated += annihilatedCycleVolume

		// Generate cycle certificate hash
		h := sha256.New()
		h.Write([]byte(fmt.Sprintf("cycle-%d-%d-%v", cyclesEliminated, minAmt, cycle)))
		certHash := hex.EncodeToString(h.Sum(nil))[:16]
		certs = append(certs, fmt.Sprintf("0x%s (%d nodes, -%d micro-USDC)", certHash, len(cycle), minAmt))

		// Cap iterations for safety
		if cyclesEliminated >= 1000 {
			break
		}
	}

	finalGross := uint64(0)
	for _, targets := range g.edges {
		for _, amt := range targets {
			finalGross += amt
		}
	}

	savedPct := 0.0
	if initialGross > 0 {
		savedPct = float64(totalAnnihilated) / float64(initialGross) * 100.0
		if savedPct > 100.0 {
			savedPct = 100.0
		}
	}

	treasuryFee := totalAnnihilated / 10000 // 0.01% fee

	return &NettingResult{
		InitialGrossMicro:    initialGross,
		FinalGrossMicro:      finalGross,
		CyclesEliminated:     cyclesEliminated,
		VolumeAnnihilated:    totalAnnihilated,
		VolumeAnnihilatedUSDC: float64(totalAnnihilated) / 1e6,
		GrossSavedPercent:    savedPct,
		TreasuryFeeMicro:     treasuryFee,
		CycleCertificates:    certs,
		ExecutionDuration:    time.Since(start),
	}
}

// findSimpleCycle finds a directed cycle using DFS.
func (g *DebtGraph) findSimpleCycle() []string {
	visited := make(map[string]bool)
	onStack := make(map[string]bool)
	var parent = make(map[string]string)

	var allNodes []string
	for u := range g.edges {
		if len(g.edges[u]) > 0 {
			allNodes = append(allNodes, u)
		}
	}
	sort.Strings(allNodes)

	var cycle []string
	var dfs func(u string) bool
	dfs = func(u string) bool {
		visited[u] = true
		onStack[u] = true

		for v := range g.edges[u] {
			if g.edges[u][v] == 0 {
				continue
			}
			if !visited[v] {
				parent[v] = u
				if dfs(v) {
					return true
				}
			} else if onStack[v] {
				// Cycle detected: backtrack from u to v
				curr := u
				cycle = append(cycle, curr)
				for curr != v {
					curr = parent[curr]
					cycle = append(cycle, curr)
				}
				// Reverse to orient in forward order
				for i, j := 0, len(cycle)-1; i < j; i, j = i+1, j-1 {
					cycle[i], cycle[j] = cycle[j], cycle[i]
				}
				return true
			}
		}

		onStack[u] = false
		return false
	}

	for _, n := range allNodes {
		if !visited[n] {
			if dfs(n) {
				return cycle
			}
		}
	}
	return nil
}
