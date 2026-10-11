// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package session_test

import (
	"testing"

	"csls/internal/session"
)

func TestDebtGraphEmpty(t *testing.T) {
	g := session.NewDebtGraph()
	if g.GrossVolume() != 0 {
		t.Fatalf("expected 0 gross volume, got %d", g.GrossVolume())
	}
	if g.EdgeCount() != 0 {
		t.Fatalf("expected 0 edges, got %d", g.EdgeCount())
	}

	res := g.ReduceKirchhoffCycles()
	if res.CyclesEliminated != 0 {
		t.Fatalf("expected 0 cycles, got %d", res.CyclesEliminated)
	}
	if res.VolumeAnnihilated != 0 {
		t.Fatalf("expected 0 volume annihilated, got %d", res.VolumeAnnihilated)
	}
}

func TestDebtGraphSingleCycle(t *testing.T) {
	g := session.NewDebtGraph()
	// NodeA owes NodeB $1.00 (1_000_000 micro-USDC)
	// NodeB owes NodeC $1.00
	// NodeC owes NodeA $1.00
	g.AddObligation("NodeA", "NodeB", 1000000)
	g.AddObligation("NodeB", "NodeC", 1000000)
	g.AddObligation("NodeC", "NodeA", 1000000)

	if g.GrossVolume() != 3000000 {
		t.Fatalf("expected 3_000_000 gross volume, got %d", g.GrossVolume())
	}
	if g.EdgeCount() != 3 {
		t.Fatalf("expected 3 edges, got %d", g.EdgeCount())
	}

	res := g.ReduceKirchhoffCycles()
	if res.CyclesEliminated != 1 {
		t.Fatalf("expected 1 cycle eliminated, got %d", res.CyclesEliminated)
	}
	if res.VolumeAnnihilated != 3000000 {
		t.Fatalf("expected 3_000_000 annihilated volume, got %d", res.VolumeAnnihilated)
	}
	if res.FinalGrossMicro != 0 {
		t.Fatalf("expected 0 final gross volume, got %d", res.FinalGrossMicro)
	}
	if res.GrossSavedPercent < 99.9 {
		t.Fatalf("expected ~100%% savings, got %f", res.GrossSavedPercent)
	}
	if len(res.CycleCertificates) != 1 {
		t.Fatalf("expected 1 cycle certificate, got %d", len(res.CycleCertificates))
	}
}

func TestDebtGraphMultiCycleAndConservation(t *testing.T) {
	g := session.NewDebtGraph()
	// Cycle 1: A -> B -> C -> A with min edge $0.20
	g.AddObligation("NodeA", "NodeB", 500000) // $0.50
	g.AddObligation("NodeB", "NodeC", 300000) // $0.30
	g.AddObligation("NodeC", "NodeA", 200000) // $0.20

	// Branch: C -> D -> E -> C with min edge $0.10
	g.AddObligation("NodeC", "NodeD", 400000) // $0.40
	g.AddObligation("NodeD", "NodeE", 100000) // $0.10
	g.AddObligation("NodeE", "NodeC", 150000) // $0.15

	initialGross := g.GrossVolume()
	res := g.ReduceKirchhoffCycles()

	if res.CyclesEliminated < 2 {
		t.Fatalf("expected at least 2 cycles eliminated, got %d", res.CyclesEliminated)
	}

	// Conservation invariant: Initial == Final + Annihilated
	if initialGross != res.FinalGrossMicro+res.VolumeAnnihilated {
		t.Fatalf("conservation invariant violated: initial(%d) != final(%d) + annihilated(%d)",
			initialGross, res.FinalGrossMicro, res.VolumeAnnihilated)
	}

	// Check treasury fee (0.01%)
	expectedFee := res.VolumeAnnihilated / 10000
	if res.TreasuryFeeMicro != expectedFee {
		t.Fatalf("expected treasury fee %d, got %d", expectedFee, res.TreasuryFeeMicro)
	}
}
