// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package agent_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"csls/internal/agent"
)

func TestCanonical2026ModelCatalogue(t *testing.T) {
	router := agent.NewUpstreamRouter()
	ctx := context.Background()

	models, err := router.ListModels(ctx)
	if err != nil {
		t.Fatalf("ListModels failed: %v", err)
	}

	if len(models) == 0 {
		t.Fatalf("expected non-empty canonical 2026 model catalogue")
	}

	foundOpus := false
	foundSol := false
	for _, m := range models {
		if m.ID == "claude-opus-5.5" {
			foundOpus = true
		}
		if m.ID == "gpt-6.1-sol" {
			foundSol = true
		}
	}

	if !foundOpus || !foundSol {
		t.Fatalf("canonical 2026 model catalogue missing frontier models (Opus: %v, Sol: %v)", foundOpus, foundSol)
	}
}

func TestMerchantDirectRoutingAndKeys(t *testing.T) {
	merchants := agent.CanonicalMerchants()
	if len(merchants) < 15 {
		t.Fatalf("expected at least 15 canonical merchants, got %d", len(merchants))
	}

	for _, m := range merchants {
		pk := m.PublicKeyBytes()
		if len(pk) != 33 {
			t.Fatalf("merchant %s invalid compressed secp256k1 pubkey length: %d", m.ID, len(pk))
		}
		if !strings.HasPrefix(m.PayoutAddress, "0x") || len(m.PayoutAddress) != 42 {
			t.Fatalf("merchant %s invalid Base L2 payout address: %s", m.ID, m.PayoutAddress)
		}
		if m.UnitPriceMicro == 0 {
			t.Fatalf("merchant %s must have non-zero UnitPriceMicro", m.ID)
		}
	}

	anth, ok := agent.ResolveMerchant("anthropic:claude-opus-5.5")
	if !ok || anth.ID != "anthropic" {
		t.Fatalf("expected anthropic merchant for anthropic:claude-opus-5.5, got %v", anth)
	}

	ds, ok := agent.ResolveMerchant("deepseek:deepseek-v4-pro")
	if !ok || ds.ID != "deepseek" {
		t.Fatalf("expected deepseek merchant for deepseek:deepseek-v4-pro, got %v", ds)
	}
}

func TestSharedPoolExecution(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live network test in short mode")
	}
	if os.Getenv("GEMINI_API_KEY") == "" && os.Getenv("GROQ_API_KEY") == "" && os.Getenv("OPENROUTER_API_KEY") == "" {
		t.Skip("skipping live network test: no upstream API key env vars set")
	}

	router := agent.NewUpstreamRouter()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	messages := []map[string]string{
		{"role": "user", "content": "Return the word PONG and nothing else."},
	}

	var chunks []string
	reply, err := router.ExecuteStreaming(ctx, "google:gemini-3.5-flash", messages, func(chunk string) {
		chunks = append(chunks, chunk)
	})

	if err != nil {
		t.Fatalf("ExecuteStreaming failed: %v", err)
	}

	if len(reply) == 0 {
		t.Fatalf("expected non-empty reply")
	}
}
