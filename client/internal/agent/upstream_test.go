// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package agent_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"csls/internal/agent"
)

func TestSharedPoolExecution(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live network test in short mode")
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

	upper := strings.ToUpper(reply)
	if !strings.Contains(upper, "PONG") {
		t.Logf("Reply received from pool: %s", reply)
	}
}

func TestSharedPoolFailover(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live network test in short mode")
	}

	router := agent.NewUpstreamRouter()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	messages := []map[string]string{
		{"role": "user", "content": "Say hello in 3 words"},
	}

	// Requesting an upstream model that has no direct provider key (e.g. anthropic)
	// Router should transparently failover to the shared pool
	reply, err := router.ExecuteStreaming(ctx, "anthropic:claude-opus-5.5", messages, nil)
	if err != nil {
		t.Fatalf("Failover execution failed: %v", err)
	}
	if len(strings.TrimSpace(reply)) == 0 {
		t.Fatalf("expected non-empty failover reply")
	}
	t.Logf("Failover reply received: %s", reply)
}
