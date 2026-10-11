// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package session

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestInputHistoryPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("CSLS_HOME", tmpDir)

	// Initially empty
	h := LoadInputHistory()
	if len(h) != 0 {
		t.Fatalf("expected empty history, got %v", h)
	}

	// Append items
	AppendInputHistory("/help")
	AppendInputHistory("/model")
	// Consecutive duplicate should be ignored
	AppendInputHistory("/model")
	AppendInputHistory("hello world")

	h = LoadInputHistory()
	if len(h) != 3 {
		t.Fatalf("expected 3 items, got %d: %v", len(h), h)
	}
	if h[0] != "/help" || h[1] != "/model" || h[2] != "hello world" {
		t.Fatalf("unexpected history contents: %v", h)
	}

	// Verify file path
	expectedPath := filepath.Join(tmpDir, "input_history")
	if InputHistoryFile() != expectedPath {
		t.Fatalf("expected path %s, got %s", expectedPath, InputHistoryFile())
	}
}

func TestMemoryManagerPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("CSLS_HOME", tmpDir)

	ws := filepath.Join(tmpDir, "my_project")
	mm := NewMemoryManager(ws)

	if len(mm.Messages()) != 0 {
		t.Fatalf("expected empty initial messages")
	}

	err := mm.AddTurn("What is CSLS?", "CSLS is a sovereign clearing protocol.")
	if err != nil {
		t.Fatalf("AddTurn failed: %v", err)
	}

	msgs := mm.Messages()
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}
	if msgs[0].Role != "user" || msgs[0].Content != "What is CSLS?" {
		t.Fatalf("unexpected user message: %+v", msgs[0])
	}
	if msgs[1].Role != "assistant" || !strings.Contains(msgs[1].Content, "sovereign clearing") {
		t.Fatalf("unexpected assistant message: %+v", msgs[1])
	}

	tokens := mm.EstimateTokens()
	if tokens <= 0 {
		t.Fatalf("expected tokens > 0, got %d", tokens)
	}

	// Reload from disk with fresh manager instance
	mm2 := NewMemoryManager(ws)
	msgs2 := mm2.Messages()
	if len(msgs2) != 2 {
		t.Fatalf("expected 2 messages after reload, got %d", len(msgs2))
	}

	// Test compaction
	for i := 0; i < 10; i++ {
		_ = mm.AddTurn("query", "reply")
	}
	purged, err := mm.CompactMemory(2)
	if err != nil {
		t.Fatalf("CompactMemory failed: %v", err)
	}
	if purged <= 0 {
		t.Fatalf("expected purged > 0, got %d", purged)
	}

	// Test Clear
	cleared := mm.Clear()
	if cleared <= 0 {
		t.Fatalf("expected cleared > 0, got %d", cleared)
	}
	if len(mm.Messages()) != 0 {
		t.Fatalf("expected 0 messages after clear")
	}
}
