// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"csls/internal/session"
)

func TestPersistenceFailuresAreReported(t *testing.T) {
	home := t.TempDir()
	t.Setenv("CSLS_HOME", home)
	m := session.NewMemoryManager("workspace")
	if err := m.AddTurn("question", "answer"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(m.MemoryFile()); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(m.MemoryFile(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.MemoryFile(), "blocker"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	sess := &session.State{Memory: m, CurrentModel: "original:model"}
	result := runClear(sess)
	if result.Err == nil || !strings.Contains(result.Output, "Cannot clear conversation memory") {
		t.Fatalf("clear failure not reported: %+v", result)
	}
	if len(m.Messages()) != 2 {
		t.Fatal("failed clear discarded messages")
	}

	blockedHome := filepath.Join(home, "not-a-directory")
	if err := os.WriteFile(blockedHome, nil, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CSLS_HOME", blockedHome)
	result = runModel(sess, nil, []string{"openai:test-model"})
	if result.Err == nil || !strings.Contains(result.Output, "Cannot save active model") {
		t.Fatalf("model failure not reported: %+v", result)
	}
	if sess.CurrentModel != "original:model" {
		t.Fatal("failed save changed live model")
	}
	result = runTheme([]string{"amber"})
	if result.Err == nil || !strings.Contains(result.Output, "Cannot save theme") {
		t.Fatalf("theme failure not reported: %+v", result)
	}
}
