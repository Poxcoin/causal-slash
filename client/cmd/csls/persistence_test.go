// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"csls/internal/session"
)

func TestClearBackendPreservesErrors(t *testing.T) {
	t.Setenv("CSLS_HOME", t.TempDir())
	m := session.NewMemoryManager("workspace")
	b := &appBackend{sess: &session.State{Memory: m}}
	if output, _ := b.ExecuteSlash("/clear"); output != "" {
		t.Fatalf("successful clear must restore startup view, got %q", output)
	}
	if err := m.Save(); err != nil {
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
	if output, _ := b.ExecuteSlash("/clear"); !strings.Contains(output, "Cannot clear conversation memory") {
		t.Fatalf("backend hid failed clear: %q", output)
	}
}
