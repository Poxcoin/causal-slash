// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"csls/internal/session"

	tea "github.com/charmbracelet/bubbletea"
)

type clearFailureBackend struct{ testBackend }

func (b *clearFailureBackend) ExecuteSlash(string) (string, bool) {
	return "Cannot clear conversation memory: test failure", false
}

func TestClearFailureRetainsDisplayAndReportsError(t *testing.T) {
	t.Setenv("CSLS_HOME", t.TempDir())
	m := NewApp(&clearFailureBackend{}, "test", "workspace")
	m.lines = []string{"existing conversation"}
	m.input.SetValue("/clear")
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	lines := strings.Join(updated.(AppModel).lines, "\n")
	if !strings.Contains(lines, "existing conversation") || !strings.Contains(lines, "Cannot clear conversation memory") {
		t.Fatalf("failed clear discarded conversation or hid error: %q", lines)
	}
}

func TestInputHistoryFailureIsVisible(t *testing.T) {
	home := t.TempDir()
	t.Setenv("CSLS_HOME", home)
	if err := os.Mkdir(session.InputHistoryFile(), 0700); err != nil {
		t.Fatal(err)
	}
	m := NewApp(&testBackend{}, "test", "workspace")
	m.input.SetValue("/help")
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	lines := strings.Join(updated.(AppModel).lines, "\n")
	if !strings.Contains(lines, "Cannot save input history") {
		t.Fatalf("history persistence error hidden: %q", lines)
	}
}

func TestThemeWizardShowsSaveFailure(t *testing.T) {
	home := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(home, nil, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CSLS_HOME", home)
	m := NewThemeWizard()
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	wizard := updated.(ThemeWizard)
	if wizard.quitting || cmd != nil || wizard.saveErr == nil {
		t.Fatalf("failed theme save should stay open with an error: %+v", wizard)
	}
	if !strings.Contains(wizard.View(), "Cannot save theme") {
		t.Fatal("wizard hid save error")
	}
}

func TestThemeWizardCancelDoesNotOverwriteTheme(t *testing.T) {
	t.Setenv("CSLS_HOME", t.TempDir())
	if err := os.WriteFile(session.ThemeFile(), []byte("neon-amber\n"), 0600); err != nil {
		t.Fatal(err)
	}
	m := NewThemeWizard()
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if !updated.(ThemeWizard).quitting {
		t.Fatal("cancel must quit wizard")
	}
	raw, err := os.ReadFile(session.ThemeFile())
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "neon-amber\n" {
		t.Fatalf("cancel overwrote saved theme: %q", raw)
	}
}
