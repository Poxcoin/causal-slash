// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package ui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

func typeRunes(m tea.Model, s string) tea.Model {
	for _, r := range s {
		m, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	return m
}

func TestCommandMenuFiltersByPrefix(t *testing.T) {
	var m tea.Model = NewApp(&testBackend{}, "t", "/tmp")
	m, _ = m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m = typeRunes(m, "/s")
	view := ansi.Strip(m.View())
	if !strings.Contains(view, "/status") || strings.Contains(view, "/help") {
		t.Fatalf("expected only /status suggestion:\n%s", view)
	}
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyTab})
	if got := m.(AppModel).input.Value(); got != "/status" {
		t.Fatalf("tab must complete to /status, got %q", got)
	}
}

func TestModelPickerSelectsWithArrows(t *testing.T) {
	var m tea.Model = NewApp(&testBackend{}, "t", "/tmp")
	m, _ = m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m = typeRunes(m, "/model")
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if got := m.(AppModel).input.Value(); got != "/model " {
		t.Fatalf("enter on /model must open picker, got %q", got)
	}
	view := ansi.Strip(m.View())
	if !strings.Contains(view, "Anthropic") || !strings.Contains(view, "OpenAI") {
		t.Fatalf("company list missing:\n%s", view)
	}
	// Select Anthropic
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if m.(AppModel).selectedCompany != "anthropic" {
		t.Fatalf("expected selectedCompany anthropic, got %q", m.(AppModel).selectedCompany)
	}
	viewCompany := ansi.Strip(m.View())
	if !strings.Contains(viewCompany, "Claude Opus 5.5") {
		t.Fatalf("models for company missing:\n%s", viewCompany)
	}
}
