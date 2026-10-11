// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package ui

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"csls/internal/session"
	tea "github.com/charmbracelet/bubbletea"
)

type testBackend struct {
	bondStatus string
}

func (b *testBackend) BondStatus() string {
	if b.bondStatus != "" {
		return b.bondStatus
	}
	return "ready"
}

func (b *testBackend) Commands() []CommandItem {
	return []CommandItem{
		{Name: "/help", Description: "show help"},
		{Name: "/model", Description: "select model", ArgsSpec: "[model]"},
		{Name: "/status", Description: "status"},
	}
}

func (b *testBackend) ListModels() ([]ModelItem, error) {
	return []ModelItem{{Ref: "groq:alpha"}, {Ref: "openrouter:beta/gamma"}}, nil
}

func (b *testBackend) ActiveModel() string {
	return "claude-opus-5.5"
}

func (b *testBackend) ExecuteSlash(cmd string) (string, bool) {
	if cmd == "/help" {
		return "Available commands: /help, /bond, /status, /model, /wallet, /clear, /exit", false
	}
	if cmd == "/exit" {
		return "", true
	}
	return "unknown command", false
}

func (b *testBackend) StreamQuery(ctx context.Context, query string) (<-chan string, <-chan error) {
	tCh := make(chan string, 10)
	eCh := make(chan error, 1)
	go func() {
		defer close(tCh)
		defer close(eCh)
		tCh <- "Streaming response: " + query
	}()
	return tCh, eCh
}

func (b *testBackend) InitialLines() []string {
	return nil
}

func (b *testBackend) CommandHistory() []string {
	return nil
}

var _ Backend = (*testBackend)(nil)

func TestAppPipedInput(t *testing.T) {
	backend := &testBackend{}
	app := NewApp(backend, "0.3.0", "/test/cwd")

	pr, pw := io.Pipe()
	var outBuf bytes.Buffer

	p := tea.NewProgram(
		app,
		tea.WithInput(pr),
		tea.WithOutput(&outBuf),
	)

	// Feed input sequentially: "hello\n", then "/help\n", then Ctrl+D (\x04)
	go func() {
		time.Sleep(50 * time.Millisecond)
		p.Send(tea.WindowSizeMsg{Width: 80, Height: 24})

		time.Sleep(50 * time.Millisecond)
		_, _ = pw.Write([]byte("hello\n"))

		time.Sleep(150 * time.Millisecond)
		_, _ = pw.Write([]byte("/help\n"))

		time.Sleep(150 * time.Millisecond)
		_, _ = pw.Write([]byte("\x04"))

		time.Sleep(50 * time.Millisecond)
		_ = pw.Close()
	}()

	finalModel, err := p.Run()
	if err != nil {
		t.Fatalf("Program.Run failed: %v", err)
	}

	model, ok := finalModel.(AppModel)
	if !ok {
		t.Fatalf("Expected AppModel, got %T", finalModel)
	}

	// Verify no panic occurred and history contains both commands
	content := strings.Join(model.lines, "\n")

	if !strings.Contains(content, "hello") {
		t.Errorf("Expected content to contain 'hello', got:\n%s", content)
	}
	if !strings.Contains(content, "Streaming response: hello") {
		t.Errorf("Expected content to contain agent response, got:\n%s", content)
	}
	if !strings.Contains(content, "/help") {
		t.Errorf("Expected content to contain '/help', got:\n%s", content)
	}
}

func TestScrollbackCap(t *testing.T) {
	backend := &testBackend{}
	app := NewApp(backend, "0.3.0", "/test/cwd")

	// Append 6000 lines
	for i := 0; i < 6000; i++ {
		app.appendToken("line\n")
	}

	if len(app.lines) > maxScrollbackLines {
		t.Fatalf("expected lines to be capped at %d, but got %d", maxScrollbackLines, len(app.lines))
	}
	if len(app.lines) != maxScrollbackLines {
		t.Fatalf("expected exactly %d lines after cap, got %d", maxScrollbackLines, len(app.lines))
	}
}

func TestFormatInitialTurns(t *testing.T) {
	msgs := []session.ChatMessage{
		{Role: "user", Content: "hello"},
		{Role: "assistant", Content: "world reply"},
		{Role: "system", Content: "summary note"},
	}
	lines := FormatInitialTurns(msgs)
	if len(lines) == 0 {
		t.Fatalf("expected formatted lines, got empty")
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "hello") {
		t.Errorf("expected 'hello' in lines, got:\n%s", joined)
	}
	if !strings.Contains(joined, "world reply") {
		t.Errorf("expected 'world reply' in lines, got:\n%s", joined)
	}
	if !strings.Contains(joined, "summary note") {
		t.Errorf("expected 'summary note' in lines, got:\n%s", joined)
	}
}

type historyBackend struct {
	testBackend
	lines   []string
	history []string
}

func (h *historyBackend) InitialLines() []string {
	return h.lines
}

func (h *historyBackend) CommandHistory() []string {
	return h.history
}

func TestAppInitialLinesAndHistory(t *testing.T) {
	backend := &historyBackend{
		lines:   []string{"> previous question", "previous answer"},
		history: []string{"/help", "previous question"},
	}
	app := NewApp(backend, "0.3.0", "/test/cwd")

	if len(app.lines) != 2 {
		t.Fatalf("expected 2 initial lines, got %d", len(app.lines))
	}
	if len(app.history) != 2 {
		t.Fatalf("expected 2 history items, got %d", len(app.history))
	}
	if app.historyIdx != 2 {
		t.Fatalf("expected historyIdx to be 2, got %d", app.historyIdx)
	}

	// Press Up arrow -> should recall "previous question"
	u1, _ := app.Update(tea.KeyMsg{Type: tea.KeyUp})
	m1 := u1.(AppModel)
	if m1.input.Value() != "previous question" {
		t.Fatalf("expected input 'previous question' after Up arrow, got '%s'", m1.input.Value())
	}

	// Press Up arrow again -> should recall "/help"
	u2, _ := m1.Update(tea.KeyMsg{Type: tea.KeyUp})
	m2 := u2.(AppModel)
	if m2.input.Value() != "/help" {
		t.Fatalf("expected input '/help' after Up arrow, got '%s'", m2.input.Value())
	}
}

