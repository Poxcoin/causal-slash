// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package ui

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

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
		tCh <- "Echo response for query: " + query
	}()
	return tCh, eCh
}

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
	fmt.Printf("--- Final Viewport Content ---\n%s\n------------------------------\n", content)

	if !strings.Contains(content, "hello") {
		t.Errorf("Expected content to contain 'hello', got:\n%s", content)
	}
	if !strings.Contains(content, "Echo response for query: hello") {
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
