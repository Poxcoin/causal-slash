// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package ui

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func TestInspectView(t *testing.T) {
	backend := &testBackend{}

	// Test 80 cols x 24 rows
	t.Run("80 columns", func(t *testing.T) {
		app := NewApp(backend, "0.3.0", "/home/minus/workspace")
		updated, _ := app.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
		m := updated.(AppModel)

		view := m.View()
		lines := strings.Split(view, "\n")
		fmt.Printf("\n=== RENDERED VIEW 80 COLS (Lines=%d, Width=%d) ===\n", len(lines), lipgloss.Width(view))
		for i, line := range lines {
			fmt.Printf("%02d | %s\n", i+1, line)
		}

		if len(lines) != 24 {
			t.Errorf("Expected 24 lines, got %d", len(lines))
		}
	})

	// Test 40 cols x 24 rows
	t.Run("40 columns", func(t *testing.T) {
		app := NewApp(backend, "0.3.0", "/home/minus/workspace")
		updated, _ := app.Update(tea.WindowSizeMsg{Width: 40, Height: 24})
		m := updated.(AppModel)

		view := m.View()
		lines := strings.Split(view, "\n")
		fmt.Printf("\n=== RENDERED VIEW 40 COLS (Lines=%d, Width=%d) ===\n", len(lines), lipgloss.Width(view))
		for i, line := range lines {
			fmt.Printf("%02d | %s\n", i+1, line)
		}

		if len(lines) != 24 {
			t.Errorf("Expected 24 lines, got %d", len(lines))
		}
	})

	// Test FocusMsg, BlurMsg, and mouse click cursor transitions
	t.Run("Focus and blur cursor transitions", func(t *testing.T) {
		app := NewApp(backend, "0.3.0", "/home/minus/workspace")
		u1, _ := app.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
		m := u1.(AppModel)

		// Unfocused initial state: square is hollow '⎕' (transparent interior, matching screenshots 15-16-13 & 20-11-01)
		if !strings.Contains(m.renderInput(), "⎕") {
			t.Errorf("Initial unfocused state must contain hollow square '⎕'")
		}
		if strings.Contains(m.renderInput(), "█") {
			t.Errorf("Initial unfocused state must not contain filled square '█'")
		}

		// Mouse click event: activates focus, turning cursor into solid white-filled square '█'
		uClick, _ := m.Update(tea.MouseMsg{Button: tea.MouseButtonLeft, Action: tea.MouseActionPress})
		mClicked := uClick.(AppModel)
		if !strings.Contains(mClicked.renderInput(), "█") {
			t.Errorf("Mouse click state must contain white-filled square '█'")
		}
		if strings.Contains(mClicked.renderInput(), "⎕") {
			t.Errorf("Mouse click state must not contain hollow square '⎕'")
		}

		// Cursor blinking when focused: when Blink is true, cursor blinks off
		mBlinkOn := mClicked
		mBlinkOn.input.Cursor.Blink = true
		if strings.Contains(mBlinkOn.renderInput(), "█") {
			t.Errorf("When cursor blinks off, solid square '█' must temporarily disappear")
		}

		// Blur event: square remains, but becomes hollow '⎕' (static, does not blink)
		u2, _ := mClicked.Update(tea.BlurMsg{})
		mBlur := u2.(AppModel)
		if !strings.Contains(mBlur.renderInput(), "⎕") {
			t.Errorf("Blurred state must render hollow square '⎕'")
		}

		// Re-focus event: square becomes fully white-filled '█' again
		u3, _ := mBlur.Update(tea.FocusMsg{})
		mFocused := u3.(AppModel)
		if !strings.Contains(mFocused.renderInput(), "█") {
			t.Errorf("Re-focused state must restore white-filled square '█'")
		}
		if strings.Contains(mFocused.renderInput(), "⎕") {
			t.Errorf("Re-focused state must not contain hollow square '⎕'")
		}

		// Ctrl+Y copy test
		mFocused.lines = []string{"> prompt", "Response text to copy"}
		uCtrlY, _ := mFocused.Update(tea.KeyMsg{Type: tea.KeyCtrlY})
		mCopied := uCtrlY.(AppModel)
		if mCopied.flashMsg != "copied to clipboard" && !strings.HasPrefix(mCopied.flashMsg, "clipboard error") {
			t.Errorf("Ctrl+Y must trigger copy flashMsg, got %q", mCopied.flashMsg)
		}
	})

	// Test Viewport scrolling with mouse wheel and keys
	t.Run("Viewport scrolling up and down", func(t *testing.T) {
		app := NewApp(backend, "0.3.0", "/home/minus/workspace")
		u1, _ := app.Update(tea.WindowSizeMsg{Width: 80, Height: 20})
		m := u1.(AppModel)

		// Populate lines so viewport has scrollable content
		m.lines = make([]string, 50)
		for i := range m.lines {
			m.lines[i] = fmt.Sprintf("Line %02d of long output", i+1)
		}
		m.recalculateViewport()
		m.viewport.GotoBottom()

		initialOffset := m.viewport.YOffset
		if initialOffset == 0 {
			t.Fatalf("Expected YOffset > 0 for 50 lines in 20-row terminal")
		}

		// Mouse wheel UP: scrolls up
		uWheelUp, _ := m.Update(tea.MouseMsg{Button: tea.MouseButtonWheelUp})
		mScrolledUp := uWheelUp.(AppModel)
		if mScrolledUp.viewport.YOffset >= initialOffset {
			t.Errorf("Mouse wheel up should decrease YOffset, got %d (was %d)", mScrolledUp.viewport.YOffset, initialOffset)
		}

		// Mouse wheel DOWN: scrolls back down
		uWheelDown, _ := mScrolledUp.Update(tea.MouseMsg{Button: tea.MouseButtonWheelDown})
		mScrolledDown := uWheelDown.(AppModel)
		if mScrolledDown.viewport.YOffset <= mScrolledUp.viewport.YOffset {
			t.Errorf("Mouse wheel down should increase YOffset, got %d (was %d)", mScrolledDown.viewport.YOffset, mScrolledUp.viewport.YOffset)
		}

		// Keyboard PageUp: scrolls up
		uPgUp, _ := m.Update(tea.KeyMsg{Type: tea.KeyPgUp})
		mPgUp := uPgUp.(AppModel)
		if mPgUp.viewport.YOffset >= initialOffset {
			t.Errorf("PageUp should decrease YOffset, got %d (was %d)", mPgUp.viewport.YOffset, initialOffset)
		}

		// Keyboard Shift+Up: scrolls up
		uShiftUp, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("shift+up")})
		mShiftUp := uShiftUp.(AppModel)
		if mShiftUp.viewport.YOffset >= initialOffset {
			t.Errorf("Shift+Up should decrease YOffset, got %d (was %d)", mShiftUp.viewport.YOffset, initialOffset)
		}
	})

	// Test Active Conversation state: startup header disappears, zero permanent header
	t.Run("Active conversation state transitions", func(t *testing.T) {
		app := NewApp(backend, "0.3.0", "/home/minus/workspace")
		u1, _ := app.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
		m := u1.(AppModel)

		// 1. Initial startup state: authentic logo is visible, no KADO text splash
		startupView := m.View()
		if strings.Contains(startupView, "K A D O") {
			t.Errorf("Startup view must NOT contain invented 'K A D O' text splash")
		}
		if !strings.Contains(startupView, "Causal-Slash CLI") {
			t.Errorf("Startup view should contain 'Causal-Slash CLI'")
		}

		// 2. User executes /help: startup header vanishes completely
		m.input.SetValue("/help")
		u2, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
		mActive := u2.(AppModel)

		activeView := mActive.View()
		activeLines := strings.Split(activeView, "\n")
		fmt.Printf("\n=== RENDERED ACTIVE VIEW (Lines=%d) ===\n", len(activeLines))
		for i, line := range activeLines {
			fmt.Printf("%02d | %s\n", i+1, line)
		}

		if len(activeLines) != 24 {
			t.Errorf("Active view expected 24 lines, got %d", len(activeLines))
		}
		if strings.Contains(activeView, "Causal-Slash CLI") {
			t.Errorf("Active view must NOT contain top header 'Causal-Slash CLI'")
		}
		if !strings.Contains(activeLines[0], "/help") {
			t.Errorf("Line 1 of active view should start with prompt/output, got: %q", activeLines[0])
		}

		// 3. User executes /clear: returns to startup state
		mActive.input.SetValue("/clear")
		u3, _ := mActive.Update(tea.KeyMsg{Type: tea.KeyEnter})
		mCleared := u3.(AppModel)

		clearedView := mCleared.View()
		clearedLines := strings.Split(clearedView, "\n")
		if len(clearedLines) != 24 {
			t.Errorf("Cleared view expected 24 lines, got %d", len(clearedLines))
		}
		if !strings.Contains(clearedView, "Causal-Slash CLI") {
			t.Errorf("Cleared view must restore startup state")
		}
	})
}
