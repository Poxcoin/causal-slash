// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package ui

import (
	"context"
	"strings"
	"time"

	"csls/internal/session"
	"github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

const (
	doubleCtrlC        = time.Second
	maxScrollbackLines = 5000
)

type tokenMsg string

type streamDoneMsg struct {
	err error
}

func readNextToken(tokens <-chan string, errs <-chan error) tea.Cmd {
	return func() tea.Msg {
		select {
		case token, ok := <-tokens:
			if ok {
				return tokenMsg(token)
			}
			select {
			case err, ok := <-errs:
				if ok && err != nil {
					return streamDoneMsg{err: err}
				}
			default:
			}
			return streamDoneMsg{}
		case err, ok := <-errs:
			if ok && err != nil {
				return streamDoneMsg{err: err}
			}
			token, ok := <-tokens
			if ok {
				return tokenMsg(token)
			}
			return streamDoneMsg{}
		}
	}
}

// AppModel implements the Bubble Tea interface for the full AltScreen TUI.
type AppModel struct {
	backend      Backend
	version      string
	cwd          string
	width        int
	height       int
	viewport     viewport.Model
	input        textinput.Model
	lines        []string
	history      []string
	historyIdx   int
	lastCtrlC    time.Time
	streaming    bool
	tokenChan    <-chan string
	errChan      <-chan error
	streamCancel context.CancelFunc
	focused      bool
	flashMsg     string
	flashUntil   time.Time
}

// NewApp creates the initial AppModel.
func NewApp(backend Backend, version, cwd string) AppModel {
	ti := textinput.New()
	ti.Prompt = "> "
	ti.PromptStyle = lipgloss.NewStyle().Foreground(lipgloss.Color(colorPrompt)).Bold(true)
	ti.Cursor.Style = lipgloss.NewStyle().Foreground(lipgloss.Color(colorPrompt))
	ti.Cursor.SetMode(cursor.CursorBlink)
	ti.Placeholder = ""
	ti.Blur()

	vp := viewport.New(76, 13)
	vp.Style = lipgloss.NewStyle().PaddingLeft(2).PaddingRight(2)
	vp.SetContent("")

	return AppModel{
		backend:    backend,
		version:    version,
		cwd:        cwd,
		width:      80,
		height:     24,
		viewport:   vp,
		input:      ti,
		lines:      nil,
		history:    nil,
		historyIdx: 0,
		focused:    false,
	}
}

func (m *AppModel) enforceScrollbackCap() {
	if len(m.lines) > maxScrollbackLines {
		m.lines = m.lines[len(m.lines)-maxScrollbackLines:]
	}
}

func (m *AppModel) appendToken(token string) {
	if len(m.lines) == 0 {
		m.lines = append(m.lines, "")
	}
	parts := strings.Split(token, "\n")
	if len(m.lines) > 0 {
		m.lines[len(m.lines)-1] += parts[0]
	}
	for i := 1; i < len(parts); i++ {
		m.lines = append(m.lines, parts[i])
	}
	m.enforceScrollbackCap()
}

func (m *AppModel) recalculateViewport() {
	bottomHeight := 4
	var headerHeight int
	if len(m.lines) == 0 {
		headerHeight = 1
	}
	vpHeight := m.height - headerHeight - bottomHeight
	if vpHeight < 1 {
		vpHeight = 1
	}
	vpWidth := m.width - 2
	if vpWidth < 1 {
		vpWidth = 1
	}
	m.viewport.Width = vpWidth
	m.viewport.Height = vpHeight
	m.viewport.SetContent(strings.Join(m.lines, "\n"))
	m.input.Width = m.width - 6
	if m.input.Width < 1 {
		m.input.Width = 1
	}
}

func (m AppModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m AppModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.recalculateViewport()
		m.viewport.GotoBottom()
		return m, nil

	case tokenMsg:
		wasAtBottom := m.viewport.AtBottom()
		m.appendToken(string(msg))
		m.viewport.SetContent(strings.Join(m.lines, "\n"))
		if wasAtBottom {
			m.viewport.GotoBottom()
		}
		return m, readNextToken(m.tokenChan, m.errChan)

	case streamDoneMsg:
		wasAtBottom := m.viewport.AtBottom()
		m.streaming = false
		if msg.err != nil {
			errStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(colorError))
			m.lines = append(m.lines, errStyle.Render("Agent error: "+msg.err.Error()))
		}
		m.lines = append(m.lines, "")
		m.enforceScrollbackCap()
		m.viewport.SetContent(strings.Join(m.lines, "\n"))
		if wasAtBottom {
			m.viewport.GotoBottom()
		}
		m.streamCancel = nil
		m.tokenChan = nil
		m.errChan = nil
		m.input.Focus()
		return m, nil

	case tea.FocusMsg:
		m.focused = true
		cmdFocus := m.input.Focus()
		m.input.Cursor.SetMode(cursor.CursorBlink)
		return m, cmdFocus

	case tea.BlurMsg:
		m.focused = false
		m.input.Blur()
		return m, nil

	case tea.MouseMsg:
		switch msg.Button {
		case tea.MouseButtonWheelUp:
			m.viewport.ScrollUp(3)
			return m, nil
		case tea.MouseButtonWheelDown:
			m.viewport.ScrollDown(3)
			return m, nil
		case tea.MouseButtonRight:
			// Right-click: quick copy of response or chat history to clipboard
			if msg.Action != tea.MouseActionMotion {
				textToCopy := m.getLastResponse()
				if textToCopy == "" && len(m.lines) > 0 {
					textToCopy = ansi.Strip(strings.Join(m.lines, "\n"))
				}
				if textToCopy != "" {
					if err := session.CopyToClipboard(textToCopy); err != nil {
						m.flashMsg = "clipboard error: " + err.Error()
					} else {
						m.flashMsg = "copied to clipboard"
					}
					m.flashUntil = time.Now().Add(2 * time.Second)
				}
			}
			return m, nil
		case tea.MouseButtonLeft:
			// Clicking in the terminal activates focus and turns cursor into solid white blinking square
			m.focused = true
			cmdFocus := m.input.Focus()
			m.input.Cursor.SetMode(cursor.CursorBlink)
			var cmdUpdate tea.Cmd
			m.input, cmdUpdate = m.input.Update(msg)
			return m, tea.Batch(cmdFocus, cmdUpdate)
		}

	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC || msg.String() == "ctrl+c" {
			now := time.Now()
			// If input has text, copy input to clipboard and clear
			if m.input.Value() != "" {
				val := m.input.Value()
				if err := session.CopyToClipboard(val); err != nil {
					m.flashMsg = "clipboard error: " + err.Error()
				} else {
					m.flashMsg = "input copied to clipboard"
				}
				m.input.SetValue("")
				m.lastCtrlC = now
				m.flashUntil = now.Add(2 * time.Second)
				return m, nil
			}
			if now.Sub(m.lastCtrlC) < doubleCtrlC {
				if m.streamCancel != nil {
					m.streamCancel()
				}
				return m, tea.Quit
			}
			m.lastCtrlC = now
			if m.streaming && m.streamCancel != nil {
				m.streamCancel()
				m.streaming = false
				m.lines = append(m.lines, lipgloss.NewStyle().Foreground(lipgloss.Color(colorWarn)).Render("[Stream interrupted]"))
				m.enforceScrollbackCap()
				m.viewport.SetContent(strings.Join(m.lines, "\n"))
				m.viewport.GotoBottom()
				return m, nil
			}
			// Copy last response on first Ctrl+C
			textToCopy := m.getLastResponse()
			if textToCopy == "" && len(m.lines) > 0 {
				textToCopy = ansi.Strip(strings.Join(m.lines, "\n"))
			}
			if textToCopy != "" {
				if err := session.CopyToClipboard(textToCopy); err != nil {
					m.flashMsg = "clipboard error: " + err.Error()
				} else {
					m.flashMsg = "copied (Ctrl+C again to exit)"
				}
			} else {
				m.flashMsg = "Press Ctrl+C again to exit"
			}
			m.flashUntil = now.Add(doubleCtrlC)
			return m, nil
		}

		if msg.Type == tea.KeyCtrlD || msg.String() == "ctrl+d" {
			if m.input.Value() == "" && !m.streaming {
				return m, tea.Quit
			}
			return m, nil
		}

		// Escape explicitly removes focus (cursor turns into hollow white rectangle, static)
		if msg.String() == "esc" {
			m.focused = false
			m.input.Blur()
			m.input.Cursor.SetMode(cursor.CursorStatic)
			return m, nil
		}

		// Keyboard input activates focus and white blinking cursor
		var focusCmd tea.Cmd
		if !m.focused {
			m.focused = true
			focusCmd = m.input.Focus()
			m.input.Cursor.SetMode(cursor.CursorBlink)
		}

		switch msg.String() {
		case "pgup", "pageup":
			m.viewport.HalfViewUp()
			return m, focusCmd

		case "pgdown", "pagedown":
			m.viewport.HalfViewDown()
			return m, focusCmd

		case "shift+up", "alt+up":
			m.viewport.ScrollUp(2)
			return m, focusCmd

		case "shift+down", "alt+down":
			m.viewport.ScrollDown(2)
			return m, focusCmd

		case "ctrl+u":
			m.viewport.HalfViewUp()
			return m, focusCmd

		case "home":
			if m.input.Value() == "" {
				m.viewport.GotoTop()
				return m, focusCmd
			}

		case "end":
			if m.input.Value() == "" {
				m.viewport.GotoBottom()
				return m, focusCmd
			}

		case "up":
			if len(m.history) > 0 && m.historyIdx > 0 {
				m.historyIdx--
				if m.historyIdx >= 0 && m.historyIdx < len(m.history) {
					m.input.SetValue(m.history[m.historyIdx])
					m.input.CursorEnd()
				}
				return m, focusCmd
			}
			// When at top of command history or no history, scroll output viewport up
			m.viewport.ScrollUp(1)
			return m, focusCmd

		case "down":
			if len(m.history) > 0 {
				if m.historyIdx < len(m.history)-1 {
					m.historyIdx++
					if m.historyIdx >= 0 && m.historyIdx < len(m.history) {
						m.input.SetValue(m.history[m.historyIdx])
						m.input.CursorEnd()
					}
					return m, focusCmd
				} else if m.historyIdx == len(m.history)-1 {
					m.historyIdx = len(m.history)
					m.input.SetValue("")
					return m, focusCmd
				}
			}
			// When at bottom of history, scroll output viewport down
			m.viewport.ScrollDown(1)
			return m, focusCmd

		case "ctrl+y", "ctrl+shift+c":
			// Copy clean session output or last response to clipboard
			textToCopy := m.getLastResponse()
			if textToCopy == "" && len(m.lines) > 0 {
				textToCopy = ansi.Strip(strings.Join(m.lines, "\n"))
			}
			if textToCopy != "" {
				if err := session.CopyToClipboard(textToCopy); err != nil {
					m.flashMsg = "clipboard error: " + err.Error()
				} else {
					m.flashMsg = "copied to clipboard"
				}
				m.flashUntil = time.Now().Add(2 * time.Second)
			}
			return m, focusCmd

		case "enter", "ctrl+j":
			if m.streaming {
				return m, nil
			}

			line := strings.TrimSpace(m.input.Value())
			m.input.SetValue("")
			if line == "" {
				return m, nil
			}

			m.history = append(m.history, line)
			m.historyIdx = len(m.history)

			promptMarker := lipgloss.NewStyle().Foreground(lipgloss.Color(colorPrompt)).Bold(true).Render("> ")
			userText := lipgloss.NewStyle().Foreground(lipgloss.Color("#E2E8F0")).Render(line)
			m.lines = append(m.lines, promptMarker+userText)
			m.enforceScrollbackCap()
			m.viewport.SetContent(strings.Join(m.lines, "\n"))
			m.viewport.GotoBottom()

			if strings.HasPrefix(line, "/") || line == "?" {
				output, quit := m.backend.ExecuteSlash(line)
				if quit {
					return m, tea.Quit
				}
				if line == "/clear" {
					m.lines = nil
				} else if output != "" {
					outLines := strings.Split(output, "\n")
					m.lines = append(m.lines, outLines...)
					m.lines = append(m.lines, "")
					m.enforceScrollbackCap()
				}
				m.recalculateViewport()
				m.viewport.GotoBottom()
				return m, nil
			}

			// Free-text query to agent
			m.streaming = true
			m.input.Blur()
			m.lines = append(m.lines, "")
			m.enforceScrollbackCap()
			m.recalculateViewport()
			m.viewport.GotoBottom()
			ctx, cancel := context.WithCancel(context.Background())
			m.streamCancel = cancel
			tokenChan, errChan := m.backend.StreamQuery(ctx, line)
			m.tokenChan = tokenChan
			m.errChan = errChan
			return m, readNextToken(tokenChan, errChan)
		}
	}

	var cmdInput, cmdVP tea.Cmd
	if !m.streaming {
		m.input, cmdInput = m.input.Update(msg)
	}
	m.viewport, cmdVP = m.viewport.Update(msg)
	return m, tea.Batch(cmdInput, cmdVP)
}

func (m AppModel) getLastResponse() string {
	if len(m.lines) == 0 {
		return ""
	}
	var lastUserPrompt string
	if len(m.history) > 0 {
		lastUserPrompt = "> " + m.history[len(m.history)-1]
	}
	var block []string
	for i := len(m.lines) - 1; i >= 0; i-- {
		l := ansi.Strip(m.lines[i])
		if lastUserPrompt != "" && strings.TrimSpace(l) == strings.TrimSpace(lastUserPrompt) {
			break
		}
		if strings.TrimSpace(l) != "" && !strings.HasPrefix(l, "── $") {
			block = append([]string{l}, block...)
		}
	}
	if len(block) > 0 {
		return strings.Join(block, "\n")
	}
	return ansi.Strip(strings.Join(m.lines, "\n"))
}

func (m AppModel) renderInput() string {
	prompt := m.input.PromptStyle.Render(m.input.Prompt)
	val := m.input.Value()
	pos := m.input.Position()
	runes := []rune(val)
	if pos < 0 {
		pos = 0
	}
	if pos > len(runes) {
		pos = len(runes)
	}

	whiteStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF"))

	var cursorStr string
	if m.focused {
		// Focused / Active: Solid white-filled square '█', blinks with cursor blink cycle
		if m.input.Cursor.Blink {
			cursorStr = " "
		} else {
			cursorStr = whiteStyle.Render("█")
		}
	} else {
		// Unfocused / Inactive: Hollow square '⎕' in white, static (does not blink)
		cursorStr = whiteStyle.Render("⎕")
	}

	var text string
	if pos < len(runes) {
		char := string(runes[pos])
		var cursorChar string
		if m.focused {
			if m.input.Cursor.Blink {
				cursorChar = whiteStyle.Render(char)
			} else {
				cursorChar = lipgloss.NewStyle().Background(lipgloss.Color("#FFFFFF")).Foreground(lipgloss.Color("#000000")).Render(char)
			}
		} else {
			cursorChar = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Underline(true).Render(char)
		}
		text = string(runes[:pos]) + cursorChar + string(runes[pos+1:])
	} else {
		text = string(runes) + cursorStr
	}
	return prompt + text
}

func (m AppModel) renderBottom() string {
	sepStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#333333"))
	sep := sepStyle.Render(strings.Repeat("─", m.width))

	input := "  " + m.renderInput()
	status := m.statusLine(m.width)

	return strings.Join([]string{
		sep,
		input,
		sep,
		status,
	}, "\n")
}

func (m AppModel) View() string {
	bottom := m.renderBottom()
	bottomHeight := 4

	if len(m.lines) == 0 {
		header := renderHeader(m.version, m.cwd, m.width)
		headerHeight := lipgloss.Height(header)
		vpHeight := m.height - headerHeight - bottomHeight
		if vpHeight < 0 {
			vpHeight = 0
		}
		var emptyLines []string
		for i := 0; i < vpHeight; i++ {
			emptyLines = append(emptyLines, "")
		}
		parts := []string{header}
		if len(emptyLines) > 0 {
			parts = append(parts, strings.Join(emptyLines, "\n"))
		}
		parts = append(parts, bottom)
		return strings.Join(parts, "\n")
	}

	// Active conversation: text occupies the ENTIRE terminal from line 1 down to the bottom prompt
	vpHeight := m.height - bottomHeight
	if vpHeight < 1 {
		vpHeight = 1
	}

	vpView := m.viewport.View()
	vpLines := strings.Split(vpView, "\n")
	if len(vpLines) > vpHeight {
		vpLines = vpLines[:vpHeight]
	}
	for len(vpLines) < vpHeight {
		vpLines = append(vpLines, "")
	}

	return strings.Join([]string{
		strings.Join(vpLines, "\n"),
		bottom,
	}, "\n")
}

func (m AppModel) statusLine(w int) string {
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color(colorDim))
	modelStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(colorTeal))

	left := "? for shortcuts • Right-Click / Ctrl+Shift+C / Ctrl+C to copy"
	if m.flashMsg != "" && time.Now().Before(m.flashUntil) {
		left = "[" + m.flashMsg + "]"
		dim = lipgloss.NewStyle().Foreground(lipgloss.Color(colorTeal)).Bold(true)
	}

	model := m.backend.ActiveModel()
	if model == "" {
		model = "claude-opus-5.5"
	}
	right := "model: " + model

	avail := w - 4
	if avail < 1 {
		avail = 1
	}

	leftW := lipgloss.Width(left)
	rightW := lipgloss.Width(right)

	if leftW+rightW+1 > avail {
		if w < 45 {
			right = model
			rightW = lipgloss.Width(right)
		}
	}

	gap := avail - leftW - rightW
	if gap < 1 {
		gap = 1
	}

	return "  " + dim.Render(left) + strings.Repeat(" ", gap) + modelStyle.Render(right)
}
