// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package ui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

const (
	menuRows    = 8
	modelPrefix = "/model "
)

type menuItem struct {
	label string
	desc  string
	value string // empty means non-selectable info row
}

type modelsMsg struct {
	items []ModelItem
	err   error
}

func fetchModelsCmd(b Backend) tea.Cmd {
	return func() tea.Msg {
		items, err := b.ListModels()
		return modelsMsg{items: items, err: err}
	}
}

// menuKind returns "command", "model" or "" for the current input.
func (m AppModel) menuKind() string {
	val := m.input.Value()
	if m.streaming || val == "" || val == m.dismissed || !strings.HasPrefix(val, "/") {
		return ""
	}
	if strings.HasPrefix(val, modelPrefix) {
		return "model"
	}
	if strings.Contains(val, " ") {
		return ""
	}
	return "command"
}

func (m AppModel) menuItems() []menuItem {
	val := m.input.Value()
	switch m.menuKind() {
	case "command":
		prefix := strings.ToLower(val)
		var items []menuItem
		for _, c := range m.backend.Commands() {
			if strings.HasPrefix(c.Name, prefix) {
				label := c.Name
				if c.ArgsSpec != "" {
					label += " " + c.ArgsSpec
				}
				items = append(items, menuItem{label: label, desc: c.Description, value: c.Name})
			}
		}
		return items
	case "model":
		if m.modelsErr != "" {
			return []menuItem{{label: "model list unavailable: " + m.modelsErr}}
		}
		if !m.modelsLoaded {
			return []menuItem{{label: "loading models..."}}
		}
		filter := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(val, modelPrefix)))
		var items []menuItem
		for _, mi := range m.models {
			if filter == "" || strings.Contains(strings.ToLower(mi.Ref), filter) {
				items = append(items, menuItem{label: mi.Ref, value: mi.Ref})
			}
		}
		if len(items) == 0 {
			return []menuItem{{label: "no model matches '" + filter + "'"}}
		}
		return items
	}
	return nil
}

func (m AppModel) menuHeight() int {
	n := len(m.menuItems())
	if n > menuRows {
		n = menuRows
	}
	return n
}

func (m AppModel) renderMenu() []string {
	items := m.menuItems()
	if len(items) == 0 {
		return nil
	}
	idx := m.menuIdx
	if idx >= len(items) {
		idx = len(items) - 1
	}
	start := 0
	if idx >= menuRows {
		start = idx - menuRows + 1
	}
	end := start + menuRows
	if end > len(items) {
		end = len(items)
	}
	sel := lipgloss.NewStyle().Foreground(lipgloss.Color(colorTeal)).Bold(true)
	norm := lipgloss.NewStyle().Foreground(lipgloss.Color(colorPrompt))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color(colorDim))
	kind := m.menuKind()

	labelW := 0
	for _, it := range items[start:end] {
		if w := lipgloss.Width(it.label); w > labelW {
			labelW = w
		}
	}
	if labelW > m.width/2 && kind == "command" {
		labelW = m.width / 2
	}
	var out []string
	for i := start; i < end; i++ {
		it := items[i]
		marker := "  "
		style := norm
		if it.value == "" {
			style = dim
		} else if i == idx {
			marker = "> "
			style = sel
		}
		label := ansi.Truncate(it.label, labelW, "")
		pad := strings.Repeat(" ", labelW-lipgloss.Width(label))
		line := "  " + marker + style.Render(label) + pad
		if it.desc != "" {
			line += "  " + dim.Render(it.desc)
		}
		out = append(out, ansi.Truncate(line, m.width, ""))
	}
	return out
}

// applyMenu handles navigation keys. handled reports whether the key was consumed;
// execute reports that the input has been rewritten and must now be submitted.
func (m *AppModel) applyMenu(key string) (handled, execute bool) {
	kind := m.menuKind()
	if kind == "" {
		return false, false
	}
	items := m.menuItems()
	if len(items) == 0 {
		return false, false
	}
	if m.menuIdx >= len(items) {
		m.menuIdx = len(items) - 1
	}
	switch key {
	case "up":
		if m.menuIdx > 0 {
			m.menuIdx--
		}
		return true, false
	case "down":
		if m.menuIdx < len(items)-1 {
			m.menuIdx++
		}
		return true, false
	case "esc":
		m.dismissed = m.input.Value()
		return true, false
	case "tab", "enter", "ctrl+j":
		sel := items[m.menuIdx]
		if sel.value == "" {
			return true, false
		}
		if kind == "model" {
			m.input.SetValue(modelPrefix + sel.value)
			m.input.CursorEnd()
			return true, key != "tab"
		}
		val := strings.TrimSpace(m.input.Value())
		if val != sel.value || (sel.value == "/model" && key != "tab") || key == "tab" {
			next := sel.value
			if sel.value == "/model" || strings.Contains(sel.label, " ") {
				next += " "
			}
			m.input.SetValue(next)
			m.input.CursorEnd()
			return true, false
		}
		return false, false
	}
	return false, false
}

// styleInput colors a leading slash command token differently from its arguments.
func styleInput(s string) string {
	blue := lipgloss.NewStyle().Foreground(lipgloss.Color(colorPrompt)).Bold(true)
	if !strings.HasPrefix(s, "/") {
		return blue.Render(s)
	}
	cmd := lipgloss.NewStyle().Foreground(lipgloss.Color(colorTeal)).Bold(true)
	i := strings.IndexByte(s, ' ')
	if i < 0 {
		return cmd.Render(s)
	}
	return cmd.Render(s[:i]) + blue.Render(s[i:])
}
