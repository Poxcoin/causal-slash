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
	menuRows    = 10
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

		// Group order for clean structured browsing
		familyOrder := []string{
			"Claude (Anthropic)",
			"ChatGPT (OpenAI)",
			"Gemini (Google)",
			"DeepSeek",
			"Llama (Meta)",
			"Qwen (Alibaba)",
			"Mistral AI",
			"Other / Community",
		}

		for _, fam := range familyOrder {
			var famItems []menuItem
			for _, mi := range m.models {
				if mi.Family != fam && fam != "Other / Community" {
					continue
				}
				if fam == "Other / Community" && mi.Family != "" && mi.Family != "Other / Community" {
					continue
				}

				// Match by filter across ref, friendly name, or family tag
				match := filter == "" ||
					strings.Contains(strings.ToLower(mi.Ref), filter) ||
					strings.Contains(strings.ToLower(mi.Name), filter) ||
					strings.Contains(strings.ToLower(mi.Family), filter)

				if match {
					displayName := mi.Ref
					if mi.Name != "" {
						displayName = mi.Name
					}
					famItems = append(famItems, menuItem{
						label: displayName,
						desc:  "[" + fam + "] " + mi.Ref,
						value: mi.Ref,
					})
				}
			}

			if len(famItems) > 0 {
				// Category header row (non-selectable)
				items = append(items, menuItem{
					label: "--- " + fam + " ---",
					desc:  "",
					value: "",
				})
				items = append(items, famItems...)
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
	kind := m.menuKind()
	n := len(m.menuItems())
	if n > menuRows {
		n = menuRows
	}
	if kind == "model" {
		// Switch Model header (3) + effort slider & legend (6)
		n += 9
	}
	return n
}

func (m AppModel) renderMenu() []string {
	kind := m.menuKind()
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

	titleStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Bold(true)
	sel := lipgloss.NewStyle().Foreground(lipgloss.Color(colorTeal)).Bold(true)
	norm := lipgloss.NewStyle().Foreground(lipgloss.Color(colorPrompt))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color(colorDim))
	categoryStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(colorWarn)).Bold(true)
	currentTag := lipgloss.NewStyle().Foreground(lipgloss.Color(colorTeal)).Italic(true)

	labelW := 0
	for _, it := range items[start:end] {
		if it.value != "" {
			if w := lipgloss.Width(it.label); w > labelW {
				labelW = w
			}
		}
	}
	if labelW > m.width/2 && kind == "command" {
		labelW = m.width / 2
	}

	var out []string
	if kind == "model" {
		out = append(out, "  "+titleStyle.Render("Switch Model"))
		searchQuery := strings.TrimPrefix(m.input.Value(), modelPrefix)
		out = append(out, "  "+dim.Render("Search: ")+lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Render(searchQuery))
		out = append(out, "")
	}

	activeModel := m.backend.ActiveModel()
	for i := start; i < end; i++ {
		it := items[i]
		if it.value == "" {
			// Header section like --- Claude (Anthropic) ---
			out = append(out, "  "+categoryStyle.Render(it.label))
			continue
		}

		marker := "  "
		style := norm
		if i == idx {
			marker = "> "
			style = sel
		}
		label := ansi.Truncate(it.label, labelW, "")
		pad := strings.Repeat(" ", labelW-lipgloss.Width(label))
		line := "  " + marker + style.Render(label) + pad

		if it.value != "" && strings.EqualFold(it.value, activeModel) {
			line += "  " + currentTag.Render("(current)")
		} else if it.desc != "" {
			line += "  " + dim.Render(it.desc)
		}
		out = append(out, ansi.Truncate(line, m.width, ""))
	}

	if kind == "model" {
		out = append(out, "")
		effort := "medium"
		if e := m.effort(); e != "" {
			effort = e
		}

		bar := renderEffortSlider(effort)
		out = append(out, "  "+dim.Render("Effort ")+bar)

		var effortSubtext string
		switch effort {
		case "low":
			effortSubtext = "Fast response with minimal reasoning latency"
		case "high":
			effortSubtext = "Deepest reasoning for complex problems - slower but strongest"
		default:
			effortSubtext = "Balanced speed and reasoning quality for most tasks"
		}
		out = append(out, "         "+lipgloss.NewStyle().Foreground(lipgloss.Color(colorDim)).Italic(true).Render(effortSubtext))
		out = append(out, "")
		navLegend := lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Bold(true).Render("Keyboard: ") +
			sel.Render("↑/↓") + dim.Render(" Navigate  ") +
			sel.Render("←/→") + dim.Render(" Effort  ") +
			sel.Render("enter") + dim.Render(" Select  ") +
			sel.Render("esc") + dim.Render(" Go Back")
		out = append(out, "  "+navLegend)
	}

	return out
}

func renderEffortSlider(effort string) string {
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color(colorDim))
	warn := lipgloss.NewStyle().Foreground(lipgloss.Color(colorWarn)).Bold(true)
	line := lipgloss.NewStyle().Foreground(lipgloss.Color(colorWarn)).Render("──────────────")

	lowDot := "○"
	medDot := "○"
	highDot := "○"

	switch effort {
	case "low":
		lowDot = "●"
		return dim.Render("◄ ") + warn.Render(lowDot) + line + dim.Render(medDot) + line + dim.Render(highDot) + dim.Render(" ►")
	case "high":
		highDot = "●"
		return dim.Render("◄ ") + dim.Render(lowDot) + line + dim.Render(medDot) + line + warn.Render(highDot) + dim.Render(" ►")
	default:
		medDot = "●"
		return dim.Render("◄ ") + dim.Render(lowDot) + line + warn.Render(medDot) + line + dim.Render(highDot) + dim.Render(" ►")
	}
}

func (m AppModel) effort() string {
	if m.backend != nil {
		if s, ok := m.backend.(interface{ ReasoningEffort() string }); ok {
			return s.ReasoningEffort()
		}
	}
	return "medium"
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
	if kind == "model" {
		switch key {
		case "left":
			if e := m.effort(); e == "high" {
				m.setEffort("medium")
			} else if e == "medium" {
				m.setEffort("low")
			}
			return true, false
		case "right":
			if e := m.effort(); e == "low" {
				m.setEffort("medium")
			} else if e == "medium" {
				m.setEffort("high")
			}
			return true, false
		}
	}

	switch key {
	case "up":
		for m.menuIdx > 0 {
			m.menuIdx--
			if items[m.menuIdx].value != "" {
				break
			}
		}
		return true, false
	case "down":
		for m.menuIdx < len(items)-1 {
			m.menuIdx++
			if items[m.menuIdx].value != "" {
				break
			}
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

func (m *AppModel) setEffort(effort string) {
	if m.backend != nil {
		if s, ok := m.backend.(interface{ SetReasoningEffort(string) }); ok {
			s.SetReasoningEffort(effort)
		}
	}
}
