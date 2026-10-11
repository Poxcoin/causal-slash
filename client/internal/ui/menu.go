// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package ui

import (
	"fmt"
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
	value string // empty means non-selectable info row / back
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

// Known top AI companies
var Companies = []struct {
	ID   string
	Name string
	Desc string
}{
	{"anthropic", "Anthropic", "Claude 3.7 / 3.5 Sonnet, Opus frontier reasoning"},
	{"openai", "OpenAI", "o3, o1, GPT-4o, GPT-4.5 frontier models"},
	{"google", "Google", "Gemini 2.5 Pro / Flash ultra-fast multimodel"},
	{"deepseek", "DeepSeek", "DeepSeek R1 reasoning, V3 open frontier"},
	{"meta", "Meta (Llama)", "Llama 3.3 70B, Llama 3.1 405B open weights"},
	{"qwen", "Qwen (Alibaba)", "Qwen 2.5 72B, QwQ frontier code & math"},
	{"mistral", "Mistral AI", "Mistral Large 4, Codestral premier coding"},
}

// isJunkModel filters out batch, toy, embedding, and outdated small models (< 14B)
func isJunkModel(id, name string) bool {
	lowerID := strings.ToLower(id)
	lowerName := strings.ToLower(name)

	// Filter out non-interactive batch & utility models
	if strings.Contains(lowerID, ":batch") ||
		strings.Contains(lowerID, "embed") ||
		strings.Contains(lowerID, "whisper") ||
		strings.Contains(lowerID, "guard") ||
		strings.Contains(lowerID, "moderation") ||
		strings.Contains(lowerID, "image") {
		return true
	}

	// Filter out small toy models (< 14B)
	toyTokens := []string{
		"-1b", "/1b", " 1b",
		"-2b", "/2b", " 2b",
		"-3b", "/3b", " 3b",
		"-4b", "/4b", " 4b",
		"-7b", "/7b", " 7b",
		"-8b", "/8b", " 8b",
		"nano", "mini", "tiny", "lite",
	}
	// Exception: o3-mini and o1-mini from OpenAI are strong frontier models
	if strings.Contains(lowerID, "o3-mini") || strings.Contains(lowerID, "o1-mini") {
		return false
	}

	for _, t := range toyTokens {
		if strings.Contains(lowerID, t) || strings.Contains(lowerName, t) {
			return true
		}
	}
	return false
}

func matchesCompany(companyID, ref, family string) bool {
	lowerRef := strings.ToLower(ref)
	switch companyID {
	case "anthropic":
		return strings.Contains(lowerRef, "anthropic") || strings.Contains(lowerRef, "claude")
	case "openai":
		return strings.Contains(lowerRef, "openai") || strings.Contains(lowerRef, "gpt") || strings.Contains(lowerRef, "o1") || strings.Contains(lowerRef, "o3")
	case "google":
		return strings.Contains(lowerRef, "google") || strings.Contains(lowerRef, "gemini")
	case "deepseek":
		return strings.Contains(lowerRef, "deepseek")
	case "meta":
		return strings.Contains(lowerRef, "meta-llama") || strings.Contains(lowerRef, "llama")
	case "qwen":
		return strings.Contains(lowerRef, "qwen") || strings.Contains(lowerRef, "qwq")
	case "mistral":
		return strings.Contains(lowerRef, "mistral") || strings.Contains(lowerRef, "codestral")
	}
	return false
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

		// LEVEL 1: If no company selected and no active text search, show Company List
		if m.selectedCompany == "" && filter == "" {
			var items []menuItem
			for _, comp := range Companies {
				items = append(items, menuItem{
					label: comp.Name,
					desc:  comp.Desc,
					value: "company:" + comp.ID,
				})
			}
			return items
		}

		// LEVEL 2: Show curated models for selected company OR global search results
		var items []menuItem
		if m.selectedCompany != "" {
			items = append(items, menuItem{
				label: "◄ Back to Companies",
				desc:  "Press Enter or Esc to return",
				value: "back:companies",
			})
		}

		for _, mi := range m.models {
			if isJunkModel(mi.Ref, mi.Name) {
				continue
			}

			if m.selectedCompany != "" {
				if !matchesCompany(m.selectedCompany, mi.Ref, mi.Family) {
					continue
				}
			}

			// Filter check
			if filter != "" {
				searchMatch := strings.Contains(strings.ToLower(mi.Ref), filter) ||
					strings.Contains(strings.ToLower(mi.Name), filter) ||
					strings.Contains(strings.ToLower(mi.Family), filter)
				if !searchMatch {
					continue
				}
			}

			displayName := mi.Ref
			if mi.Name != "" {
				displayName = mi.Name
			}

			items = append(items, menuItem{
				label: displayName,
				desc:  mi.Ref,
				value: mi.Ref,
			})
		}

		if len(items) == 0 {
			return []menuItem{{label: "no frontier models match '" + filter + "'"}}
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
	norm := lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF"))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color(colorDim))
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
		headerText := "Switch Model"
		if m.selectedCompany != "" {
			for _, c := range Companies {
				if c.ID == m.selectedCompany {
					headerText = "Switch Model › " + c.Name
					break
				}
			}
		}
		out = append(out, "  "+titleStyle.Render(headerText))
		searchQuery := strings.TrimPrefix(m.input.Value(), modelPrefix)
		cursorBlock := lipgloss.NewStyle().Background(lipgloss.Color("#FFFFFF")).Foreground(lipgloss.Color("#000000")).Render(" ")
		out = append(out, fmt.Sprintf("    Search: %s%s", lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Render(searchQuery), cursorBlock))
		underlineW := lipgloss.Width(searchQuery) + 8
		if underlineW < 22 {
			underlineW = 22
		}
		out = append(out, "            "+dim.Render(strings.Repeat("─", underlineW)))
		out = append(out, "")
	}

	activeModel := m.backend.ActiveModel()
	for i := start; i < end; i++ {
		it := items[i]
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

		bar, subtext := renderEffortSlider(effort)
		out = append(out, "  "+dim.Render("Effort ")+bar)
		out = append(out, "  "+lipgloss.NewStyle().Foreground(lipgloss.Color(colorDim)).Italic(true).Render(subtext))
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

func renderEffortSlider(effort string) (bar string, subtext string) {
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color(colorDim))
	green := lipgloss.NewStyle().Foreground(lipgloss.Color("#10B981")).Bold(true)
	yellow := lipgloss.NewStyle().Foreground(lipgloss.Color("#F59E0B")).Bold(true)
	salmon := lipgloss.NewStyle().Foreground(lipgloss.Color("#F87171")).Bold(true)

	arrowL := dim.Render("◄")
	arrowR := dim.Render("►")
	segment := "────────────"
	dimSeg := dim.Render(segment)

	var dLow, dMed, dHigh string
	var seg1, seg2 string
	var lLow, lMed, lHigh string

	switch effort {
	case "low":
		dLow = green.Render("◎")
		dMed = dim.Render("○")
		dHigh = dim.Render("○")
		seg1 = dimSeg
		seg2 = dimSeg
		lLow = green.Render("low")
		lMed = dim.Render("medium")
		lHigh = dim.Render("high")
		subtext = "Faster responses, lighter reasoning - great for simpler tasks"
	case "high":
		dLow = dim.Render("○")
		dMed = dim.Render("○")
		dHigh = salmon.Render("◎")
		seg1 = lipgloss.NewStyle().Foreground(lipgloss.Color("#F87171")).Render(segment)
		seg2 = lipgloss.NewStyle().Foreground(lipgloss.Color("#F87171")).Render(segment)
		lLow = dim.Render("low")
		lMed = dim.Render("medium")
		lHigh = salmon.Render("high")
		subtext = "Deepest reasoning for complex problems - slower but strongest"
	default: // medium
		dLow = dim.Render("○")
		dMed = yellow.Render("◎")
		dHigh = dim.Render("○")
		seg1 = lipgloss.NewStyle().Foreground(lipgloss.Color("#F59E0B")).Render(segment)
		seg2 = dimSeg
		lLow = dim.Render("low")
		lMed = yellow.Render("medium")
		lHigh = dim.Render("high")
		subtext = "Balanced speed and reasoning quality for most tasks"
	}

	track := fmt.Sprintf("%s   %s%s%s%s%s   %s", arrowL, dLow, seg1, dMed, seg2, dHigh, arrowR)
	labels := fmt.Sprintf("    %s          %s          %s", lLow, lMed, lHigh)
	bar = track + "\n" + labels
	return bar, subtext
}

func (m AppModel) effort() string {
	if m.backend != nil {
		if s, ok := m.backend.(interface{ ReasoningEffort() string }); ok {
			return s.ReasoningEffort()
		}
	}
	return "medium"
}

// applyMenu handles navigation keys.
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
		case "esc":
			if m.selectedCompany != "" {
				m.selectedCompany = ""
				m.menuIdx = 0
				return true, false
			}
			m.dismissed = m.input.Value()
			return true, false
		}
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
			if strings.HasPrefix(sel.value, "company:") {
				m.selectedCompany = strings.TrimPrefix(sel.value, "company:")
				m.menuIdx = 0
				return true, false
			}
			if sel.value == "back:companies" {
				m.selectedCompany = ""
				m.menuIdx = 0
				return true, false
			}

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

func (m *AppModel) setEffort(effort string) {
	if m.backend != nil {
		if s, ok := m.backend.(interface{ SetReasoningEffort(string) }); ok {
			s.SetReasoningEffort(effort)
		}
	}
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
