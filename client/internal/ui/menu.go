// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package ui

import (
	"fmt"
	"strings"

	"csls/internal/session"
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

// Top AI companies
var Companies = []struct {
	ID   string
	Name string
	Desc string
}{
	{"anthropic", "Anthropic", "Claude Opus 5.5, Sonnet 5.5, Haiku 5.5 series"},
	{"openai", "OpenAI", "GPT-6.1 Sol, GPT-6 Luna series"},
	{"google", "Google", "Gemini 4 Argon, Project Astra series"},
	{"deepseek", "DeepSeek", "DeepSeek-V4-Pro, DeepSeek-V4.1-Flash series"},
	{"qwen", "Qwen (Alibaba)", "Qwen 3.8, 3.7, 3.5 series"},
	{"meta-llama", "Meta (Llama)", "Llama 4, Llama 3.3 70B series"},
	{"mistralai", "Mistral AI", "Mistral Large 4, Codestral series"},
}

// isJunkModel filters out batch, whisper, image generation, embeddings, and toy micro-models (<8B)
func isJunkModel(ref, name string) bool {
	lower := strings.ToLower(ref)
	if strings.Contains(lower, ":batch") ||
		strings.Contains(lower, "whisper") ||
		strings.Contains(lower, "embed") ||
		strings.Contains(lower, "image") ||
		strings.Contains(lower, "audio") ||
		strings.Contains(lower, "guard") ||
		strings.Contains(lower, "moderation") {
		return true
	}

	// Filter out tiny toy models (< 8B)
	toyTokens := []string{
		"-1b", "/1b", " 1b",
		"-2b", "/2b", " 2b",
		"-3b", "/3b", " 3b",
		"-4b", "/4b", " 4b",
		"-7b", "/7b", " 7b",
		"-8b", "/8b", " 8b",
		"nano", "mini",
	}
	for _, t := range toyTokens {
		if strings.Contains(lower, t) || strings.Contains(strings.ToLower(name), t) {
			return true
		}
	}
	return false
}

// matchesCompany checks if live model belongs to the selected company
func matchesCompany(companyID, ref string) bool {
	cleanID := strings.TrimPrefix(ref, "openrouter:")
	cleanID = strings.TrimPrefix(cleanID, "groq:")
	lower := strings.ToLower(cleanID)

	switch companyID {
	case "anthropic":
		return strings.HasPrefix(lower, "anthropic/") || strings.Contains(lower, "claude")
	case "openai":
		return strings.HasPrefix(lower, "openai/") || strings.Contains(lower, "gpt")
	case "google":
		return strings.HasPrefix(lower, "google/") || strings.Contains(lower, "gemini")
	case "deepseek":
		return strings.HasPrefix(lower, "deepseek/") || strings.Contains(lower, "deepseek")
	case "qwen":
		return strings.HasPrefix(lower, "qwen/") || strings.Contains(lower, "qwen") || strings.Contains(lower, "qwq")
	case "meta-llama":
		return strings.HasPrefix(lower, "meta-llama/") || strings.Contains(lower, "llama") || strings.Contains(lower, "hermes")
	case "mistralai":
		return strings.HasPrefix(lower, "mistralai/") || strings.Contains(lower, "mistral") || strings.Contains(lower, "codestral")
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
			return []menuItem{{label: "loading live models from OpenRouter..."}}
		}

		filter := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(val, modelPrefix)))

		// LEVEL 1: If no company selected and no active search query, show Companies
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

		// LEVEL 2: Show ALL live models for the selected company
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
				if !matchesCompany(m.selectedCompany, mi.Ref) {
					continue
				}
			}

			// Filter check if search query is active
			if filter != "" {
				searchMatch := strings.Contains(strings.ToLower(mi.Ref), filter) ||
					strings.Contains(strings.ToLower(mi.Name), filter)
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
			return []menuItem{{label: "no live models match '" + filter + "'"}}
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

// FormatInitialTurns converts loaded chat messages into styled terminal lines.
func FormatInitialTurns(messages []session.ChatMessage) []string {
	if len(messages) == 0 {
		return nil
	}
	var lines []string
	promptMarker := lipgloss.NewStyle().Foreground(lipgloss.Color(colorPrompt)).Bold(true).Render("> ")
	for _, m := range messages {
		switch m.Role {
		case "user":
			lines = append(lines, promptMarker+styleInput(m.Content))
		case "assistant":
			parts := strings.Split(m.Content, "\n")
			lines = append(lines, parts...)
			lines = append(lines, "")
		case "system":
			sysStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(colorDim)).Italic(true)
			lines = append(lines, sysStyle.Render(m.Content))
			lines = append(lines, "")
		}
	}
	return lines
}
