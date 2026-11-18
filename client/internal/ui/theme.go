// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package ui

import (
	"fmt"
	"strings"

	"csls/internal/session"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ThemeOption represents one selectable color scheme.
type ThemeOption struct {
	ID          string
	Name        string
	Description string
	Preview     string
}

// AvailableThemes lists the 4 canonical terminal themes.
var AvailableThemes = []ThemeOption{
	{
		ID:          "cyber-emerald",
		Name:        "Cyber Emerald",
		Description: "Deep obsidian black with glowing Base L2 teal & emerald accents (Default)",
		Preview:     "#21E2CC / #10B981",
	},
	{
		ID:          "neon-amber",
		Name:        "Neon Amber",
		Description: "Warm retro phosphor terminal amber with golden prompt accents",
		Preview:     "#F59E0B / #FBBF24",
	},
	{
		ID:          "cyberpunk-cyan",
		Name:        "Cyberpunk Cyan",
		Description: "High-voltage electric cyan & violet neon Tokyo Night aesthetic",
		Preview:     "#06B6D4 / #A855F7",
	},
	{
		ID:          "monochrome-dark",
		Name:        "Monochrome Dark",
		Description: "Minimalist ultra-high contrast pure white & slate monochrome",
		Preview:     "#F8FAFC / #94A3B8",
	},
}

// activePrimaryColor returns the primary accent hex color for the currently active theme.
func activePrimaryColor() string {
	switch session.LoadTheme() {
	case "neon-amber":
		return "#F59E0B"
	case "cyberpunk-cyan":
		return "#06B6D4"
	case "monochrome-dark":
		return "#F8FAFC"
	default:
		return colorTeal
	}
}

// activePromptColor returns the prompt/input accent hex color for the currently active theme.
func activePromptColor() string {
	switch session.LoadTheme() {
	case "neon-amber":
		return "#FBBF24"
	case "cyberpunk-cyan":
		return "#A855F7"
	case "monochrome-dark":
		return "#94A3B8"
	default:
		return colorPrompt
	}
}

// ThemeWizard provides a clean interactive first-launch theme selection model.
type ThemeWizard struct {
	cursor   int
	selected string
	quitting bool
	saveErr  error
}

// NewThemeWizard creates the theme onboarding wizard.
func NewThemeWizard() ThemeWizard {
	return ThemeWizard{
		cursor:   0,
		selected: "cyber-emerald",
	}
}

func (m ThemeWizard) Init() tea.Cmd {
	return nil
}

func (m ThemeWizard) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			// Cancelling must not overwrite an existing theme or hide save errors.
			m.quitting = true
			return m, tea.Quit

		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			} else {
				m.cursor = len(AvailableThemes) - 1
			}

		case "down", "j":
			if m.cursor < len(AvailableThemes)-1 {
				m.cursor++
			} else {
				m.cursor = 0
			}

		case "enter", " ":
			chosen := AvailableThemes[m.cursor].ID
			if err := session.SaveTheme(chosen); err != nil {
				m.saveErr = err
				return m, nil
			}
			m.saveErr = nil
			m.selected = chosen
			m.quitting = true
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m ThemeWizard) View() string {
	if m.quitting {
		return ""
	}

	teal := lipgloss.NewStyle().Foreground(lipgloss.Color(colorTeal)).Bold(true)
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color(colorDim))
	green := lipgloss.NewStyle().Foreground(lipgloss.Color("#10B981")).Bold(true)
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(colorTeal)).
		Padding(1, 2).
		Margin(1, 2)

	var sb strings.Builder
	sb.WriteString(teal.Render("Welcome to Causal-Slash Protocol (CSLS) CLI") + "\n")
	sb.WriteString(dim.Render("Select your terminal appearance & color scheme (you can change this anytime with /theme):") + "\n\n")

	for i, t := range AvailableThemes {
		cursor := "  "
		itemStyle := dim
		if m.cursor == i {
			cursor = green.Render("> ")
			itemStyle = teal
		}
		sb.WriteString(fmt.Sprintf("%s[%d] %-18s %s\n", cursor, i+1, itemStyle.Render(t.Name), dim.Render(t.Description)))
	}

	if m.saveErr != nil {
		sb.WriteString("\nCannot save theme: " + m.saveErr.Error() + "\n")
	}
	sb.WriteString("\n" + dim.Render("Use [Up/Down] arrows to navigate • [Enter] to confirm • [Esc] to cancel") + "\n")

	return box.Render(sb.String())
}
