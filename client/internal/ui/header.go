// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package ui

import (
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

const (
	Tagline = "Sovereign M2M Clearing for Autonomous Agents"

	colorTeal   = "#21E2CC"
	colorDim    = "#888888"
	colorPrompt = "#7AA2F7"
	colorWarn   = "#F59E0B"
	colorError  = "#EF4444"
)

// formatCwd formats an absolute directory path to replace home with '~'
func formatCwd(cwd string) string {
	if strings.HasPrefix(cwd, "~") {
		return cwd
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if cwd == home {
			return "~"
		}
		if strings.HasPrefix(cwd, home+"/") {
			return "~" + cwd[len(home):]
		}
	}
	return cwd
}

// renderHeader renders a sleek, minimalist single-line header (Claude Code / Lazygit style).
// Maximizes vertical terminal real estate for prompts, streaming responses, and full scrollback.
func renderHeader(version, cwd string, width int, maxHeight ...int) string {
	teal := lipgloss.NewStyle().Foreground(lipgloss.Color(colorTeal))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color(colorDim))

	vStr := version
	if !strings.HasPrefix(vStr, "v") {
		vStr = "v" + vStr
	}
	title := teal.Bold(true).Render("Causal-Slash CLI " + vStr)
	descStr := Tagline
	if width < 60 {
		descStr = "Sovereign M2M Clearing"
	}
	desc := dim.Render(descStr)
	path := dim.Render(formatCwd(cwd))
	sep := dim.Render(" │ ")

	// Full single-line header: CSLS v0.3.0 │ Sovereign M2M Clearing │ ~/workspace
	content := title + sep + desc + sep + path
	if width > 0 && lipgloss.Width(content)+4 > width {
		// Medium width: CSLS v0.3.0 │ ~/workspace
		content = title + sep + path
		if lipgloss.Width(content)+4 > width {
			// Narrow width (e.g. 40 cols): CSLS v0.3.0
			content = title
		}
	}

	return lipgloss.NewStyle().Padding(0, 2, 0, 2).Render(content)
}

// renderHeaderCompact is an alias for renderHeader in modern single-line layout.
func renderHeaderCompact(version, cwd string, width int) string {
	return renderHeader(version, cwd, width)
}

// Header is a backward-compatible wrapper returning rendered string and its line height.
func Header(version, cwd string, width int) (string, int) {
	rendered := renderHeader(version, cwd, width)
	return rendered, lipgloss.Height(rendered)
}
