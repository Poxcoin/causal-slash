// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package ui

import (
	_ "embed"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

//go:embed logo.txt
var logoTxt string

const (
	Tagline   = "Sovereign M2M Clearing for Autonomous Agents"
	LogoWidth = 16

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

// renderHeader renders the CSLS startup header with the 4-bar geometric glyph logo
// on wide terminals (width >= 56) and falls back to compact text-only on narrow terminals.
func renderHeader(version, cwd string, width int, maxHeight ...int) string {
	primary := lipgloss.NewStyle().Foreground(lipgloss.Color(activePrimaryColor()))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color(colorDim))

	vStr := version
	if !strings.HasPrefix(vStr, "v") {
		vStr = "v" + vStr
	}
	title := primary.Bold(true).Render("Causal-Slash CLI " + vStr)
	path := dim.Render(formatCwd(cwd))

	// Narrow terminal (< 56 cols, e.g. 40 cols): suppress logo, single-line text header without wrapping
	if width > 0 && width < LogoWidth+40 {
		sep := dim.Render(" │ ")
		content := title + sep + path
		if lipgloss.Width(content)+4 > width {
			content = title
		}
		return lipgloss.NewStyle().Padding(0, 2, 0, 2).Render(content)
	}

	desc := dim.Render(Tagline)
	proto := dim.Render("Base L2 • 167B Session MAC • O(1) Schnorr EOTS")
	info := strings.Join([]string{
		"",
		title,
		desc,
		path,
		proto,
	}, "\n")

	trimmedLogo := strings.TrimRight(logoTxt, "\r\n")
	logo := primary.Bold(true).Render(trimmedLogo)
	content := lipgloss.JoinHorizontal(lipgloss.Top, logo, "   ", info)

	return lipgloss.NewStyle().Padding(1, 2, 1, 2).Render(content)
}

// renderHeaderCompact renders a single-line compact header.
func renderHeaderCompact(version, cwd string, width int) string {
	primary := lipgloss.NewStyle().Foreground(lipgloss.Color(activePrimaryColor()))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color(colorDim))

	vStr := version
	if !strings.HasPrefix(vStr, "v") {
		vStr = "v" + vStr
	}
	title := primary.Bold(true).Render("Causal-Slash CLI " + vStr)
	path := dim.Render(formatCwd(cwd))
	sep := dim.Render(" │ ")
	content := title + sep + path
	if width > 0 && lipgloss.Width(content)+4 > width {
		content = title
	}
	return lipgloss.NewStyle().Padding(0, 2, 0, 2).Render(content)
}

// Header is a backward-compatible wrapper returning rendered string and its line height.
func Header(version, cwd string, width int) (string, int) {
	rendered := renderHeader(version, cwd, width)
	return rendered, lipgloss.Height(rendered)
}

