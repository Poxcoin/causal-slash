// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package main

import (
	"fmt"
	"os"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"

	"csls/internal/agent"
	"csls/internal/commands"
	"csls/internal/session"
	"csls/internal/ui"
)

const version = "0.3.0"

func findRepoRoot() string {
	exe, err := os.Executable()
	if err == nil {
		exePath, err := filepath.EvalSymlinks(exe)
		if err == nil {
			cand := filepath.Dir(filepath.Dir(exePath))
			if _, err := os.Stat(filepath.Join(cand, "Makefile")); err == nil {
				return cand
			}
		}
	}
	cwd, err := os.Getwd()
	if err == nil {
		cand := cwd
		for i := 0; i < 4; i++ {
			if _, err := os.Stat(filepath.Join(cand, "Makefile")); err == nil {
				return cand
			}
			parent := filepath.Dir(cand)
			if parent == cand {
				break
			}
			cand = parent
		}
	}
	return "."
}

func isTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func main() {
	if os.Getenv("COLORFGBG") == "" {
		_ = os.Setenv("COLORFGBG", "15;0")
	}

	sess := session.NewState()
	if err := sess.Memory.LoadError(); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot load conversation memory; repair the file and restart, or use /clear to discard it. Saving is disabled: %v\n", err)
	}
	agentClient := agent.NewClient(sess)
	defer agentClient.Close()

	repoRoot := findRepoRoot()
	args := os.Args[1:]

	// 1. Handle command-line flags
	if len(args) > 0 {
		first := args[0]
		if first == "-v" || first == "--version" {
			fmt.Printf("Causal-Slash CLI %s\n", version)
			return
		}
		if first == "-h" || first == "--help" {
			res := commands.Execute("/help", sess, agentClient, repoRoot)
			fmt.Println(res.Output)
			return
		}
		if first == "--theme" || first == "theme" {
			wizard := ui.NewThemeWizard()
			wp := tea.NewProgram(wizard)
			if _, err := wp.Run(); err != nil {
				fmt.Fprintf(os.Stderr, "Theme wizard failed: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	// 2. Interactive TUI shell (Bubble Tea with AltScreen and MouseCellMotion)
	backend := &appBackend{
		sess:        sess,
		agentClient: agentClient,
		repoRoot:    repoRoot,
	}

	app := ui.NewApp(backend, version, sess.DisplayCwd())
	p := tea.NewProgram(
		app,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
		tea.WithReportFocus(),
	)

	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
