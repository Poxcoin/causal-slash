// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

func isCharDevice(f *os.File) bool {
	fi, err := f.Stat()
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
		if strings.HasPrefix(first, "/") {
			line := strings.Join(args, " ")
			res := commands.Execute(line, sess, agentClient, repoRoot)
			if res.Output != "" {
				fmt.Println(res.Output)
			}
			return
		}
	}

	// 2. Non-interactive piped mode
	if !isCharDevice(os.Stdin) {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			res := commands.Execute(line, sess, agentClient, repoRoot)
			if res.Quit {
				break
			}
			if res.Output != "" {
				fmt.Println(res.Output)
			}
		}
		return
	}

	// 3. Interactive TUI shell (Bubble Tea with AltScreen and MouseCellMotion)
	backend := &appBackend{
		sess:        sess,
		agentClient: agentClient,
		repoRoot:    repoRoot,
	}

	app := ui.NewApp(backend, version, sess.DisplayCwd())
	p := tea.NewProgram(
		app,
		tea.WithAltScreen(),
		tea.WithReportFocus(),
	)

	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
