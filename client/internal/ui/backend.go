// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package ui

import "context"

// CommandItem describes a slash command offered in the suggestion list.
type CommandItem struct {
	Name        string
	Description string
	ArgsSpec    string
}

// ModelItem is one live model from an upstream provider; Ref is "provider:id".
type ModelItem struct {
	Ref      string
	Provider string
	Name     string
	Family   string
}

// Backend abstracts all agent, wallet, cheque, and command logic away from the TUI.
type Backend interface {
	// BondStatus returns the current bond status ("ready" or "no bond").
	BondStatus() string

	// ActiveModel returns the currently configured model ID.
	ActiveModel() string

	// ExecuteSlash processes slash commands (/help, /status, /bond, etc.).
	ExecuteSlash(cmd string) (output string, quit bool)

	// StreamQuery streams tokens from frontier vendor node over channels.
	StreamQuery(ctx context.Context, query string) (<-chan string, <-chan error)

	// Commands lists all slash commands for suggestions.
	Commands() []CommandItem

	// ListModels fetches the live model catalogue from the configured upstreams.
	ListModels() ([]ModelItem, error)

	// InitialLines returns loaded chat memory turns for terminal startup.
	InitialLines() []string

	// CommandHistory returns persisted command history for Up/Down arrows.
	CommandHistory() []string
}
