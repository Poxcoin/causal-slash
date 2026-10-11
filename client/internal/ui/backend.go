// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package ui

import "context"

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
}
