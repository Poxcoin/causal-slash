// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package main

import (
	"context"
	"fmt"

	"csls/internal/agent"
	"csls/internal/commands"
	"csls/internal/session"
	"csls/internal/ui"
)

// Ensure appBackend implements ui.Backend interface.
var _ ui.Backend = (*appBackend)(nil)

type appBackend struct {
	sess        *session.State
	agentClient *agent.Client
	repoRoot    string
}

func (b *appBackend) BondStatus() string {
	return b.sess.BondStatus()
}

func (b *appBackend) ActiveModel() string {
	if b.sess != nil && b.sess.CurrentModel != "" {
		return b.sess.CurrentModel
	}
	return "claude-opus-5.5"
}

func (b *appBackend) ExecuteSlash(cmd string) (string, bool) {
	res := commands.Execute(cmd, b.sess, b.agentClient, b.repoRoot)
	return res.Output, res.Quit
}

func (b *appBackend) StreamQuery(ctx context.Context, query string) (<-chan string, <-chan error) {
	tokenChan := make(chan string, 128)
	errChan := make(chan error, 1)

	go func() {
		defer close(tokenChan)
		defer close(errChan)

		_, height, err := b.agentClient.ProcessQuery(ctx, query, func(chunk string) {
			select {
			case tokenChan <- chunk:
			case <-ctx.Done():
			}
		})
		if err != nil {
			errChan <- err
			return
		}

		auditLine := fmt.Sprintf("── $0.0005 USDC settled (0 gas) | seq #%d | model: %s", height, b.sess.CurrentModel)
		select {
		case tokenChan <- "\n\n" + auditLine:
		case <-ctx.Done():
		}
	}()

	return tokenChan, errChan
}
