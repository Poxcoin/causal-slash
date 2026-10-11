// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

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
	return ""
}

func (b *appBackend) Commands() []ui.CommandItem {
	out := make([]ui.CommandItem, 0, len(commands.Registry))
	for _, c := range commands.Registry {
		out = append(out, ui.CommandItem{Name: c.Name, Description: c.Description, ArgsSpec: c.ArgsSpec})
	}
	return out
}

func detectFamily(id string) string {
	lower := strings.ToLower(id)
	if strings.Contains(lower, "claude") || strings.HasPrefix(lower, "anthropic/") {
		return "Claude (Anthropic)"
	}
	if strings.Contains(lower, "gpt") || strings.Contains(lower, "o1") || strings.Contains(lower, "o3") || strings.HasPrefix(lower, "openai/") {
		return "ChatGPT (OpenAI)"
	}
	if strings.Contains(lower, "gemini") || strings.HasPrefix(lower, "google/") {
		return "Gemini (Google)"
	}
	if strings.Contains(lower, "deepseek") {
		return "DeepSeek"
	}
	if strings.Contains(lower, "llama") || strings.HasPrefix(lower, "meta-llama/") {
		return "Llama (Meta)"
	}
	if strings.Contains(lower, "qwen") {
		return "Qwen (Alibaba)"
	}
	if strings.Contains(lower, "mistral") || strings.Contains(lower, "codestral") {
		return "Mistral AI"
	}
	return "Other / Community"
}

func (b *appBackend) ListModels() ([]ui.ModelItem, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	models, err := b.agentClient.ListModels(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ui.ModelItem, 0, len(models))
	for _, m := range models {
		out = append(out, ui.ModelItem{
			Ref:      m.Ref(),
			Provider: m.Provider,
			Name:     m.Name,
			Family:   detectFamily(m.ID),
		})
	}
	return out, nil
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

		if height == 0 {
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
