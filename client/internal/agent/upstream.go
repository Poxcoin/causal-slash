// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// UpstreamRouter provides resilient frontier inference via non-custodial sovereign routing.
// Client terminal maintains ZERO client Web2 API keys (pure 167-byte Session MAC clearing).
type UpstreamRouter struct {
	httpClient *http.Client
}

// NewUpstreamRouter initializes the upstream router.
func NewUpstreamRouter() *UpstreamRouter {
	return &UpstreamRouter{
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// ModelEntry is one model offered by a real upstream provider.
type ModelEntry struct {
	Provider string // e.g. "anthropic", "openai", "deepseek", "google"
	ID       string
	Name     string
}

// Canonical2026Models returns the official October 2026 model directory.
func Canonical2026Models() []ModelEntry {
	return []ModelEntry{
		{Provider: "anthropic", ID: "claude-opus-5.5", Name: "Claude Opus 5.5 (1M context)"},
		{Provider: "anthropic", ID: "claude-sonnet-5.5", Name: "Claude Sonnet 5.5"},
		{Provider: "anthropic", ID: "claude-haiku-5.5", Name: "Claude Haiku 5.5"},
		{Provider: "openai", ID: "gpt-6.1-sol", Name: "GPT-6.1 Sol"},
		{Provider: "openai", ID: "gpt-6-luna", Name: "GPT-6 Luna"},
		{Provider: "deepseek", ID: "deepseek-v4-pro", Name: "DeepSeek-V4-Pro (1.6T MoE)"},
		{Provider: "deepseek", ID: "deepseek-v4.1-flash", Name: "DeepSeek-V4.1-Flash"},
		{Provider: "google", ID: "gemini-4-argon", Name: "Gemini 4 Argon (1M context)"},
		{Provider: "google", ID: "gemini-3.8-live", Name: "Gemini 3.8 Live"},
		{Provider: "qwen", ID: "qwen-3.8-coder", Name: "Qwen 3.8 Coder"},
		{Provider: "meta-llama", ID: "llama-4-scout", Name: "Llama 4 Scout"},
		{Provider: "mistralai", ID: "mistral-large-4", Name: "Mistral Large 4"},
	}
}

// Ref returns the "provider:id" reference stored as the active model.
func (e ModelEntry) Ref() string { return e.Provider + ":" + e.ID }

// ParseModelRef splits a "provider:id" reference.
func ParseModelRef(ref string) (provider, id string, ok bool) {
	i := strings.Index(ref, ":")
	if i <= 0 || i == len(ref)-1 {
		return "", "", false
	}
	return ref[:i], ref[i+1:], true
}

// ListModels returns the official October 2026 canonical model catalogue.
func (r *UpstreamRouter) ListModels(ctx context.Context) ([]ModelEntry, error) {
	return Canonical2026Models(), nil
}

// ExecuteStreaming is strictly disabled on client terminals to enforce Zero Client Web2 Keys.
// All inference requests must route via CSLS clearing vendor gateways using 167-byte Session MAC micro-cheques.
func (r *UpstreamRouter) ExecuteStreaming(
	ctx context.Context,
	model string,
	messages []map[string]string,
	onChunk StreamCallback,
) (string, error) {
	return "", fmt.Errorf("502 DIRECT_WEB2_INVOCATION_BANNED: client terminal cannot bypass wire clearing; must connect to CSLS vendor node with 167-byte Session MAC micro-cheques")
}

// parseSSEStream decodes incoming Server-Sent Events from the CSLS vendor node.
func parseSSEStream(r io.Reader, onChunk StreamCallback) (string, error) {
	var full strings.Builder
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		dataStr := strings.TrimSpace(line[6:])
		if dataStr == "[DONE]" {
			break
		}
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(dataStr), &chunk); err == nil && len(chunk.Choices) > 0 {
			c := chunk.Choices[0].Delta.Content
			if c != "" {
				full.WriteString(c)
				if onChunk != nil {
					onChunk(c)
				}
			}
		}
	}
	return full.String(), scanner.Err()
}
