// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// UpstreamRouter provides resilient frontier inference via non-custodial sovereign routing.
type UpstreamRouter struct {
	httpClient    *http.Client
	groqKey       string
	openRouterKey string
}

// NewUpstreamRouter initializes the upstream provider router from environment.
func NewUpstreamRouter() *UpstreamRouter {
	return &UpstreamRouter{
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		groqKey:       os.Getenv("GROQ_API_KEY"),
		openRouterKey: os.Getenv("OPENROUTER_API_KEY"),
	}
}

// ModelEntry is one model offered by a real upstream provider.
type ModelEntry struct {
	Provider string // "groq" or "openrouter"
	ID       string
}

// Ref returns the "provider:id" reference stored as the active model.
func (e ModelEntry) Ref() string { return e.Provider + ":" + e.ID }

// ParseModelRef splits a "provider:id" reference.
func ParseModelRef(ref string) (provider, id string, ok bool) {
	i := strings.Index(ref, ":")
	if i <= 0 || i == len(ref)-1 {
		return "", "", false
	}
	p := ref[:i]
	if p != "groq" && p != "openrouter" {
		return "", "", false
	}
	return p, ref[i+1:], true
}

func (r *UpstreamRouter) fetchModels(ctx context.Context, url, key, provider string) ([]ModelEntry, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s models: %w", provider, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s models: HTTP %d", provider, resp.StatusCode)
	}
	var body struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("%s models: %w", provider, err)
	}
	out := make([]ModelEntry, 0, len(body.Data))
	for _, d := range body.Data {
		if d.ID != "" {
			out = append(out, ModelEntry{Provider: provider, ID: d.ID})
		}
	}
	return out, nil
}

// ListModels returns the live model catalogue of every configured upstream.
func (r *UpstreamRouter) ListModels(ctx context.Context) ([]ModelEntry, error) {
	var all []ModelEntry
	var errs []string
	if r.groqKey != "" {
		m, err := r.fetchModels(ctx, "https://api.groq.com/openai/v1/models", r.groqKey, "groq")
		if err != nil {
			errs = append(errs, err.Error())
		}
		all = append(all, m...)
	}
	// The OpenRouter catalogue is public; no key is needed to list it.
	m, err := r.fetchModels(ctx, "https://openrouter.ai/api/v1/models", r.openRouterKey, "openrouter")
	if err != nil {
		errs = append(errs, err.Error())
	}
	all = append(all, m...)
	if len(all) == 0 {
		return nil, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return all, nil
}

// ExecuteStreaming executes inference query, streaming tokens to onChunk.
// Tries Groq LPU first, then OpenRouter. Fails fast with clean error if unavailable.
func (r *UpstreamRouter) ExecuteStreaming(
	ctx context.Context,
	model string,
	messages []map[string]string,
	onChunk StreamCallback,
) (string, error) {
	provider, modelID, ok := ParseModelRef(model)
	if !ok {
		return "", fmt.Errorf("no model selected: pick one with /model")
	}

	// Inject system prompt if missing
	hasSystem := false
	for _, m := range messages {
		if m["role"] == "system" {
			hasSystem = true
			break
		}
	}
	payloadMessages := make([]map[string]string, 0, len(messages)+1)
	if !hasSystem {
		payloadMessages = append(payloadMessages, map[string]string{
			"role":    "system",
			"content": "You are CSLS Sovereign Agent, an autonomous frontier AI coding and cryptoeconomic reasoning assistant operating on the Causal-Slash Protocol (Base L2). You provide concise, technically rigorous, and direct answers.",
		})
	}
	payloadMessages = append(payloadMessages, messages...)

	switch provider {
	case "groq":
		if r.groqKey == "" {
			return "", fmt.Errorf("GROQ_API_KEY is not set")
		}
		return r.streamGroq(ctx, modelID, payloadMessages, onChunk)
	default:
		if r.openRouterKey == "" {
			return "", fmt.Errorf("OPENROUTER_API_KEY is not set")
		}
		return r.streamOpenRouter(ctx, modelID, payloadMessages, onChunk)
	}
}

func (r *UpstreamRouter) streamGroq(
	ctx context.Context,
	model string,
	messages []map[string]string,
	onChunk StreamCallback,
) (string, error) {
	body, err := json.Marshal(map[string]any{
		"model":       model,
		"messages":    messages,
		"stream":      true,
		"max_tokens":  2048,
		"temperature": 0.6,
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.groq.com/openai/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.groqKey)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("groq HTTP %d", resp.StatusCode)
	}

	return parseSSEStream(resp.Body, onChunk)
}

func (r *UpstreamRouter) streamOpenRouter(
	ctx context.Context,
	model string,
	messages []map[string]string,
	onChunk StreamCallback,
) (string, error) {
	body, err := json.Marshal(map[string]any{
		"model":       model,
		"messages":    messages,
		"stream":      true,
		"max_tokens":  2048,
		"temperature": 0.6,
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://openrouter.ai/api/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.openRouterKey)
	req.Header.Set("HTTP-Referer", "https://causal-slash.io")
	req.Header.Set("X-Title", "Causal-Slash Terminal")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openrouter HTTP %d", resp.StatusCode)
	}

	return parseSSEStream(resp.Body, onChunk)
}

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
