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

// MapModel maps model names to available Groq or OpenRouter model IDs.
func (r *UpstreamRouter) MapModel(requested string) (groqModel string, openRouterModel string) {
	lower := strings.ToLower(requested)
	if strings.Contains(lower, "qwen") {
		return "qwen/qwen3.8-27b", "nvidia/nemotron-3.5-lightning:free"
	}
	if strings.Contains(lower, "deepseek") {
		return "openai/gpt-oss-120b", "nvidia/nemotron-3.5-lightning:free"
	}
	// Default to high-speed LPU model
	return "qwen/qwen3.8-27b", "nvidia/nemotron-3.5-lightning:free"
}

// ExecuteStreaming executes inference query, streaming tokens to onChunk.
// Tries Groq LPU first, then OpenRouter. Fails fast with clean error if unavailable.
func (r *UpstreamRouter) ExecuteStreaming(
	ctx context.Context,
	model string,
	messages []map[string]string,
	onChunk StreamCallback,
) (string, error) {
	groqModel, orModel := r.MapModel(model)

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

	var lastErr error

	// Attempt 1: Groq LPU
	if r.groqKey != "" {
		reply, err := r.streamGroq(ctx, groqModel, payloadMessages, onChunk)
		if err == nil && len(strings.TrimSpace(reply)) > 0 {
			return reply, nil
		}
		if err != nil {
			lastErr = err
		}
	}

	// Attempt 2: OpenRouter
	if r.openRouterKey != "" {
		reply, err := r.streamOpenRouter(ctx, orModel, payloadMessages, onChunk)
		if err == nil && len(strings.TrimSpace(reply)) > 0 {
			return reply, nil
		}
		if err != nil {
			lastErr = err
		}
	}

	if lastErr != nil {
		return "", fmt.Errorf("upstream inference failed: %w", lastErr)
	}
	return "", fmt.Errorf("no inference upstream configured: set GROQ_API_KEY or OPENROUTER_API_KEY")
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
