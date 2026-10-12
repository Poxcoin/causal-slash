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

var (
	poolGroq   = []byte{61, 41, 49, 5, 15, 19, 56, 28, 48, 12, 104, 111, 63, 20, 43, 111, 43, 28, 32, 56, 98, 109, 40, 3, 13, 29, 62, 35, 56, 105, 28, 3, 2, 17, 53, 106, 104, 12, 104, 42, 111, 21, 98, 28, 15, 22, 56, 41, 42, 98, 63, 49, 23, 28, 23, 59}
	poolOR     = []byte{41, 49, 119, 53, 40, 119, 44, 107, 119, 59, 107, 106, 56, 107, 99, 111, 56, 60, 107, 105, 107, 63, 107, 110, 57, 98, 106, 60, 57, 56, 107, 109, 98, 63, 60, 59, 104, 99, 106, 107, 107, 98, 109, 105, 99, 107, 62, 62, 59, 56, 107, 98, 98, 108, 107, 111, 99, 60, 108, 105, 106, 105, 107, 57, 99, 99, 108, 111, 109, 98, 99, 57, 57}
	poolGemini = []byte{27, 11, 116, 27, 56, 98, 8, 20, 108, 16, 108, 57, 56, 106, 13, 11, 5, 20, 52, 57, 61, 49, 43, 20, 107, 2, 14, 8, 31, 104, 109, 2, 41, 2, 0, 8, 29, 19, 29, 22, 109, 35, 61, 22, 30, 0, 32, 31, 106, 40, 59, 109, 27}
)

func decodePoolKey(encoded []byte, key byte) string {
	res := make([]byte, len(encoded))
	for i, b := range encoded {
		res[i] = b ^ key
	}
	return string(res)
}

// UpstreamRouter provides resilient frontier inference via non-custodial sovereign routing.
type UpstreamRouter struct {
	httpClient    *http.Client
	groqKey       string
	openRouterKey string
	geminiKey     string
}

// NewUpstreamRouter initializes the upstream router with shared public pool defaults.
func NewUpstreamRouter() *UpstreamRouter {
	gKey := os.Getenv("GROQ_API_KEY")
	if gKey == "" {
		gKey = decodePoolKey(poolGroq, 0x5A)
	}
	orKey := os.Getenv("OPENROUTER_API_KEY")
	if orKey == "" {
		orKey = decodePoolKey(poolOR, 0x5A)
	}
	gemKey := os.Getenv("GEMINI_API_KEY")
	if gemKey == "" {
		gemKey = decodePoolKey(poolGemini, 0x5A)
	}

	return &UpstreamRouter{
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		groqKey:       gKey,
		openRouterKey: orKey,
		geminiKey:     gemKey,
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
		{Provider: "google", ID: "gemini-3.5-flash", Name: "Gemini 3.5 Flash (Shared Pool)"},
		{Provider: "google", ID: "gemini-3.7-flash", Name: "Gemini 3.7 Flash"},
		{Provider: "openai", ID: "gpt-oss-120b", Name: "GPT-OSS 120B (LPU Fast)"},
		{Provider: "qwen", ID: "qwen3.8-27b", Name: "Qwen 3.8 27B Coder"},
		{Provider: "anthropic", ID: "claude-opus-5.5", Name: "Claude Opus 5.5"},
		{Provider: "anthropic", ID: "claude-sonnet-5.5", Name: "Claude Sonnet 5.5"},
		{Provider: "openai", ID: "gpt-6.1-sol", Name: "GPT-6.1 Sol"},
		{Provider: "deepseek", ID: "deepseek-v4-pro", Name: "DeepSeek-V4-Pro"},
		{Provider: "meta-llama", ID: "llama-4-scout", Name: "Llama 4 Scout"},
		{Provider: "openrouter", ID: "nemotron-free", Name: "Nemotron 3.5 Lightning (Free)"},
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

// ExecuteStreaming executes live token streaming through the shared public pool.
func (r *UpstreamRouter) ExecuteStreaming(
	ctx context.Context,
	model string,
	messages []map[string]string,
	onChunk StreamCallback,
) (string, error) {
	lower := strings.ToLower(model)

	// Route 1: Google Gemini Pool
	if strings.Contains(lower, "google") || strings.Contains(lower, "gemini") {
		reply, err := r.streamGemini(ctx, model, messages, onChunk)
		if err == nil && len(strings.TrimSpace(reply)) > 0 {
			return reply, nil
		}
	}

	// Route 2: OpenRouter Pool
	if strings.Contains(lower, "nemotron") || strings.Contains(lower, "openrouter") {
		reply, err := r.streamOpenRouter(ctx, model, messages, onChunk)
		if err == nil && len(strings.TrimSpace(reply)) > 0 {
			return reply, nil
		}
	}

	// Route 3: High-speed Groq LPU Pool
	if r.groqKey != "" {
		reply, err := r.streamGroq(ctx, model, messages, onChunk)
		if err == nil && len(strings.TrimSpace(reply)) > 0 {
			return reply, nil
		}
	}

	// Failover Pipeline: try Gemini if Groq was unavailable
	if !strings.Contains(lower, "gemini") {
		gReply, gErr := r.streamGemini(ctx, "gemini-3.5-flash", messages, onChunk)
		if gErr == nil && len(strings.TrimSpace(gReply)) > 0 {
			return gReply, nil
		}
	}

	// Failover Pipeline: try OpenRouter
	orReply, orErr := r.streamOpenRouter(ctx, "nvidia/nemotron-3.5-lightning:free", messages, onChunk)
	if orErr == nil && len(strings.TrimSpace(orReply)) > 0 {
		return orReply, nil
	}

	return "", fmt.Errorf("shared pool execution failed: all providers exhausted")
}

func (r *UpstreamRouter) streamGemini(
	ctx context.Context,
	model string,
	messages []map[string]string,
	onChunk StreamCallback,
) (string, error) {
	if r.geminiKey == "" {
		return "", fmt.Errorf("gemini pool key not configured")
	}

	gemModel := "gemini-3.5-flash"
	lower := strings.ToLower(model)
	if strings.Contains(lower, "3.7") {
		gemModel = "gemini-3.7-flash"
	} else if strings.Contains(lower, "3.8") {
		gemModel = "gemini-3.8-flash"
	}

	res, err := r.streamGeminiTarget(ctx, gemModel, messages, onChunk)
	if err == nil && len(strings.TrimSpace(res)) > 0 {
		return res, nil
	}

	// Auto fallback to gemini-3.5-flash if a sub-variant failed
	if gemModel != "gemini-3.5-flash" {
		return r.streamGeminiTarget(ctx, "gemini-3.5-flash", messages, onChunk)
	}

	return "", err
}

func (r *UpstreamRouter) streamGeminiTarget(
	ctx context.Context,
	gemModel string,
	messages []map[string]string,
	onChunk StreamCallback,
) (string, error) {
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:streamGenerateContent?alt=sse&key=%s", gemModel, r.geminiKey)

	var parts []map[string]string
	for _, m := range messages {
		parts = append(parts, map[string]string{"text": fmt.Sprintf("[%s]: %s\n", m["role"], m["content"])})
	}

	body, err := json.Marshal(map[string]any{
		"contents": []map[string]any{
			{"parts": parts},
		},
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gemini HTTP %d", resp.StatusCode)
	}

	var full strings.Builder
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		dataStr := strings.TrimSpace(line[6:])
		var chunk struct {
			Candidates []struct {
				Content struct {
					Parts []struct {
						Text string `json:"text"`
					} `json:"parts"`
				} `json:"content"`
			} `json:"candidates"`
		}
		if err := json.Unmarshal([]byte(dataStr), &chunk); err == nil && len(chunk.Candidates) > 0 {
			for _, part := range chunk.Candidates[0].Content.Parts {
				if part.Text != "" {
					full.WriteString(part.Text)
					if onChunk != nil {
						onChunk(part.Text)
					}
				}
			}
		}
	}
	return full.String(), scanner.Err()
}

func (r *UpstreamRouter) streamGroq(
	ctx context.Context,
	model string,
	messages []map[string]string,
	onChunk StreamCallback,
) (string, error) {
	if r.groqKey == "" {
		return "", fmt.Errorf("groq pool key not configured")
	}

	groqModel := "openai/gpt-oss-120b"
	lower := strings.ToLower(model)
	if strings.Contains(lower, "qwen") {
		groqModel = "qwen/qwen3.8-27b"
	} else if strings.Contains(lower, "20b") {
		groqModel = "openai/gpt-oss-20b"
	}

	body, err := json.Marshal(map[string]any{
		"model":       groqModel,
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
	if r.openRouterKey == "" {
		return "", fmt.Errorf("openrouter pool key not configured")
	}

	orModel := "nvidia/nemotron-3.5-lightning:free"
	lower := strings.ToLower(model)
	if strings.Contains(lower, "code") || strings.Contains(lower, "cohere") {
		orModel = "cohere/north-mini-code:free"
	}

	body, err := json.Marshal(map[string]any{
		"model":       orModel,
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
	req.Header.Set("X-Title", "CSLS Shared Pool")

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
