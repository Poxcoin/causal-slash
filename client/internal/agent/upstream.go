// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package agent

import (
	"context"
	"strings"
)

// UpstreamRouter exposes the canonical merchant model directory only.
type UpstreamRouter struct{}

// NewUpstreamRouter creates a directory without client-side upstream credentials.
func NewUpstreamRouter() *UpstreamRouter { return &UpstreamRouter{} }

// ModelEntry is one model offered by a real upstream provider.
type ModelEntry struct {
	Provider string // e.g. "anthropic", "openai", "deepseek", "google", "kuaishou", "elevenlabs"
	ID       string
	Name     string
}

// Canonical2026Models returns the official October 2026 model directory.
func Canonical2026Models() []ModelEntry {
	return []ModelEntry{
		{Provider: "anthropic", ID: "claude-opus-5.5", Name: "Claude Opus 5.5 (Flagship Long-Horizon Reasoning)"},
		{Provider: "anthropic", ID: "claude-sonnet-5.5", Name: "Claude Sonnet 5.5 (High-Speed Agentic Coding)"},
		{Provider: "openai", ID: "gpt-6.1-sol", Name: "GPT-6.1 Sol (Frontier Reasoning & Tools)"},
		{Provider: "openai", ID: "gpt-6-luna", Name: "GPT-6 Luna (Low-Latency Agent Execution)"},
		{Provider: "deepseek", ID: "deepseek-v4-pro", Name: "DeepSeek-V4-Pro (1.6T MoE Architecture)"},
		{Provider: "google", ID: "gemini-4-argon", Name: "Gemini 4 Argon (DeepSWE & Cybersecurity Leader)"},
		{Provider: "google", ID: "gemini-3.5-flash", Name: "Gemini 3.5 Flash (Shared Pool)"},
		{Provider: "groq", ID: "gpt-oss-120b", Name: "GPT-OSS 120B (Groq LPU Fast)"},
		{Provider: "qwen", ID: "qwen3.8-27b", Name: "Qwen 3.8 27B Coder (Hyperbolic)"},
		{Provider: "meta-llama", ID: "llama-4-scout", Name: "Llama 4 Scout (Together AI)"},
		{Provider: "kuaishou", ID: "kling-4.0", Name: "Kling 4.0 (Autonomous Video Diffusion)"},
		{Provider: "elevenlabs", ID: "eleven-v4", Name: "ElevenLabs v4 (Real-Time Audio Synthesis)"},
		{Provider: "openrouter", ID: "nemotron-free", Name: "Nemotron 3.5 Lightning (UsePod / OpenRouter)"},
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
