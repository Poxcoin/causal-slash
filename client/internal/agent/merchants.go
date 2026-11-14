// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package agent

import (
	"encoding/hex"
	"strings"
)

const (
	// GatewayClearingPayout is the canonical CSLS platform clearing treasury on Base L2.
	// In the CSLS protocol, individual AI providers (Anthropic, OpenAI, etc.) do NOT have crypto wallets.
	// All off-chain micro-cheques clear to the platform gateway treasury, which settles with inference brokers.
	GatewayClearingPayout = "0x5C94B2254e528074E06A3506F7AC5109d5578E70"
	DefaultGatewayPKHex   = "0280b1f3bf53e2efc19ebe333b670dccc19084e04f29b722d43f38f4884462850f"
)

// MerchantNode represents a connected model/provider route in the CSLS clearing network.
// Off-chain micro-cheques route through the CSLS Gateway Clearing Treasury on Base L2.
type MerchantNode struct {
	ID             string
	Name           string
	PublicKeyHex   string
	PayoutAddress  string
	UnitPriceMicro uint64
	Capabilities   []string
}

// PublicKeyBytes returns the 33-byte compressed secp256k1 public key.
func (m MerchantNode) PublicKeyBytes() []byte {
	b, _ := hex.DecodeString(strings.TrimPrefix(m.PublicKeyHex, "0x"))
	return b
}

// CanonicalMerchants returns the supported AI provider routes.
// All provider routes clear through the canonical CSLS Gateway Clearing Treasury.
func CanonicalMerchants() []MerchantNode {
	return []MerchantNode{
		{
			ID:             "anthropic",
			Name:           "Anthropic Partner Network",
			PublicKeyHex:   DefaultGatewayPKHex,
			PayoutAddress:  GatewayClearingPayout,
			UnitPriceMicro: 500,
			Capabilities:   []string{"claude-opus-5.5", "claude-sonnet-5.5"},
		},
		{
			ID:             "openai",
			Name:           "OpenAI Partner Network",
			PublicKeyHex:   DefaultGatewayPKHex,
			PayoutAddress:  GatewayClearingPayout,
			UnitPriceMicro: 500,
			Capabilities:   []string{"gpt-6.1-sol", "gpt-6-luna", "gpt-oss-120b"},
		},
		{
			ID:             "google",
			Name:           "Google Vertex AI",
			PublicKeyHex:   DefaultGatewayPKHex,
			PayoutAddress:  GatewayClearingPayout,
			UnitPriceMicro: 350,
			Capabilities:   []string{"gemini-4-argon", "gemini-3.5-flash", "gemini-3.7-flash"},
		},
		{
			ID:             "deepseek",
			Name:           "DeepSeek / SiliconFlow",
			PublicKeyHex:   DefaultGatewayPKHex,
			PayoutAddress:  GatewayClearingPayout,
			UnitPriceMicro: 250,
			Capabilities:   []string{"deepseek-v4-pro", "deepseek-v4.1-flash"},
		},
		{
			ID:             "groq",
			Name:           "Groq LPU Cloud",
			PublicKeyHex:   DefaultGatewayPKHex,
			PayoutAddress:  GatewayClearingPayout,
			UnitPriceMicro: 200,
			Capabilities:   []string{"gpt-oss-120b", "llama-4-scout"},
		},
		{
			ID:             "qwen",
			Name:           "Qwen / Hyperbolic",
			PublicKeyHex:   DefaultGatewayPKHex,
			PayoutAddress:  GatewayClearingPayout,
			UnitPriceMicro: 200,
			Capabilities:   []string{"qwen3.8-27b"},
		},
		{
			ID:             "meta-llama",
			Name:           "Together AI (Llama)",
			PublicKeyHex:   DefaultGatewayPKHex,
			PayoutAddress:  GatewayClearingPayout,
			UnitPriceMicro: 250,
			Capabilities:   []string{"llama-4-scout"},
		},
		{
			ID:             "openrouter",
			Name:           "UsePod / OpenRouter",
			PublicKeyHex:   DefaultGatewayPKHex,
			PayoutAddress:  GatewayClearingPayout,
			UnitPriceMicro: 200,
			Capabilities:   []string{"nemotron-free"},
		},
		{
			ID:             "elevenlabs",
			Name:           "ElevenLabs Audio",
			PublicKeyHex:   DefaultGatewayPKHex,
			PayoutAddress:  GatewayClearingPayout,
			UnitPriceMicro: 600,
			Capabilities:   []string{"eleven-v4", "eleven-v4-turbo"},
		},
		{
			ID:             "kuaishou",
			Name:           "Kling AI Video",
			PublicKeyHex:   DefaultGatewayPKHex,
			PayoutAddress:  GatewayClearingPayout,
			UnitPriceMicro: 1500,
			Capabilities:   []string{"kling-4.0", "kling-4.0-flash"},
		},
		{
			ID:             "fal",
			Name:           "fal.ai Media Cloud",
			PublicKeyHex:   DefaultGatewayPKHex,
			PayoutAddress:  GatewayClearingPayout,
			UnitPriceMicro: 800,
			Capabilities:   []string{"flux-pro-ultra", "kling-4.0"},
		},
		{
			ID:             "deepinfra",
			Name:           "DeepInfra Serverless",
			PublicKeyHex:   DefaultGatewayPKHex,
			PayoutAddress:  GatewayClearingPayout,
			UnitPriceMicro: 200,
			Capabilities:   []string{"deepseek-v4-pro", "llama-4-scout"},
		},
		{
			ID:             "fireworks",
			Name:           "Fireworks AI",
			PublicKeyHex:   DefaultGatewayPKHex,
			PayoutAddress:  GatewayClearingPayout,
			UnitPriceMicro: 250,
			Capabilities:   []string{"firefunction-v3", "deepseek-v4-pro"},
		},
		{
			ID:             "baseten",
			Name:           "Baseten Serving",
			PublicKeyHex:   DefaultGatewayPKHex,
			PayoutAddress:  GatewayClearingPayout,
			UnitPriceMicro: 300,
			Capabilities:   []string{"truss-custom-llm"},
		},
		{
			ID:             "novita",
			Name:           "Novita AI Hub",
			PublicKeyHex:   DefaultGatewayPKHex,
			PayoutAddress:  GatewayClearingPayout,
			UnitPriceMicro: 200,
			Capabilities:   []string{"deepseek-v4-pro", "qwen3.8-27b"},
		},
		{
			ID:             "replicate",
			Name:           "Replicate Cloud",
			PublicKeyHex:   DefaultGatewayPKHex,
			PayoutAddress:  GatewayClearingPayout,
			UnitPriceMicro: 400,
			Capabilities:   []string{"sdxl-lightning", "flux-dev"},
		},
		{
			ID:             "mistral",
			Name:           "Mistral AI",
			PublicKeyHex:   DefaultGatewayPKHex,
			PayoutAddress:  GatewayClearingPayout,
			UnitPriceMicro: 350,
			Capabilities:   []string{"mistral-large-3", "codestral-2605"},
		},
		{
			ID:             "cohere",
			Name:           "Cohere Enterprise",
			PublicKeyHex:   DefaultGatewayPKHex,
			PayoutAddress:  GatewayClearingPayout,
			UnitPriceMicro: 300,
			Capabilities:   []string{"command-r-plus-2026", "rerank-4"},
		},
		{
			ID:             "xai",
			Name:           "xAI / Grok",
			PublicKeyHex:   DefaultGatewayPKHex,
			PayoutAddress:  GatewayClearingPayout,
			UnitPriceMicro: 500,
			Capabilities:   []string{"grok-4"},
		},
		{
			ID:             "cerebras",
			Name:           "Cerebras Wafer-Scale",
			PublicKeyHex:   DefaultGatewayPKHex,
			PayoutAddress:  GatewayClearingPayout,
			UnitPriceMicro: 250,
			Capabilities:   []string{"llama-4-wse3"},
		},
	}
}

// ResolveMerchant finds a merchant by ID, model reference ("provider:model"), payout address, or public key.
func ResolveMerchant(query string) (MerchantNode, bool) {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return CanonicalMerchants()[0], true
	}

	// If model ref like "anthropic:claude-opus-5.5", extract provider prefix
	if idx := strings.Index(q, ":"); idx > 0 {
		q = q[:idx]
	}

	merchants := CanonicalMerchants()
	for _, m := range merchants {
		if strings.ToLower(m.ID) == q ||
			strings.ToLower(m.PayoutAddress) == q ||
			strings.TrimPrefix(strings.ToLower(m.PublicKeyHex), "0x") == strings.TrimPrefix(q, "0x") {
			return m, true
		}
	}

	// Substring match on ID or Name
	for _, m := range merchants {
		if strings.Contains(strings.ToLower(m.ID), q) || strings.Contains(strings.ToLower(m.Name), q) {
			return m, true
		}
	}

	return MerchantNode{}, false
}

// MerchantForModel returns the connected merchant for a given model reference, falling back to Anthropic.
func MerchantForModel(modelRef string) MerchantNode {
	if m, ok := ResolveMerchant(modelRef); ok {
		return m
	}
	return CanonicalMerchants()[0]
}
