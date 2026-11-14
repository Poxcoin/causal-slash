// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package session

import (
	"os"
)

const (
	DefaultBaseSepoliaRPC = "https://sepolia.base.org"
)

type rpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  string          `json:"result"`
	Error   *rpcErrorDetail `json:"error,omitempty"`
}

type rpcErrorDetail struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// GetRPCURL returns configured RPC URL or default Base Sepolia endpoint.
func GetRPCURL() string {
	if rpc := os.Getenv("BASE_SEPOLIA_RPC"); rpc != "" {
		return rpc
	}
	if rpc := os.Getenv("RPC_URL"); rpc != "" {
		return rpc
	}
	return DefaultBaseSepoliaRPC
}
