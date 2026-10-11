// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package session

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	DefaultBaseSepoliaRPC   = "https://sepolia.base.org"
	DefaultVaultAddress     = "0x8faAD06ef5937Ad1019CD49f5Dcab36181e266A5"
	VaultsSelectorHex       = "a622ee7c" // vaults(address)
	AllocatedExpSelectorHex = "62fe0452" // allocatedExposure(address)
)

// OnChainVaultState represents the verified on-chain state of an agent vault.
type OnChainVaultState struct {
	CollateralBondMicro uint64
	CollateralBondUSDC  float64
	NonceMerkleRoot     string
	SigningAddress      string
	AgentOwner          string
	PendingWithdrawal   uint64
	WithdrawalUnlock    uint64
	IsSlashed           bool
	AllocatedExposure   uint64
	FreeMarginUSDC      float64
	SyncedAt            time.Time
}

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

// QueryOnChainVault queries PerformanceCollateralVault.vaults(agentAddress) on Base Sepolia.
func QueryOnChainVault(ctx context.Context, rpcURL, vaultAddr, agentAddr string) (*OnChainVaultState, error) {
	if rpcURL == "" {
		rpcURL = GetRPCURL()
	}
	if vaultAddr == "" {
		vaultAddr = DefaultVaultAddress
	}

	cleanAddr := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(agentAddr)), "0x")
	if len(cleanAddr) != 40 {
		return nil, fmt.Errorf("invalid agent address: %s", agentAddr)
	}

	// Calldata: vaults(address) -> a622ee7c + 24 zero bytes (12 bytes) + 20 byte address
	calldata := "0x" + VaultsSelectorHex + strings.Repeat("0", 24) + cleanAddr

	callParam := map[string]string{
		"to":   vaultAddr,
		"data": calldata,
	}

	reqBody, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0",
		Method:  "eth_call",
		Params:  []interface{}{callParam, "latest"},
		ID:      1,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", rpcURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("RPC connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RPC HTTP status %d", resp.StatusCode)
	}

	var rpcResp rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return nil, fmt.Errorf("failed to decode RPC response: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	resHex := strings.TrimPrefix(rpcResp.Result, "0x")
	if len(resHex) < 64*7 { // 7 32-byte words = 448 chars
		return nil, fmt.Errorf("unexpected eth_call return length (%d chars)", len(resHex))
	}

	rawBytes, err := hex.DecodeString(resHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex result: %w", err)
	}

	// Parse fields
	bondBig := new(big.Int).SetBytes(rawBytes[0:32])
	nonceRoot := "0x" + hex.EncodeToString(rawBytes[32:64])
	signingAddr := "0x" + hex.EncodeToString(rawBytes[64+12:96])
	ownerAddr := "0x" + hex.EncodeToString(rawBytes[96+12:128])
	pendingBig := new(big.Int).SetBytes(rawBytes[128:160])
	unlockBig := new(big.Int).SetBytes(rawBytes[160:192])
	isSlashed := new(big.Int).SetBytes(rawBytes[192:224]).Uint64() != 0

	bondMicro := bondBig.Uint64()
	bondUSDC := float64(bondMicro) / 1e6

	// Query allocated exposure
	var allocatedMicro uint64
	callAlloc := map[string]string{
		"to":   vaultAddr,
		"data": "0x" + AllocatedExpSelectorHex + strings.Repeat("0", 24) + cleanAddr,
	}
	allocReq, _ := json.Marshal(rpcRequest{
		JSONRPC: "2.0",
		Method:  "eth_call",
		Params:  []interface{}{callAlloc, "latest"},
		ID:      2,
	})
	if hreq, err := http.NewRequestWithContext(ctx, "POST", rpcURL, bytes.NewReader(allocReq)); err == nil {
		hreq.Header.Set("Content-Type", "application/json")
		if aresp, err := client.Do(hreq); err == nil {
			var aRpcResp rpcResponse
			if json.NewDecoder(aresp.Body).Decode(&aRpcResp) == nil && aRpcResp.Error == nil {
				aHex := strings.TrimPrefix(aRpcResp.Result, "0x")
				if aBytes, err := hex.DecodeString(aHex); err == nil && len(aBytes) >= 32 {
					allocatedMicro = new(big.Int).SetBytes(aBytes[:32]).Uint64()
				}
			}
			_ = aresp.Body.Close()
		}
	}

	freeMarginMicro := uint64(0)
	if bondMicro > allocatedMicro {
		freeMarginMicro = bondMicro - allocatedMicro
	}
	freeMarginUSDC := float64(freeMarginMicro) / 1e6

	return &OnChainVaultState{
		CollateralBondMicro: bondMicro,
		CollateralBondUSDC:  bondUSDC,
		NonceMerkleRoot:     nonceRoot,
		SigningAddress:      signingAddr,
		AgentOwner:          ownerAddr,
		PendingWithdrawal:   pendingBig.Uint64(),
		WithdrawalUnlock:    unlockBig.Uint64(),
		IsSlashed:           isSlashed,
		AllocatedExposure:   allocatedMicro,
		FreeMarginUSDC:      freeMarginUSDC,
		SyncedAt:            time.Now(),
	}, nil
}
