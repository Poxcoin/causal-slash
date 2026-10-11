// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package session_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"csls/internal/session"
)

func TestQueryOnChainVault(t *testing.T) {
	// Construct 7 32-byte ABI words:
	// word 0: collateralBond = 10_000_000 (10 USDC) -> 0x00...00989680
	// word 1: nonceMerkleRoot -> 0x00...00
	// word 2: signingAddress -> 0x00...001122334455667788990011223344556677889900
	// word 3: agentOwner -> 0x00...00aabbccddeeff00112233445566778899aabbccdd
	// word 4: pendingWithdrawal = 1_000_000 (1 USDC) -> 0x00...000f4240
	// word 5: withdrawalUnlockTime = 1700000000 -> 0x00...0065541580
	// word 6: isSlashed = 0 -> 0x00...00
	vaultsResultHex := "0x" +
		"0000000000000000000000000000000000000000000000000000000000989680" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000001122334455667788990011223344556677889900" +
		"000000000000000000000000aabbccddeeff00112233445566778899aabbccdd" +
		"00000000000000000000000000000000000000000000000000000000000f4240" +
		"0000000000000000000000000000000000000000000000000000000065541580" +
		"0000000000000000000000000000000000000000000000000000000000000000"

	// allocatedExposure = 2_000_000 (2 USDC) -> 0x00...001e8480
	exposureResultHex := "0x00000000000000000000000000000000000000000000000000000000001e8480"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		callObj, _ := req.Params[0].(map[string]any)
		callData, _ := callObj["data"].(string)

		var resHex string
		// Selector for vaults(address) is 0xa622ee7c
		if len(callData) >= 10 && callData[:10] == "0xa622ee7c" {
			resHex = vaultsResultHex
		} else {
			resHex = exposureResultHex
		}

		resp := map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"result":  resHex,
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	vaultAddr := "0x8faAD06ef5937Ad1019CD49f5Dcab36181e266A5"
	agentAddr := "0xaabbccddeeff00112233445566778899aabbccdd"

	state, err := session.QueryOnChainVault(ctx, server.URL, vaultAddr, agentAddr)
	if err != nil {
		t.Fatalf("QueryOnChainVault failed: %v", err)
	}

	if state.CollateralBondMicro != 10000000 {
		t.Fatalf("expected 10000000 micro-USDC bond, got %d", state.CollateralBondMicro)
	}
	if state.CollateralBondUSDC < 9.99 || state.CollateralBondUSDC > 10.01 {
		t.Fatalf("expected 10.0 USDC bond, got %f", state.CollateralBondUSDC)
	}
	if state.AllocatedExposure != 2000000 {
		t.Fatalf("expected 2000000 allocated exposure, got %d", state.AllocatedExposure)
	}
	if state.PendingWithdrawal != 1000000 {
		t.Fatalf("expected 1000000 pending withdrawal, got %d", state.PendingWithdrawal)
	}
	// Free margin = 10_000_000 - 2_000_000 = 8_000_000 micro-USDC = 8.0 USDC
	if state.FreeMarginUSDC < 7.99 || state.FreeMarginUSDC > 8.01 {
		t.Fatalf("expected 8.0 USDC free margin, got %f", state.FreeMarginUSDC)
	}
	if state.IsSlashed {
		t.Fatalf("expected isSlashed false, got true")
	}
	if state.WithdrawalUnlock != 1700009344 {
		t.Fatalf("expected unlock time 1700009344, got %d", state.WithdrawalUnlock)
	}
	if state.SigningAddress != "0x1122334455667788990011223344556677889900" {
		t.Fatalf("unexpected signing address: %s", state.SigningAddress)
	}
	if state.AgentOwner != "0xaabbccddeeff00112233445566778899aabbccdd" {
		t.Fatalf("unexpected agent owner: %s", state.AgentOwner)
	}
}

func TestQueryOnChainVaultErrorHandling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"error": map[string]any{
				"code":    -32000,
				"message": "execution reverted",
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := session.QueryOnChainVault(ctx, server.URL, "0x1111", "0x2222")
	if err == nil {
		t.Fatal("expected error on RPC execution reverted response")
	}
}
