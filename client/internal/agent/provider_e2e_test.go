// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package agent_test

import (
	"context"
	"net"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"csls/internal/agent"
	"csls/internal/session"
)

func getFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestGoClientToIndependentProviderE2E(t *testing.T) {
	port := getFreePort(t)
	portStr := strconv.Itoa(port)

	// Launch Python IndependentProvider in background
	repoRoot, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("failed to resolve repo root: %v", err)
	}

	cmd := exec.Command("python3", "-m", "sdk.provider.server", "--port", portStr, "--price-micro", "500")
	cmd.Dir = repoRoot
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start Python provider server: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	providerURL := "http://127.0.0.1:" + portStr

	// Wait for provider to become reachable
	ready := false
	for i := 0; i < 30; i++ {
		time.Sleep(50 * time.Millisecond)
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+portStr, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			ready = true
			break
		}
	}
	if !ready {
		t.Fatalf("provider failed to start on %s within 1.5s", providerURL)
	}

	// Initialize Go Agent Client
	sess := session.NewState()
	sess.VendorURL = providerURL
	agClient := agent.NewClient(sess)
	defer agClient.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Discover Provider
	discoveredURL, pk, err := agClient.DiscoverVendor(ctx)
	if err != nil {
		t.Fatalf("DiscoverVendor failed: %v", err)
	}
	if discoveredURL != providerURL {
		t.Fatalf("expected discovered URL %s, got %s", providerURL, discoveredURL)
	}
	if len(pk) != 33 {
		t.Fatalf("expected 33-byte compressed pk, got %d bytes", len(pk))
	}
	if sess.ProviderPayoutAddress == "" {
		t.Fatalf("expected non-empty ProviderPayoutAddress in session")
	}

	// 2. Execute Service: compute.hash_audit
	inputData := map[string]any{
		"data":      "go-terminal-to-python-independent-provider-wire-test",
		"algorithm": "sha256",
	}

	res, height, err := agClient.ExecuteService(ctx, "compute.hash_audit", inputData)
	if err != nil {
		t.Fatalf("ExecuteService failed: %v", err)
	}

	if res.Status != "success" {
		t.Fatalf("expected status 'success', got '%s'", res.Status)
	}
	if res.Service != "compute.hash_audit" {
		t.Fatalf("expected service 'compute.hash_audit', got '%s'", res.Service)
	}
	if height == 0 {
		t.Fatalf("expected non-zero sequence height, got %d", height)
	}

	rcpt := res.Receipt
	if rcpt == nil {
		t.Fatalf("missing cryptographic receipt in response")
	}
	if !strings.HasPrefix(rcpt["receipt_id"].(string), "rcpt_") {
		t.Fatalf("unexpected receipt_id format: %v", rcpt["receipt_id"])
	}
	payoutDest := rcpt["payout_address"].(string)
	if !strings.HasPrefix(strings.ToLower(payoutDest), "0x") {
		t.Fatalf("invalid payout destination: %s", payoutDest)
	}

	// 3. Execute Second Call (Streaming Cheque Progression)
	res2, height2, err := agClient.ExecuteService(ctx, "data.transform", map[string]any{
		"text":      "second streaming micro payment",
		"operation": "tokenize",
	})
	if err != nil {
		t.Fatalf("second ExecuteService call failed: %v", err)
	}
	if height2 != height+1 {
		t.Fatalf("expected monotonic height increment: %d != %d + 1", height2, height)
	}
	if res2.Status != "success" {
		t.Fatalf("expected status 'success' on second call, got '%s'", res2.Status)
	}

	t.Logf("E2E SUCCESS: Go client executed 2 micro-cheque tasks on independent Python provider!")
	t.Logf("Provider payout destination: %s", payoutDest)
}
