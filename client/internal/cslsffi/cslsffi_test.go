// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package cslsffi_test

import (
	"encoding/hex"
	"testing"

	"csls/internal/cslsffi"
)

func TestDeriveKeypair(t *testing.T) {
	skHex := "1111111111111111111111111111111111111111111111111111111111111111"
	sk, err := hex.DecodeString(skHex)
	if err != nil {
		t.Fatal(err)
	}

	comp, uncomp, err := cslsffi.DeriveKeypair(sk)
	if err != nil {
		t.Fatalf("DeriveKeypair failed: %v", err)
	}
	if len(comp) != 33 {
		t.Fatalf("expected 33 bytes compressed, got %d", len(comp))
	}
	if len(uncomp) != 65 {
		t.Fatalf("expected 65 bytes uncompressed, got %d", len(uncomp))
	}
	if uncomp[0] != 0x04 {
		t.Fatalf("uncompressed point must start with 0x04, got 0x%02x", uncomp[0])
	}
}

func TestAgentSessionAndCheque(t *testing.T) {
	agentSk, _ := hex.DecodeString("1111111111111111111111111111111111111111111111111111111111111111")
	vendorSk, _ := hex.DecodeString("2222222222222222222222222222222222222222222222222222222222222222")

	vendorPKComp, _, err := cslsffi.DeriveKeypair(vendorSk)
	if err != nil {
		t.Fatal(err)
	}

	agent, err := cslsffi.NewAgent(agentSk, "")
	if err != nil {
		t.Fatalf("NewAgent failed: %v", err)
	}
	defer agent.Close()

	// 1. Session handshake init
	initPkt, err := agent.SessionBegin(vendorPKComp)
	if err != nil {
		t.Fatalf("SessionBegin failed: %v", err)
	}
	if len(initPkt) != 95 {
		t.Fatalf("expected 95 bytes session init packet, got %d", len(initPkt))
	}

	// 2. Sign 167-byte cheque
	wireCheque, height, err := agent.SignChequeMAC(vendorPKComp, 500) // $0.0005 = 500 micro-USDC
	if err != nil {
		t.Fatalf("SignChequeMAC failed: %v", err)
	}
	if len(wireCheque) != 167 {
		t.Fatalf("expected 167 bytes wire cheque, got %d", len(wireCheque))
	}
	if height < 1 {
		t.Fatalf("expected height >= 1, got %d", height)
	}
}

func TestEquivocationSimulation(t *testing.T) {
	out, rc, err := cslsffi.RunEquivocationSimulation()
	if err != nil {
		t.Fatalf("RunEquivocationSimulation error: %v", err)
	}
	if rc != 0 {
		t.Fatalf("expected rc 0, got %d", rc)
	}
	if len(out) == 0 {
		t.Fatal("expected non-empty captured stdout from C11 equivocation test")
	}
}
