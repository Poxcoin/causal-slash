// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package session

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestWalletNilAndValidation(t *testing.T) {
	// 1. SaveWallet(nil) must return error
	if err := SaveWallet(nil); err == nil {
		t.Fatal("expected error when saving nil wallet, got nil")
	}

	// 2. Deposit non-positive amounts must fail
	if _, err := Deposit(0); err == nil {
		t.Fatal("expected error when depositing 0, got nil")
	}
	if _, err := Deposit(-5.0); err == nil {
		t.Fatal("expected error when depositing negative amount, got nil")
	}

	// 3. Withdraw non-positive amounts must fail
	if _, err := Withdraw(0); err == nil {
		t.Fatal("expected error when withdrawing 0, got nil")
	}
	if _, err := Withdraw(-1.0); err == nil {
		t.Fatal("expected error when withdrawing negative amount, got nil")
	}
}

func TestDisplayCwdBoundary(t *testing.T) {
	s := NewState()
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("user home dir not available")
	}

	// Exact home
	s.Cwd = home
	if got := s.DisplayCwd(); got != "~" {
		t.Fatalf("expected '~', got '%s'", got)
	}

	// Subdirectory inside home
	s.Cwd = filepath.Join(home, "projects", "csls")
	expected := "~" + string(filepath.Separator) + filepath.Join("projects", "csls")
	if got := s.DisplayCwd(); got != expected {
		t.Fatalf("expected '%s', got '%s'", expected, got)
	}

	// Prefix collision check (e.g. /home/user2 should NOT become ~2)
	s.Cwd = home + "2"
	if got := s.DisplayCwd(); got != home+"2" {
		t.Fatalf("expected '%s', got '%s'", home+"2", got)
	}
}

func TestBondStatusConcurrent(t *testing.T) {
	s := NewState()
	s.Wallet = &WalletData{
		CollateralBond: 10.0,
		Status:         "ready",
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.BondStatus()
		}()
	}
	wg.Wait()
}
