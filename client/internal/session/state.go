// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package session

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// State manages the live CSLS runtime session state.
type State struct {
	mu                   sync.RWMutex
	Cwd                  string
	CurrentModel         string
	ReasoningEffort      string // "low", "medium", "high"
	VendorURL            string
	Memory               *MemoryManager
	Wallet               *WalletData
	VendorPK             []byte
	SessionInitialized     bool
	AccumulatedSpentUSDC   float64
	TotalQueries           int
	VaultAddress           string
	ProviderID             string
	ProviderPayoutAddress  string
	ProviderCapabilities   []string
	ProviderUnitPriceMicro uint64
}

// NewState creates a fresh session state.
func NewState() *State {
	cwd, err := os.Getwd()
	if err != nil || cwd == "" {
		cwd = "."
	}
	wallet, err := LoadWallet()
	if err != nil {
		if os.IsNotExist(err) {
			wallet, err = GenerateNewWallet()
			if err != nil {
				wallet = &WalletData{
					Status: "unfunded",
					Chain:  "base-l2",
				}
			}
		} else {
			// Existing wallet file could not be parsed or read; do NOT overwrite!
			// Fallback to in-memory unfunded wallet to avoid crashing while preserving disk file.
			wallet = &WalletData{
				Status: "unfunded",
				Chain:  "base-l2",
			}
		}
	} else if wallet == nil {
		wallet, err = GenerateNewWallet()
		if err != nil {
			wallet = &WalletData{
				Status: "unfunded",
				Chain:  "base-l2",
			}
		}
	}

	s := &State{
		Cwd:          cwd,
		CurrentModel: "",
		ReasoningEffort: "medium",
		Memory:       NewMemoryManager(cwd),
		Wallet:       wallet,
		VaultAddress: "0x8faAD06ef5937Ad1019CD49f5Dcab36181e266A5",
	}
	return s
}

// BondStatus returns "ready" or "no bond".
// Must strictly adhere to the invariant: "ready" ONLY when positive collateral bond and status is ready.
func (s *State) BondStatus() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Reload wallet if needed
	w, err := LoadWallet()
	if err == nil && w != nil {
		s.Wallet = w
	}

	if s.Wallet != nil && s.Wallet.CollateralBond > 0 && s.Wallet.Status == "ready" {
		return "ready"
	}
	return "no bond"
}

// DisplayCwd returns formatted cwd replacing home with ~
func (s *State) DisplayCwd() string {
	cwd := s.Cwd
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		if cwd == h {
			return "~"
		}
		if strings.HasPrefix(cwd, h+string(filepath.Separator)) {
			return "~" + cwd[len(h):]
		}
	}
	return cwd
}
