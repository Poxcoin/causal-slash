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
	mu                     sync.RWMutex
	Cwd                    string
	CurrentModel           string
	ReasoningEffort        string // "low", "medium", "high"
	VendorURL              string
	Memory                 *MemoryManager
	Wallet                 *WalletData
	WalletLoadErr          error
	VendorPK               []byte
	SessionInitialized     bool
	LastSessionVendorPKHex string
	AccumulatedSpentUSDC   float64
	TotalQueries           int
	VaultAddress           string
	ProviderID             string
	MerchantName           string
	ProviderPayoutAddress  string
	ProviderCapabilities   []string
	ProviderUnitPriceMicro uint64
	MerchantPaidUSDC       map[string]float64
	MerchantPayoutMap      map[string]string
}

// NewState creates a fresh session state.
func NewState() *State {
	cwd, err := os.Getwd()
	if err != nil || cwd == "" {
		cwd = "."
	}
	wallet, err := LoadWallet()
	if os.IsNotExist(err) || (err == nil && wallet == nil) {
		wallet, err = GenerateNewWallet()
	}

	s := &State{
		Cwd:               cwd,
		CurrentModel:      LoadActiveModel(),
		ReasoningEffort:   "medium",
		Memory:            NewMemoryManager(cwd),
		Wallet:            wallet,
		WalletLoadErr:     err,
		VaultAddress:      "0x8faAD06ef5937Ad1019CD49f5Dcab36181e266A5",
		MerchantPaidUSDC:  make(map[string]float64),
		MerchantPayoutMap: make(map[string]string),
	}
	return s
}

// RecordMerchantPayment records a direct micro-cheque payment to a merchant's Base L2 payout address.
func (s *State) RecordMerchantPayment(merchantID, payoutAddr string, amountUSDC float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.MerchantPaidUSDC == nil {
		s.MerchantPaidUSDC = make(map[string]float64)
	}
	if s.MerchantPayoutMap == nil {
		s.MerchantPayoutMap = make(map[string]string)
	}
	key := strings.ToLower(strings.TrimSpace(merchantID))
	if key == "" {
		key = "default"
	}
	s.MerchantPaidUSDC[key] += amountUSDC
	if payoutAddr != "" {
		s.MerchantPayoutMap[key] = payoutAddr
	}
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

// ActiveModelFile returns path to ~/.csls/active_model
func ActiveModelFile() string {
	return filepath.Join(ConfigDir(), "active_model")
}

// LoadActiveModel returns the saved model reference or a sensible default.
func LoadActiveModel() string {
	if raw, err := os.ReadFile(ActiveModelFile()); err == nil {
		m := strings.TrimSpace(string(raw))
		if m != "" {
			return m
		}
	}
	// Check config.toml
	cfgFile := filepath.Join(ConfigDir(), "config.toml")
	if raw, err := os.ReadFile(cfgFile); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "model") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					val := strings.Trim(strings.TrimSpace(parts[1]), "\"'")
					if val != "" && strings.Contains(val, ":") {
						return val
					}
				}
			}
		}
	}
	return "google:gemini-3.5-flash"
}

// SaveActiveModel persists the chosen model reference to disk.
func SaveActiveModel(model string) error {
	model = strings.TrimSpace(model)
	if model == "" {
		if err := os.Remove(ActiveModelFile()); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return writeAtomicFile(ActiveModelFile(), []byte(model+"\n"))
}

var (
	themeMu     sync.RWMutex
	cachedTheme string
)

// ThemeFile returns path to ~/.csls/theme
func ThemeFile() string {
	return filepath.Join(ConfigDir(), "theme")
}

// HasThemeConfigured checks if user has previously configured a theme.
func HasThemeConfigured() bool {
	_, err := os.Stat(ThemeFile())
	return err == nil
}

// LoadTheme loads active theme or returns default cyber-emerald.
func LoadTheme() string {
	themeMu.RLock()
	if cachedTheme != "" {
		t := cachedTheme
		themeMu.RUnlock()
		return t
	}
	themeMu.RUnlock()

	themeMu.Lock()
	defer themeMu.Unlock()
	if raw, err := os.ReadFile(ThemeFile()); err == nil {
		t := strings.TrimSpace(string(raw))
		if t != "" {
			cachedTheme = t
			return t
		}
	}
	cachedTheme = "cyber-emerald"
	return cachedTheme
}

// SaveTheme persists selected theme.
func SaveTheme(theme string) error {
	theme = strings.TrimSpace(theme)
	if theme == "" {
		theme = "cyber-emerald"
	}
	themeMu.Lock()
	defer themeMu.Unlock()
	if err := writeAtomicFile(ThemeFile(), []byte(theme+"\n")); err != nil {
		return err
	}
	cachedTheme = theme
	return nil
}
