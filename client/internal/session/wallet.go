// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package session

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"csls/internal/cslsffi"
)

// WalletData stores sovereign agent secp256k1 keypair and settlement status.
type WalletData struct {
	Address           string  `json:"address"`
	PublicKey         string  `json:"public_key"`
	PrivateKey        string  `json:"private_key"`
	Chain             string  `json:"chain"`
	CollateralBond    float64 `json:"collateral_bond"` // Local demo credit
	FreeMargin        float64 `json:"free_margin"`     // Local free margin
	OnChainBond       float64 `json:"onchain_bond,omitempty"`
	OnChainFreeMargin float64 `json:"onchain_free_margin,omitempty"`
	PendingWithdrawal float64 `json:"pending_withdrawal,omitempty"`
	IsSlashed         bool    `json:"is_slashed,omitempty"`
	Status            string  `json:"status"` // "ready", "demo", "unfunded"
	LastSyncedAt      string  `json:"last_synced_at,omitempty"`
}

// DeriveAddress derives canonical Ethereum address from 65-byte uncompressed pubkey.
// address = last 20 bytes of keccak256(x || y) of sk * G.
func DeriveAddress(pkUncompressed []byte) (string, error) {
	if len(pkUncompressed) != 65 || pkUncompressed[0] != 0x04 {
		return "", errors.New("expected 65-byte uncompressed pubkey starting with 0x04")
	}
	hash := Keccak256(pkUncompressed[1:])
	return "0x" + hex.EncodeToString(hash[12:]), nil
}

// ConfigDir returns ~/.csls or $CSLS_HOME.
func ConfigDir() string {
	if h := os.Getenv("CSLS_HOME"); h != "" {
		return h
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".csls"
	}
	return filepath.Join(home, ".csls")
}

// WalletPath returns path to wallet.json.
func WalletPath() string {
	return filepath.Join(ConfigDir(), "wallet.json")
}

// LoadWallet loads existing wallet from ~/.csls/wallet.json.
func LoadWallet() (*WalletData, error) {
	path := WalletPath()
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var w WalletData
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, err
	}
	return &w, nil
}

// SaveWallet saves wallet to ~/.csls/wallet.json.
func SaveWallet(w *WalletData) error {
	if w == nil {
		return errors.New("cannot save nil wallet")
	}
	dir := ConfigDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "wallet.json.tmp")
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, WalletPath())
}

// GenerateNewWallet generates fresh secp256k1 keypair and saves to wallet.json.
func GenerateNewWallet() (*WalletData, error) {
	sk, err := cslsffi.GenerateRandomKey()
	if err != nil {
		return nil, err
	}
	comp, uncomp, err := cslsffi.DeriveKeypair(sk)
	if err != nil {
		return nil, err
	}
	_ = comp
	addr, err := DeriveAddress(uncomp)
	if err != nil {
		return nil, err
	}

	w := &WalletData{
		Address:        addr,
		PublicKey:      hex.EncodeToString(uncomp),
		PrivateKey:     hex.EncodeToString(sk),
		Chain:          "base-l2",
		CollateralBond: 0.0,
		FreeMargin:     0.0,
		Status:         "unfunded",
	}

	if err := SaveWallet(w); err != nil {
		return nil, err
	}
	return w, nil
}

// SyncWalletOnChain queries Base Sepolia RPC and updates confirmed on-chain bond balances.
func SyncWalletOnChain(w *WalletData, rpcURL, vaultAddr string) (*OnChainVaultState, error) {
	if w == nil || w.Address == "" {
		return nil, errors.New("wallet is not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	state, err := QueryOnChainVault(ctx, rpcURL, vaultAddr, w.Address)
	if err != nil {
		return nil, err
	}

	w.OnChainBond = state.CollateralBondUSDC
	w.OnChainFreeMargin = state.FreeMarginUSDC
	w.PendingWithdrawal = float64(state.PendingWithdrawal) / 1e6
	w.IsSlashed = state.IsSlashed
	w.LastSyncedAt = state.SyncedAt.UTC().Format(time.RFC3339)

	if w.OnChainBond > 0 && !w.IsSlashed {
		w.Status = "ready"
	} else if w.CollateralBond > 0 {
		w.Status = "demo"
	} else {
		w.Status = "unfunded"
	}

	if err := SaveWallet(w); err != nil {
		return nil, fmt.Errorf("failed to save synced wallet: %w", err)
	}
	return state, nil
}

// Deposit tops up the collateral bond balance and updates wallet state.
func Deposit(amount float64) (*WalletData, error) {
	if amount <= 0 {
		return nil, errors.New("deposit amount must be positive")
	}
	w, err := LoadWallet()
	if err != nil {
		if os.IsNotExist(err) {
			w, err = GenerateNewWallet()
			if err != nil {
				return nil, fmt.Errorf("failed to generate new wallet: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to load existing wallet: %w", err)
		}
	} else if w == nil {
		w, err = GenerateNewWallet()
		if err != nil {
			return nil, fmt.Errorf("failed to generate new wallet: %w", err)
		}
	}
	w.CollateralBond += amount
	w.FreeMargin += amount
	if w.OnChainBond > 0 && !w.IsSlashed {
		w.Status = "ready"
	} else {
		w.Status = "demo"
	}
	if err := SaveWallet(w); err != nil {
		return nil, err
	}
	return w, nil
}

// Withdraw reduces collateral balance.
func Withdraw(amount float64) (*WalletData, error) {
	if amount <= 0 {
		return nil, errors.New("withdrawal amount must be positive")
	}
	w, err := LoadWallet()
	if err != nil {
		return nil, fmt.Errorf("failed to load wallet: %w", err)
	}
	if w == nil {
		return nil, errors.New("no wallet found")
	}
	totalAvail := w.FreeMargin
	if w.OnChainFreeMargin > totalAvail {
		totalAvail = w.OnChainFreeMargin
	}
	if amount > totalAvail {
		return nil, fmt.Errorf("requested amount $%.2f exceeds available margin $%.2f", amount, totalAvail)
	}

	if w.FreeMargin >= amount {
		w.FreeMargin -= amount
	} else {
		w.FreeMargin = 0
	}
	if w.CollateralBond >= amount {
		w.CollateralBond -= amount
	} else {
		w.CollateralBond = 0
	}

	if w.CollateralBond <= 0 && w.OnChainBond <= 0 {
		w.Status = "unfunded"
	}
	if err := SaveWallet(w); err != nil {
		return nil, err
	}
	return w, nil
}
