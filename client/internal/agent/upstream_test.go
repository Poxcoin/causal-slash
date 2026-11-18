// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package agent_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"csls/internal/agent"
	"csls/internal/session"
)

func TestCanonical2026ModelCatalogue(t *testing.T) {
	router := agent.NewUpstreamRouter()
	ctx := context.Background()

	models, err := router.ListModels(ctx)
	if err != nil {
		t.Fatalf("ListModels failed: %v", err)
	}

	if len(models) == 0 {
		t.Fatalf("expected non-empty canonical 2026 model catalogue")
	}

	foundOpus := false
	foundSol := false
	for _, m := range models {
		if m.ID == "claude-opus-5.5" {
			foundOpus = true
		}
		if m.ID == "gpt-6.1-sol" {
			foundSol = true
		}
	}

	if !foundOpus || !foundSol {
		t.Fatalf("canonical 2026 model catalogue missing frontier models (Opus: %v, Sol: %v)", foundOpus, foundSol)
	}
}

func TestMerchantDirectRoutingAndKeys(t *testing.T) {
	merchants := agent.CanonicalMerchants()
	if len(merchants) < 15 {
		t.Fatalf("expected at least 15 canonical merchants, got %d", len(merchants))
	}

	for _, m := range merchants {
		pk := m.PublicKeyBytes()
		if len(pk) != 33 {
			t.Fatalf("merchant %s invalid compressed secp256k1 pubkey length: %d", m.ID, len(pk))
		}
		if !strings.HasPrefix(m.PayoutAddress, "0x") || len(m.PayoutAddress) != 42 {
			t.Fatalf("merchant %s invalid Base L2 payout address: %s", m.ID, m.PayoutAddress)
		}
		if m.UnitPriceMicro == 0 {
			t.Fatalf("merchant %s must have non-zero UnitPriceMicro", m.ID)
		}
	}

	anth, ok := agent.ResolveMerchant("anthropic:claude-opus-5.5")
	if !ok || anth.ID != "anthropic" {
		t.Fatalf("expected anthropic merchant for anthropic:claude-opus-5.5, got %v", anth)
	}

	ds, ok := agent.ResolveMerchant("deepseek:deepseek-v4-pro")
	if !ok || ds.ID != "deepseek" {
		t.Fatalf("expected deepseek merchant for deepseek:deepseek-v4-pro, got %v", ds)
	}
}

func TestProcessQueryRequiresReachableMerchant(t *testing.T) {
	t.Setenv("CSLS_PUBLIC_RELAYS", "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	for _, endpoint := range []string{"", "csls://merchant/anthropic", server.URL} {
		c := agent.NewClient(&session.State{VendorURL: endpoint})
		start := time.Now()
		reply, height, err := c.ProcessQuery(context.Background(), "ping", nil)
		c.Close()
		if err == nil || !strings.Contains(err.Error(), "no reachable sovereign CSLS merchant node") || reply != "" || height != 0 {
			t.Fatalf("endpoint %q: reply=%q height=%d err=%v", endpoint, reply, height, err)
		}
		if time.Since(start) > 2*time.Second {
			t.Fatal("discovery did not fail fast")
		}
	}
}

func TestDiscoverVendorWANLatency(t *testing.T) {
	t.Setenv("CSLS_PUBLIC_RELAYS", "")
	pk := agent.CanonicalMerchants()[0].PublicKeyHex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
			return
		}
		time.Sleep(100 * time.Millisecond)
		fmt.Fprintf(w, `{"vendor_pk":%q}`, pk)
	}))
	defer server.Close()
	c := agent.NewClient(&session.State{VendorURL: server.URL})
	defer c.Close()
	start := time.Now()
	endpoint, key, err := c.DiscoverVendor(context.Background())
	if err != nil || endpoint != server.URL || len(key) != 33 {
		t.Fatalf("endpoint=%q key=%x err=%v", endpoint, key, err)
	}
	if time.Since(start) < 100*time.Millisecond {
		t.Fatal("health handler was not awaited")
	}
	// Discover a relay even when no explicit merchant endpoint is configured.
	t.Setenv("CSLS_PUBLIC_RELAYS", "ftp://invalid, file:///invalid, "+server.URL+", "+server.URL)
	c = agent.NewClient(&session.State{})
	defer c.Close()
	if endpoint, _, err := c.DiscoverVendor(context.Background()); err != nil || endpoint != server.URL {
		t.Fatalf("relay discovery: %s %v", endpoint, err)
	}
}

func TestDiscoverVendorFailsFast(t *testing.T) {
	t.Setenv("CSLS_PUBLIC_RELAYS", "")
	failed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer failed.Close()
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer slow.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unreachable := "http://" + listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{failed.URL, slow.URL, unreachable} {
		c := agent.NewClient(&session.State{VendorURL: endpoint})
		start := time.Now()
		_, _, err := c.DiscoverVendor(context.Background())
		c.Close()
		if err == nil || !strings.Contains(err.Error(), "no vendor reachable") {
			t.Fatalf("endpoint=%s err=%v", endpoint, err)
		}
		if time.Since(start) > 2500*time.Millisecond {
			t.Fatal("discovery exceeded bounded timeout")
		}
	}
}
