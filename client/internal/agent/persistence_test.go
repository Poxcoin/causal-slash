// SPDX-License-Identifier: Apache-2.0
package agent_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"csls/internal/agent"
	"csls/internal/session"
)

func TestProcessQueryReportsSettledPersistenceFailure(t *testing.T) {
	for _, scenario := range []struct{ method, target string }{
		{"query", "wallet"}, {"query", "conversation"}, {"service", "wallet"},
	} {
		t.Run(scenario.method+"/"+scenario.target, func(t *testing.T) {
			target := scenario.target
			t.Setenv("CSLS_HOME", t.TempDir())
			t.Setenv("CSLS_PUBLIC_RELAYS", "")
			sess := session.NewState()
			sess.ProviderID = "test-merchant"
			sess.ProviderPayoutAddress = "test-payout"
			sess.ProviderUnitPriceMicro = 750
			path := session.WalletPath()
			if target == "conversation" {
				path = sess.Memory.MemoryFile()
			}
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			// A directory at the destination forces atomic replacement to fail.
			if err := os.MkdirAll(path, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(path, "keep"), []byte("preserve"), 0600); err != nil {
				t.Fatal(err)
			}
			pk := agent.CanonicalMerchants()[0].PublicKeyHex
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/health":
					fmt.Fprintf(w, `{"vendor_pk":%q}`, pk)
				case "/v1/session/init":
					w.WriteHeader(http.StatusOK)
				case "/v1/chat/completions":
					fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"received\"}}]}\n\ndata: [DONE]\n\n")
				case "/v1/service/execute":
					fmt.Fprint(w, `{"status":"ok","result":"received"}`)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			sess.VendorURL = server.URL
			c := agent.NewClient(sess)
			defer c.Close()
			var reply string
			var height uint64
			var err error
			if scenario.method == "service" {
				var result *agent.ServiceExecutionResult
				result, height, err = c.ExecuteService(context.Background(), "test", "ping")
				if result != nil && result.Status == "ok" {
					reply, _ = result.Result.(string)
				}
			} else {
				reply, height, err = c.ProcessQuery(context.Background(), "ping", nil)
			}
			if err == nil || !strings.Contains(err.Error(), "failed to persist "+target) || !strings.Contains(err.Error(), "cheque settled at height") {
				t.Fatalf("expected settled %s persistence error, got %v", target, err)
			}
			if reply != "received" || height == 0 {
				t.Fatalf("lost settled result: reply=%q height=%d", reply, height)
			}
			const amount = 0.00075
			if sess.AccumulatedSpentUSDC != amount || sess.TotalQueries != 1 || sess.MerchantPaidUSDC["test-merchant"] != amount {
				t.Fatalf("lost or duplicated settlement: spent=%g queries=%d merchant=%g", sess.AccumulatedSpentUSDC, sess.TotalQueries, sess.MerchantPaidUSDC["test-merchant"])
			}
			if sess.MerchantPayoutMap["test-merchant"] != "test-payout" {
				t.Fatal("lost merchant payout route")
			}
		})
	}
}

func TestInvalidWalletIsNeverOverwritten(t *testing.T) {
	for _, raw := range []string{"{broken json", "{}", "null", `{"private_key":"invalid"}`} {
		for _, freshState := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/fresh=%t", raw, freshState), func(t *testing.T) {
				t.Setenv("HOME", t.TempDir())
				t.Setenv("CSLS_HOME", t.TempDir())
				original := []byte(raw)
				if err := os.WriteFile(session.WalletPath(), original, 0600); err != nil {
					t.Fatal(err)
				}
				sess := &session.State{}
				if freshState {
					sess = session.NewState()
					if raw == "{broken json" && sess.WalletLoadErr == nil {
						t.Fatal("NewState suppressed wallet load error")
					}
				}
				c := agent.NewClient(sess)
				defer c.Close()
				if _, err := c.InitSession(agent.CanonicalMerchants()[0].PublicKeyBytes()); err == nil {
					t.Fatal("expected wallet error")
				}
				got, err := os.ReadFile(session.WalletPath())
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, original) {
					t.Fatal("invalid wallet was overwritten")
				}
			})
		}
	}
}

func TestNewStateCreatesMissingWallet(t *testing.T) {
	t.Setenv("CSLS_HOME", t.TempDir())
	sess := session.NewState()
	if sess.WalletLoadErr != nil || sess.Wallet == nil || sess.Wallet.PrivateKey == "" {
		t.Fatalf("missing wallet was not initialized: %v", sess.WalletLoadErr)
	}
	if _, err := session.LoadWallet(); err != nil {
		t.Fatal(err)
	}
}
