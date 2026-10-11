// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package agent

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"csls/internal/cslsffi"
	"csls/internal/session"
)

var publicRelays = []string{}

// Client manages agent wallet, channel sessions, and M2M inference.
type Client struct {
	mu             sync.Mutex
	sess           *session.State
	agentHandle    *cslsffi.Agent
	httpClient     *http.Client
	upstreamRouter *UpstreamRouter
}

// NewClient initializes agent client.
func NewClient(sess *session.State) *Client {
	return &Client{
		sess: sess,
		httpClient: &http.Client{
			Timeout: 300 * time.Second,
		},
		upstreamRouter: NewUpstreamRouter(),
	}
}

// Close releases C11 agent resources.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.agentHandle != nil {
		c.agentHandle.Close()
		c.agentHandle = nil
	}
}

func (c *Client) getOrInitAgent() (*cslsffi.Agent, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.agentHandle != nil {
		return c.agentHandle, nil
	}

	w := c.sess.Wallet
	if w == nil || w.PrivateKey == "" {
		// Attempt to load existing wallet
		loaded, err := session.LoadWallet()
		if err == nil && loaded.PrivateKey != "" {
			c.sess.Wallet = loaded
			w = loaded
		} else {
			// Auto-generate fresh sovereign wallet out-of-the-box
			newWallet, err := session.GenerateNewWallet()
			if err != nil {
				return nil, fmt.Errorf("failed to generate agent identity: %w", err)
			}
			c.sess.Wallet = newWallet
			w = newWallet
		}
	}

	skBytes, err := cslsffi.HexToBytes(w.PrivateKey)
	if err != nil || len(skBytes) != 32 {
		return nil, errors.New("invalid private key in wallet.json")
	}

	walPath := filepath.Join(session.ConfigDir(), "agent_wal.bin")
	ag, err := cslsffi.NewAgent(skBytes, walPath)
	if err != nil {
		// Fallback to in-memory WAL if directory not writable or testing
		ag, err = cslsffi.NewAgent(skBytes, "")
		if err != nil {
			return nil, fmt.Errorf("failed to initialize C11 agent: %w", err)
		}
	}

	c.agentHandle = ag
	return ag, nil
}

type healthResponse struct {
	Status         string   `json:"status"`
	VendorPK       string   `json:"vendor_pk"`
	ProviderPK     string   `json:"provider_pk"`
	ProviderID     string   `json:"provider_id"`
	PayoutAddress  string   `json:"payout_address"`
	VaultAddress   string   `json:"vault_address"`
	UnitPriceUSDC  float64  `json:"unit_price_usdc"`
	UnitPriceMicro uint64   `json:"unit_price_micro_usdc"`
	SettlementMode string   `json:"settlement_mode"`
	Capabilities   []string `json:"capabilities"`
}

// DiscoverVendor finds the active vendor node URL and its 33-byte compressed public key.
// Returns an error when no vendor is reachable.
func (c *Client) DiscoverVendor(ctx context.Context) (string, []byte, error) {
	c.mu.Lock()
	vurl := c.sess.VendorURL
	c.mu.Unlock()

	candidates := make([]string, 0, len(publicRelays)+1)
	if vurl != "" && !strings.HasPrefix(vurl, "csls://") {
		candidates = append(candidates, strings.TrimRight(vurl, "/"))
	}
	for _, r := range publicRelays {
		r = strings.TrimRight(r, "/")
		found := false
		for _, ex := range candidates {
			if ex == r {
				found = true
				break
			}
		}
		if !found {
			candidates = append(candidates, r)
		}
	}

	type probeResult struct {
		url    string
		pk     []byte
		health healthResponse
	}

	resChan := make(chan probeResult, len(candidates))
	probeCtx, probeCancel := context.WithTimeout(ctx, 40*time.Millisecond)
	defer probeCancel()

	probeClient := &http.Client{Timeout: 40 * time.Millisecond}

	var wg sync.WaitGroup
	for _, cand := range candidates {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			req, err := http.NewRequestWithContext(probeCtx, "GET", url+"/health", nil)
			if err != nil {
				return
			}
			resp, err := probeClient.Do(req)
			if err != nil || resp.StatusCode != 200 {
				if resp != nil {
					_ = resp.Body.Close()
				}
				return
			}
			var hr healthResponse
			err = json.NewDecoder(resp.Body).Decode(&hr)
			_ = resp.Body.Close()
			pkStr := hr.VendorPK
			if pkStr == "" {
				pkStr = hr.ProviderPK
			}
			if err == nil && pkStr != "" {
				pkBytes, err := cslsffi.HexToBytes(pkStr)
				if err == nil && len(pkBytes) == 33 {
					select {
					case resChan <- probeResult{url: url, pk: pkBytes, health: hr}:
					default:
					}
				}
			}
		}(cand)
	}

	doneChan := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneChan)
	}()

	select {
	case res := <-resChan:
		c.mu.Lock()
		c.sess.VendorURL = res.url
		c.sess.VendorPK = res.pk
		if res.health.PayoutAddress != "" {
			c.sess.ProviderPayoutAddress = res.health.PayoutAddress
		}
		if res.health.ProviderID != "" {
			c.sess.ProviderID = res.health.ProviderID
		}
		if len(res.health.Capabilities) > 0 {
			c.sess.ProviderCapabilities = res.health.Capabilities
		}
		if res.health.UnitPriceMicro > 0 {
			c.sess.ProviderUnitPriceMicro = res.health.UnitPriceMicro
		}
		c.mu.Unlock()
		return res.url, res.pk, nil
	case <-probeCtx.Done():
	case <-doneChan:
		select {
		case res := <-resChan:
			c.mu.Lock()
			c.sess.VendorURL = res.url
			c.sess.VendorPK = res.pk
			if res.health.PayoutAddress != "" {
				c.sess.ProviderPayoutAddress = res.health.PayoutAddress
			}
			if res.health.ProviderID != "" {
				c.sess.ProviderID = res.health.ProviderID
			}
			if len(res.health.Capabilities) > 0 {
				c.sess.ProviderCapabilities = res.health.Capabilities
			}
			if res.health.UnitPriceMicro > 0 {
				c.sess.ProviderUnitPriceMicro = res.health.UnitPriceMicro
			}
			c.mu.Unlock()
			return res.url, res.pk, nil
		default:
		}
	}

	return "", nil, fmt.Errorf("no vendor reachable: connect one with /vendor url <url>")
}

// StreamCallback is called for each token chunk received.
type StreamCallback func(chunk string)

// ProcessQuery runs inference with wire clearing via 167-byte Session MAC micro-cheque.
func (c *Client) ProcessQuery(ctx context.Context, query string, onChunk StreamCallback) (string, uint64, error) {
	agent, err := c.getOrInitAgent()
	if err != nil {
		return "", 0, err
	}

	vendorURL, vendorPK, derr := c.DiscoverVendor(ctx)

	history := c.sess.Memory.Messages()
	messages := make([]map[string]string, 0, len(history)+1)
	for _, m := range history {
		messages = append(messages, map[string]string{"role": m.Role, "content": m.Content})
	}
	messages = append(messages, map[string]string{"role": "user", "content": query})

	// No vendor reachable: direct upstream inference, no cheque, no settlement claimed.
	if derr != nil {
		reply, err := c.upstreamRouter.ExecuteStreaming(ctx, c.sess.CurrentModel, messages, onChunk)
		if err != nil {
			return "", 0, fmt.Errorf("no vendor (%v); %w", derr, err)
		}
		_ = c.sess.Memory.AddTurn(query, reply)
		c.sess.TotalQueries++
		return reply, 0, nil
	}

	if !c.sess.SessionInitialized {
		initPkt, err := agent.SessionBegin(vendorPK)
		if err != nil {
			return "", 0, fmt.Errorf("session begin failed: %w", err)
		}
		initPayload, err := json.Marshal(map[string]string{"session_init_pkt": hex.EncodeToString(initPkt)})
		if err != nil {
			return "", 0, err
		}
		initReq, err := http.NewRequestWithContext(ctx, "POST", vendorURL+"/v1/session/init", bytes.NewReader(initPayload))
		if err != nil {
			return "", 0, err
		}
		initReq.Header.Set("Content-Type", "application/json")
		initResp, err := c.httpClient.Do(initReq)
		if err != nil {
			return "", 0, fmt.Errorf("session init failed: %w", err)
		}
		_ = initResp.Body.Close()
		if initResp.StatusCode/100 != 2 {
			return "", 0, fmt.Errorf("session init rejected: HTTP %d", initResp.StatusCode)
		}
		c.sess.SessionInitialized = true
	}

	const priceMicroUSDC = 500
	wireCheque, height, err := agent.SignChequeMAC(vendorPK, priceMicroUSDC)
	if err != nil {
		return "", 0, fmt.Errorf("cheque signing failed: %w", err)
	}
	chequeHex := "0x" + hex.EncodeToString(wireCheque)

	reqBody, err := json.Marshal(map[string]any{
		"model":    c.sess.CurrentModel,
		"messages": messages,
		"stream":   true,
	})
	if err != nil {
		return "", 0, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", vendorURL+"/v1/chat/completions", bytes.NewReader(reqBody))
	if err != nil {
		return "", 0, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Causal-Cheque", chequeHex)
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", 0, fmt.Errorf("vendor request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", 0, fmt.Errorf("vendor returned HTTP %d", resp.StatusCode)
	}
	reply, err := parseSSEStream(resp.Body, onChunk)
	if err != nil {
		return "", 0, fmt.Errorf("vendor stream failed: %w", err)
	}
	if reply == "" {
		return "", 0, fmt.Errorf("vendor returned empty reply")
	}
	_ = c.sess.Memory.AddTurn(query, reply)
	c.sess.AccumulatedSpentUSDC += 0.0005
	c.sess.TotalQueries++
	return reply, height, nil
}

// SignCheque signs an arbitrary micro-USDC cheque to the vendor.
func (c *Client) SignCheque(vendorPK []byte, amountMicro uint64) ([]byte, uint64, error) {
	agent, err := c.getOrInitAgent()
	if err != nil {
		return nil, 0, err
	}
	return agent.SignChequeMAC(vendorPK, amountMicro)
}

// InitSession initiates a Session MAC handshake with the vendor public key.
func (c *Client) InitSession(vendorPK []byte) ([]byte, error) {
	agent, err := c.getOrInitAgent()
	if err != nil {
		return nil, err
	}
	return agent.SessionBegin(vendorPK)
}

// ServiceExecutionResult encapsulates the provider's execution response and verifiable receipt.
type ServiceExecutionResult struct {
	Status     string         `json:"status"`
	Service    string         `json:"service"`
	Result     any            `json:"result"`
	Usage      map[string]any `json:"usage"`
	Settlement map[string]any `json:"settlement"`
	Receipt    map[string]any `json:"receipt"`
}

// ExecuteService discovers the provider, completes session handshake if needed,
// signs a 167-byte Session MAC micro-cheque for the capability unit price,
// and invokes POST /v1/service/execute.
func (c *Client) ExecuteService(ctx context.Context, capability string, input any) (*ServiceExecutionResult, uint64, error) {
	agent, err := c.getOrInitAgent()
	if err != nil {
		return nil, 0, err
	}

	vendorURL, vendorPK, err := c.DiscoverVendor(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("provider discovery failed: %w", err)
	}

	if !strings.HasPrefix(vendorURL, "http://") && !strings.HasPrefix(vendorURL, "https://") {
		return nil, 0, fmt.Errorf("independent provider must be an HTTP/HTTPS endpoint, got '%s'", vendorURL)
	}

	// 1. Session MAC handshake if needed
	if !c.sess.SessionInitialized {
		initPkt, err := agent.SessionBegin(vendorPK)
		if err != nil {
			return nil, 0, fmt.Errorf("session begin failed: %w", err)
		}
		initPayload, _ := json.Marshal(map[string]string{
			"session_init_pkt": hex.EncodeToString(initPkt),
		})
		initReq, err := http.NewRequestWithContext(ctx, "POST", vendorURL+"/v1/session/init", bytes.NewReader(initPayload))
		if err != nil {
			return nil, 0, fmt.Errorf("failed to create session init request: %w", err)
		}
		initReq.Header.Set("Content-Type", "application/json")
		initResp, err := c.httpClient.Do(initReq)
		if err != nil {
			return nil, 0, fmt.Errorf("provider session handshake connection failed: %w", err)
		}
		defer initResp.Body.Close()
		if initResp.StatusCode != 200 {
			var errData map[string]any
			_ = json.NewDecoder(initResp.Body).Decode(&errData)
			return nil, 0, fmt.Errorf("provider rejected session init (HTTP %d): %v", initResp.StatusCode, errData["error"])
		}
		c.sess.SessionInitialized = true
	}

	// 2. Determine price
	priceMicro := c.sess.ProviderUnitPriceMicro
	if priceMicro == 0 {
		priceMicro = 500
	}

	// 3. Sign 167-Byte Session MAC Micro-Cheque (0 Gas)
	wireCheque, height, err := agent.SignChequeMAC(vendorPK, priceMicro)
	if err != nil {
		return nil, 0, fmt.Errorf("cheque signing failed: %w", err)
	}
	chequeHex := "0x" + hex.EncodeToString(wireCheque)

	// 4. Send request to provider
	reqBody, _ := json.Marshal(map[string]any{
		"capability": capability,
		"input":      input,
	})
	httpReq, err := http.NewRequestWithContext(ctx, "POST", vendorURL+"/v1/service/execute", bytes.NewReader(reqBody))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create service execution request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Causal-Cheque", chequeHex)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, 0, fmt.Errorf("provider communication failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		var errData map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errData)
		errMsg, _ := errData["error"].(string)
		if errMsg == "" {
			errMsg = fmt.Sprintf("HTTP status %d", resp.StatusCode)
		}
		return nil, 0, fmt.Errorf("provider execution failed (%s)", errMsg)
	}

	var result ServiceExecutionResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, 0, fmt.Errorf("failed to decode provider response: %w", err)
	}

	// Update spent accounting
	c.sess.AccumulatedSpentUSDC += float64(priceMicro) / 1e6
	c.sess.TotalQueries++

	return &result, height, nil
}
