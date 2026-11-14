// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// NewClient initializes agent client and binds the active model's merchant payout route.
func NewClient(sess *session.State) *Client {
	c := &Client{
		sess: sess,
		httpClient: &http.Client{
			Timeout: 300 * time.Second,
		},
		upstreamRouter: NewUpstreamRouter(),
	}
	if sess != nil && (sess.VendorURL == "" || strings.HasPrefix(sess.VendorURL, "csls://")) {
		c.BindMerchant(MerchantForModel(sess.CurrentModel))
	}
	return c
}

// BindMerchant binds the session state directly to a canonical merchant node
// so all 167-byte Session MAC micro-cheques and Base L2 settlements route to it.
func (c *Client) BindMerchant(m MerchantNode) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sess == nil {
		return
	}
	pkBytes := m.PublicKeyBytes()
	if c.sess.LastSessionVendorPKHex != m.PublicKeyHex {
		c.sess.SessionInitialized = false
	}
	c.sess.ProviderID = m.ID
	c.sess.MerchantName = m.Name
	c.sess.ProviderPayoutAddress = m.PayoutAddress
	c.sess.ProviderUnitPriceMicro = m.UnitPriceMicro
	c.sess.ProviderCapabilities = m.Capabilities
	c.sess.VendorPK = pkBytes
	if c.sess.VendorURL == "" || strings.HasPrefix(c.sess.VendorURL, "csls://") {
		c.sess.VendorURL = "csls://merchant/" + m.ID
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
		loaded, err := session.LoadWallet()
		if err == nil && loaded.PrivateKey != "" {
			c.sess.Wallet = loaded
			w = loaded
		} else {
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
// If a remote HTTP/HTTPS vendor URL is configured, it probes GET /health.
// Otherwise, if an in-process merchant route is active, it resolves the canonical merchant.
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

	if len(candidates) == 0 {
		// Resolve directly to the connected merchant for the current model/provider
		target := c.sess.ProviderID
		if target == "" {
			target = c.sess.CurrentModel
		}
		m := MerchantForModel(target)
		c.BindMerchant(m)
		return c.sess.VendorURL, m.PublicKeyBytes(), nil
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

	applyProbe := func(res probeResult) (string, []byte, error) {
		c.mu.Lock()
		c.sess.VendorURL = res.url
		c.sess.VendorPK = res.pk
		if res.health.PayoutAddress != "" {
			c.sess.ProviderPayoutAddress = res.health.PayoutAddress
		}
		if res.health.ProviderID != "" {
			c.sess.ProviderID = res.health.ProviderID
			c.sess.MerchantName = res.health.ProviderID
		}
		if len(res.health.Capabilities) > 0 {
			c.sess.ProviderCapabilities = res.health.Capabilities
		}
		if res.health.UnitPriceMicro > 0 {
			c.sess.ProviderUnitPriceMicro = res.health.UnitPriceMicro
		}
		c.mu.Unlock()
		return res.url, res.pk, nil
	}

	select {
	case res := <-resChan:
		return applyProbe(res)
	case <-probeCtx.Done():
	case <-doneChan:
		select {
		case res := <-resChan:
			return applyProbe(res)
		default:
		}
	}

	return "", nil, fmt.Errorf("no vendor reachable")
}

// ListModels returns the live model catalogue of the configured upstreams.
func (c *Client) ListModels(ctx context.Context) ([]ModelEntry, error) {
	return c.upstreamRouter.ListModels(ctx)
}

// StreamCallback is called for each token chunk received.
type StreamCallback func(chunk string)

// ProcessQuery runs inference with wire clearing via 167-byte Session MAC micro-cheque
// paid directly to the active model's merchant.
func (c *Client) ProcessQuery(ctx context.Context, query string, onChunk StreamCallback) (string, uint64, error) {
	agent, err := c.getOrInitAgent()
	if err != nil {
		return "", 0, err
	}

	var vendorURL string
	var vendorPK []byte
	var isRemoteHTTPVendor bool

	if strings.HasPrefix(c.sess.VendorURL, "http://") || strings.HasPrefix(c.sess.VendorURL, "https://") {
		vURL, vPK, derr := c.DiscoverVendor(ctx)
		if derr == nil {
			vendorURL = vURL
			vendorPK = vPK
			isRemoteHTTPVendor = true
		}
	}

	if !isRemoteHTTPVendor {
		return "", 0, fmt.Errorf("no reachable sovereign CSLS merchant node (configure an http(s):// vendor endpoint; Web2 fallback disabled)")
	}

	history := c.sess.Memory.Messages()
	messages := make([]map[string]string, 0, len(history)+1)
	for _, m := range history {
		messages = append(messages, map[string]string{"role": m.Role, "content": m.Content})
	}
	messages = append(messages, map[string]string{"role": "user", "content": query})

	pkHex := hex.EncodeToString(vendorPK)
	if !c.sess.SessionInitialized || c.sess.LastSessionVendorPKHex != pkHex {
		initPkt, err := agent.SessionBegin(vendorPK)
		if err != nil {
			return "", 0, fmt.Errorf("session begin failed: %w", err)
		}
		if isRemoteHTTPVendor {
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
		}
		c.sess.SessionInitialized = true
		c.sess.LastSessionVendorPKHex = pkHex
	}

	priceMicroUSDC := c.sess.ProviderUnitPriceMicro
	if priceMicroUSDC == 0 {
		priceMicroUSDC = 500
	}

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

	amountUSDC := float64(priceMicroUSDC) / 1e6
	if c.sess.Wallet != nil {
		if c.sess.Wallet.FreeMargin >= amountUSDC {
			c.sess.Wallet.FreeMargin -= amountUSDC
		} else {
			c.sess.Wallet.FreeMargin = 0
		}
		_ = session.SaveWallet(c.sess.Wallet)
	}

	_ = c.sess.Memory.AddTurn(query, reply)
	c.sess.AccumulatedSpentUSDC += amountUSDC
	c.sess.TotalQueries++
	c.sess.RecordMerchantPayment(c.sess.ProviderID, c.sess.ProviderPayoutAddress, amountUSDC)

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

	pkHex := hex.EncodeToString(vendorPK)
	if !c.sess.SessionInitialized || c.sess.LastSessionVendorPKHex != pkHex {
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
		c.sess.LastSessionVendorPKHex = pkHex
	}

	priceMicro := c.sess.ProviderUnitPriceMicro
	if priceMicro == 0 {
		priceMicro = 500
	}

	wireCheque, height, err := agent.SignChequeMAC(vendorPK, priceMicro)
	if err != nil {
		return nil, 0, fmt.Errorf("cheque signing failed: %w", err)
	}
	chequeHex := "0x" + hex.EncodeToString(wireCheque)

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

	amountUSDC := float64(priceMicro) / 1e6
	c.sess.AccumulatedSpentUSDC += amountUSDC
	c.sess.TotalQueries++
	c.sess.RecordMerchantPayment(c.sess.ProviderID, c.sess.ProviderPayoutAddress, amountUSDC)

	return &result, height, nil
}

func parseSSEStream(r io.Reader, onChunk StreamCallback) (string, error) {
	var full strings.Builder
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		dataStr := strings.TrimSpace(line[6:])
		if dataStr == "[DONE]" {
			break
		}
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(dataStr), &chunk); err == nil && len(chunk.Choices) > 0 {
			c := chunk.Choices[0].Delta.Content
			if c != "" {
				full.WriteString(c)
				if onChunk != nil {
					onChunk(c)
				}
			}
		}
	}
	return full.String(), scanner.Err()
}
