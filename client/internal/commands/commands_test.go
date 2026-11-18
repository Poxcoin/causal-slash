// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package commands

import (
	"strings"
	"testing"

	"csls/internal/agent"
	"csls/internal/session"
)

func setupTestSession(t *testing.T) (*session.State, *agent.Client, string) {
	t.Helper()
	t.Setenv("CSLS_HOME", t.TempDir())
	sess := session.NewState()
	sess.CurrentModel = ""
	sess.Memory.Clear()
	agentClient := agent.NewClient(sess)
	repoRoot := "../../.." // points to repository root from client/internal/commands
	return sess, agentClient, repoRoot
}

func TestSlashHelp(t *testing.T) {
	sess, client, root := setupTestSession(t)
	defer client.Close()

	res := Execute("/help", sess, client, root)
	if !strings.Contains(res.Output, "Commands") || !strings.Contains(res.Output, "/bond") {
		t.Fatalf("unexpected /help output: %s", res.Output)
	}

	resSub := Execute("/help bond", sess, client, root)
	if !strings.Contains(resSub.Output, "/bond") {
		t.Fatalf("unexpected /help bond output: %s", resSub.Output)
	}
}

func TestSlashStatus(t *testing.T) {
	sess, client, root := setupTestSession(t)
	defer client.Close()

	res := Execute("/status", sess, client, root)
	if !strings.Contains(res.Output, "Causal-Slash Protocol Node Status") {
		t.Fatalf("unexpected /status output: %s", res.Output)
	}
	if !strings.Contains(res.Output, "167-Byte Session MAC") {
		t.Fatalf("missing settlement mode in /status: %s", res.Output)
	}
}

func TestSlashBond(t *testing.T) {
	sess, client, root := setupTestSession(t)
	defer client.Close()

	res := Execute("/bond", sess, client, root)
	if !strings.Contains(res.Output, "Base L2 Collateral Bond Status") {
		t.Fatalf("unexpected /bond output: %s", res.Output)
	}
}

func TestSlashWallet(t *testing.T) {
	sess, client, root := setupTestSession(t)
	defer client.Close()

	res := Execute("/wallet info", sess, client, root)
	if !strings.Contains(res.Output, "Address") && !strings.Contains(res.Output, "No wallet found") {
		t.Fatalf("unexpected /wallet info output: %s", res.Output)
	}
}

func TestSlashDeposit(t *testing.T) {
	sess, client, root := setupTestSession(t)
	defer client.Close()

	res := Execute("/deposit 1.0", sess, client, root)
	if !strings.Contains(res.Output, "Collateral Bond Deposited") {
		t.Fatalf("unexpected /deposit output: %s", res.Output)
	}
}

func TestSlashModel(t *testing.T) {
	sess, client, root := setupTestSession(t)
	defer client.Close()

	resBad := Execute("/model deepseek-v4.1-flash", sess, client, root)
	if !strings.Contains(resBad.Output, "Invalid model") {
		t.Fatalf("bare id must be rejected: %s", resBad.Output)
	}
	if sess.CurrentModel != "" {
		t.Fatalf("CurrentModel must stay empty, got: %s", sess.CurrentModel)
	}

	resSet := Execute("/model groq:llama-3.3-70b-versatile", sess, client, root)
	if !strings.Contains(resSet.Output, "Active model set to: groq:llama-3.3-70b-versatile") {
		t.Fatalf("failed to switch model: %s", resSet.Output)
	}
	if sess.CurrentModel != "groq:llama-3.3-70b-versatile" {
		t.Fatalf("unexpected CurrentModel: %s", sess.CurrentModel)
	}
}

func TestSlashVendor(t *testing.T) {
	sess, client, root := setupTestSession(t)
	defer client.Close()

	res := Execute("/vendor", sess, client, root)
	if !strings.Contains(res.Output, "Provider Route") {
		t.Fatalf("unexpected /vendor output: %s", res.Output)
	}

	resList := Execute("/vendor list", sess, client, root)
	if !strings.Contains(resList.Output, "Supported AI Provider Routes") || !strings.Contains(resList.Output, "anthropic") {
		t.Fatalf("unexpected /vendor list output: %s", resList.Output)
	}
}

func TestSlashMemoryAndClear(t *testing.T) {
	sess, client, root := setupTestSession(t)
	defer client.Close()

	resMem := Execute("/memory", sess, client, root)
	if !strings.Contains(resMem.Output, "Persistent Chat Memory") {
		t.Fatalf("unexpected /memory output: %s", resMem.Output)
	}

	resClear := Execute("/clear", sess, client, root)
	if !strings.Contains(resClear.Output, "Conversation memory reset") {
		t.Fatalf("unexpected /clear output: %s", resClear.Output)
	}
}

func TestSlashHound(t *testing.T) {
	sess, client, root := setupTestSession(t)
	defer client.Close()

	res := Execute("/hound", sess, client, root)
	if !strings.Contains(res.Output, "Schnorr Bloodhound") {
		t.Fatalf("unexpected /hound output: %s", res.Output)
	}
}

func TestSlashNet(t *testing.T) {
	sess, client, root := setupTestSession(t)
	defer client.Close()

	res := Execute("/net", sess, client, root)
	if !strings.Contains(res.Output, "Kirchhoff In-RAM Netting") {
		t.Fatalf("unexpected /net output: %s", res.Output)
	}
}

func TestSlashStream(t *testing.T) {
	sess, client, root := setupTestSession(t)
	defer client.Close()

	res := Execute("/stream", sess, client, root)
	if !strings.Contains(res.Output, "167-Byte Session MAC") {
		t.Fatalf("unexpected /stream output: %s", res.Output)
	}
}

func TestSlashVerify(t *testing.T) {
	sess, client, root := setupTestSession(t)
	defer client.Close()

	res := Execute("/verify", sess, client, root)
	if !strings.Contains(res.Output, "PerformanceCollateralVault") {
		t.Fatalf("unexpected /verify output: %s", res.Output)
	}
}

func TestSlashDaemon(t *testing.T) {
	sess, client, root := setupTestSession(t)
	defer client.Close()

	res := Execute("/daemon", sess, client, root)
	if !strings.Contains(res.Output, "Standalone TCP Relay Daemon") {
		t.Fatalf("unexpected /daemon output: %s", res.Output)
	}
}

func TestSlashProxy(t *testing.T) {
	sess, client, root := setupTestSession(t)
	defer client.Close()

	res := Execute("/proxy", sess, client, root)
	if !strings.Contains(res.Output, "SlashSidecarProxy") {
		t.Fatalf("unexpected /proxy output: %s", res.Output)
	}
}

func TestSlashTestC(t *testing.T) {
	sess, client, root := setupTestSession(t)
	defer client.Close()

	res := Execute("/test c", sess, client, root)
	if !strings.Contains(res.Output, "Protocol Test Suite: C11 Engine & Equivocation Tests") {
		t.Fatalf("unexpected /test c output: %s", res.Output)
	}
	if !strings.Contains(res.Output, "ALL TESTS PASSED") {
		t.Fatalf("expected test pass in /test c, got: %s", res.Output)
	}
}

func TestClosestMatch(t *testing.T) {
	match := findClosestMatch("/bon")
	if match != "/bond" {
		t.Fatalf("expected /bond, got %s", match)
	}
}

func TestSlashWithdraw(t *testing.T) {
	sess, client, root := setupTestSession(t)
	defer client.Close()

	sess.Wallet.CollateralBond = 10.0
	sess.Wallet.FreeMargin = 10.0
	if err := session.SaveWallet(sess.Wallet); err != nil {
		t.Fatalf("failed to save wallet: %v", err)
	}

	// 1. /withdraw usage
	resUsage := Execute("/withdraw", sess, client, root)
	if !strings.Contains(resUsage.Output, "Collateral Margin Withdrawal") {
		t.Fatalf("unexpected /withdraw usage output: %s", resUsage.Output)
	}

	// 2. /withdraw demo
	resDemo := Execute("/withdraw 2.5 demo", sess, client, root)
	if !strings.Contains(resDemo.Output, "Local Demo Collateral Withdrawn") || !strings.Contains(resDemo.Output, "-$2.5000") {
		t.Fatalf("unexpected /withdraw demo output: %s", resDemo.Output)
	}
	if sess.Wallet.FreeMargin > 7.51 || sess.Wallet.FreeMargin < 7.49 {
		t.Fatalf("expected remaining free margin ~7.5, got: %f", sess.Wallet.FreeMargin)
	}

	// 3. /withdraw excessive amount
	resExcess := Execute("/withdraw 999.0 demo", sess, client, root)
	if !strings.Contains(resExcess.Output, "exceeds available margin") {
		t.Fatalf("expected margin error on excessive withdrawal, got: %s", resExcess.Output)
	}

	// 4. /withdraw instant instructions
	sess.Wallet.OnChainFreeMargin = 5.0
	resInstant := Execute("/withdraw 1.0 instant", sess, client, root)
	if !strings.Contains(resInstant.Output, "instantWithdraw(uint256)") {
		t.Fatalf("unexpected /withdraw instant output: %s", resInstant.Output)
	}

	// 5. /withdraw emergency instructions
	resEmerg := Execute("/withdraw 1.0 emergency", sess, client, root)
	if !strings.Contains(resEmerg.Output, "initiateEmergencyWithdrawal(uint256)") || !strings.Contains(resEmerg.Output, "7 Days Timelock") {
		t.Fatalf("unexpected /withdraw emergency output: %s", resEmerg.Output)
	}

	// 6. /withdraw finalize instructions
	resFin := Execute("/withdraw finalize", sess, client, root)
	if !strings.Contains(resFin.Output, "finalizeEmergencyWithdrawal()") {
		t.Fatalf("unexpected /withdraw finalize output: %s", resFin.Output)
	}
}

func TestSlashSend(t *testing.T) {
	sess, client, root := setupTestSession(t)
	defer client.Close()

	sess.Wallet.CollateralBond = 5.0
	sess.Wallet.FreeMargin = 5.0
	sess.Wallet.Status = "ready"
	if err := session.SaveWallet(sess.Wallet); err != nil {
		t.Fatalf("failed to save wallet: %v", err)
	}

	// 1. /send usage
	resUsage := Execute("/send", sess, client, root)
	if !strings.Contains(resUsage.Output, "167-Byte Session MAC Micro-Cheque") {
		t.Fatalf("unexpected /send usage output: %s", resUsage.Output)
	}

	// 2. /send 0.0005 to active provider
	resSend := Execute("/send 0.0005", sess, client, root)
	if !strings.Contains(resSend.Output, "167-Byte Session MAC Micro-Cheque Dispatched to Gateway") {
		t.Fatalf("expected direct gateway payment dispatch, got: %s", resSend.Output)
	}
	if sess.AccumulatedSpentUSDC != 0.0005 {
		t.Fatalf("expected spend of 0.0005, got: %f", sess.AccumulatedSpentUSDC)
	}
	if sess.MerchantPaidUSDC["anthropic"] != 0.0005 {
		t.Fatalf("expected anthropic paid 0.0005, got: %f", sess.MerchantPaidUSDC["anthropic"])
	}

	// 3. /send 0.001 directly to specific provider (e.g. deepseek)
	resDeepseek := Execute("/send 0.001 deepseek", sess, client, root)
	if !strings.Contains(resDeepseek.Output, "DeepSeek / SiliconFlow") || !strings.Contains(resDeepseek.Output, "0x5C94B2254e528074E06A3506F7AC5109d5578E70") {
		t.Fatalf("expected deepseek route dispatch, got: %s", resDeepseek.Output)
	}
	if sess.MerchantPaidUSDC["deepseek"] != 0.001 {
		t.Fatalf("expected deepseek paid 0.001, got: %f", sess.MerchantPaidUSDC["deepseek"])
	}

	// 4. Over-margin send fails fast
	resExcess := Execute("/send 100.0", sess, client, root)
	if !strings.Contains(strings.ToLower(resExcess.Output), "insufficient margin") {
		t.Fatalf("expected insufficient margin, got: %s", resExcess.Output)
	}
}

func TestSlashDepositVariations(t *testing.T) {
	sess, client, root := setupTestSession(t)
	defer client.Close()

	// 1. /deposit onchain instructions
	resOnchain := Execute("/deposit onchain", sess, client, root)
	if !strings.Contains(resOnchain.Output, "0xa07eA15D1FE0B884Ffb51b19d98D938b2Bf04D6B") || strings.Contains(resOnchain.Output, "<USDC_ADDR>") || !strings.Contains(resOnchain.Output, "mint(address,uint256)") {
		t.Fatalf("invalid onchain USDC instructions: %s", resOnchain.Output)
	}
	if !strings.Contains(resOnchain.Output, "PerformanceCollateralVault") || !strings.Contains(resOnchain.Output, "cast send") {
		t.Fatalf("unexpected /deposit onchain output: %s", resOnchain.Output)
	}

	// 2. /deposit demo top-up
	resDeposit := Execute("/deposit 2.0 demo", sess, client, root)
	if !strings.Contains(resDeposit.Output, "Base L2 Collateral Bond Deposited") || !strings.Contains(resDeposit.Output, "+2.00 USDC") {
		t.Fatalf("unexpected /deposit demo output: %s", resDeposit.Output)
	}
}

func TestSlashHoundAndNetProduction(t *testing.T) {
	sess, client, root := setupTestSession(t)
	defer client.Close()

	// 1. /hound execution
	resHound := Execute("/hound", sess, client, root)
	if !strings.Contains(resHound.Output, "Schnorr Bloodhound Equivocation Hunter") {
		t.Fatalf("unexpected /hound header: %s", resHound.Output)
	}
	if !strings.Contains(resHound.Output, "ACTIVE") || !strings.Contains(resHound.Output, "100% EXACT MATCH") {
		t.Fatalf("unexpected /hound result: %s", resHound.Output)
	}

	// 2. /net execution
	resNet := Execute("/net", sess, client, root)
	if !strings.Contains(resNet.Output, "Kirchhoff In-RAM Netting Engine") {
		t.Fatalf("unexpected /net header: %s", resNet.Output)
	}
	if !strings.Contains(resNet.Output, "Cycles Eliminated") || !strings.Contains(resNet.Output, "STRICTLY CONSERVED") {
		t.Fatalf("unexpected /net result: %s", resNet.Output)
	}
}

func TestSlashProvider(t *testing.T) {
	sess, client, root := setupTestSession(t)
	defer client.Close()

	res := Execute("/provider", sess, client, root)
	if !strings.Contains(res.Output, "Independent Provider Summary") {
		t.Fatalf("unexpected /provider status output: %s", res.Output)
	}

	resUsage := Execute("/provider exec", sess, client, root)
	if !strings.Contains(resUsage.Output, "Usage: /provider exec") {
		t.Fatalf("unexpected /provider exec usage: %s", resUsage.Output)
	}
}

func TestSlashCopy(t *testing.T) {
	previousCopy := copyToClipboard
	t.Cleanup(func() { copyToClipboard = previousCopy })
	var copied []string
	copyToClipboard = func(text string) error {
		copied = append(copied, text)
		return nil
	}
	sess, client, root := setupTestSession(t)
	defer client.Close()

	// 1. Invalid arguments fail-fast (even when memory is empty)
	resInvalidEmpty := Execute("/copy invalid_arg", sess, client, root)
	if !strings.Contains(resInvalidEmpty.Output, "Invalid argument 'invalid_arg'") {
		t.Fatalf("expected invalid argument error, got: %s", resInvalidEmpty.Output)
	}

	resTooMany := Execute("/copy last extra_arg", sess, client, root)
	if !strings.Contains(resTooMany.Output, "Too many arguments") {
		t.Fatalf("expected too many arguments error, got: %s", resTooMany.Output)
	}

	// 2. Empty conversation test
	resEmpty := Execute("/copy", sess, client, root)
	if !strings.Contains(resEmpty.Output, "No conversation messages") {
		t.Fatalf("expected no conversation message, got: %s", resEmpty.Output)
	}

	// 3. Add turns to memory
	if err := sess.Memory.AddTurn("What is CSLS?", "CSLS is a sovereign clearing protocol."); err != nil {
		t.Fatal(err)
	}

	// 4. Default /copy (implicit last)
	resDefault := Execute("/copy", sess, client, root)
	if !strings.Contains(resDefault.Output, "Last response copied to clipboard") {
		t.Fatalf("unexpected /copy default output: %s", resDefault.Output)
	}

	// 5. Explicit /copy last and case-insensitivity
	resLast := Execute("/copy last", sess, client, root)
	if !strings.Contains(resLast.Output, "Last response copied to clipboard") {
		t.Fatalf("unexpected /copy last output: %s", resLast.Output)
	}

	resLastUpper := Execute("/copy LAST", sess, client, root)
	if !strings.Contains(resLastUpper.Output, "Last response copied to clipboard") {
		t.Fatalf("unexpected /copy LAST output: %s", resLastUpper.Output)
	}

	// 6. Copy all and case-insensitivity
	resAll := Execute("/copy all", sess, client, root)
	if !strings.Contains(resAll.Output, "Full conversation") || !strings.Contains(resAll.Output, "copied to clipboard") {
		t.Fatalf("unexpected /copy all output: %s", resAll.Output)
	}

	resAllUpper := Execute("/copy ALL", sess, client, root)
	if !strings.Contains(resAllUpper.Output, "Full conversation") || !strings.Contains(resAllUpper.Output, "copied to clipboard") {
		t.Fatalf("unexpected /copy ALL output: %s", resAllUpper.Output)
	}

	// 7. Invalid argument with active conversation
	resInvalidActive := Execute("/copy unknown", sess, client, root)
	if !strings.Contains(resInvalidActive.Output, "Invalid argument 'unknown'") {
		t.Fatalf("expected invalid argument error, got: %s", resInvalidActive.Output)
	}

	// 8. Edge case: user message only, empty assistant response
	if _, err := sess.Memory.Clear(); err != nil {
		t.Fatal(err)
	}
	if err := sess.Memory.AddTurn("Only user query", ""); err != nil {
		t.Fatal(err)
	}
	resUserOnly := Execute("/copy last", sess, client, root)
	if !strings.Contains(resUserOnly.Output, "Last response copied to clipboard") {
		t.Fatalf("unexpected /copy with user-only turn: %s", resUserOnly.Output)
	}

	// 9. Edge case: empty message contents
	if _, err := sess.Memory.Clear(); err != nil {
		t.Fatal(err)
	}
	if err := sess.Memory.AddTurn("", ""); err != nil {
		t.Fatal(err)
	}
	resNothing := Execute("/copy", sess, client, root)
	if !strings.Contains(resNothing.Output, "Nothing to copy.") {
		t.Fatalf("expected 'Nothing to copy.', got: %s", resNothing.Output)
	}
	want := []string{
		"CSLS is a sovereign clearing protocol.",
		"CSLS is a sovereign clearing protocol.",
		"CSLS is a sovereign clearing protocol.",
		"USER:\nWhat is CSLS?\n\nASSISTANT:\nCSLS is a sovereign clearing protocol.",
		"USER:\nWhat is CSLS?\n\nASSISTANT:\nCSLS is a sovereign clearing protocol.",
		"Only user query",
	}
	if len(copied) != len(want) {
		t.Fatalf("clipboard calls = %d, want %d: %q", len(copied), len(want), copied)
	}
	for i := range want {
		if copied[i] != want[i] {
			t.Errorf("clipboard call %d = %q, want %q", i, copied[i], want[i])
		}
	}
}
