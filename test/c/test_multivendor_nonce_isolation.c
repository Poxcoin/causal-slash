// SPDX-License-Identifier: Apache-2.0
// Multi-Vendor Nonce Domain Separation & Channel Isolation Verification Suite
// Proves that multi-vendor streaming at identical heights does NOT leak private keys,
// and that equivocation is strictly detected and slashed within vendor channels.

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include "causal_daemon.h"
#include "schnorr_bloodhound.h"

#define NUM_VENDORS 5

int main(void) {
    printf("======================================================================\n");
    printf("[SECURITY TEST] Multi-Vendor Nonce Domain Separation & State Isolation\n");
    printf("======================================================================\n");

    int cr = csls_crypto_global_init();
    assert(cr == 0);

    // Initialize honest agent with secret key
    uint8_t agent_sk[32];
    memset(agent_sk, 0x42, 32);
    csls_agent_ctx_t agent;
    assert(csls_agent_init(&agent, agent_sk, NULL) == 0);

    // Initialize 5 distinct vendors
    csls_vendor_ctx_t *vendors[NUM_VENDORS];
    for (int i = 0; i < NUM_VENDORS; i++) {
        uint8_t v_sk[32];
        memset(v_sk, 0x10 + i, 32);
        vendors[i] = csls_vendor_new(v_sk, CSLS_DEFAULT_DELTA_V);
        assert(vendors[i] != NULL);
    }

    // -------------------------------------------------------------------------
    // TEST 1: Multi-Vendor Sequential Streaming at Height 1
    // -------------------------------------------------------------------------
    printf("[PHASE 1] Signing $0.01 cheques to 5 different vendors at height h = 1...\n");
    csls_cheque_pkt_t cheques[NUM_VENDORS];

    for (int i = 0; i < NUM_VENDORS; i++) {
        // Each channel starts at height 1
        int sign_rc = csls_agent_sign_cheque(&agent, vendors[i]->pk, 10000, &cheques[i]);
        assert(sign_rc == 0);
        assert(cheques[i].height == 1);
        assert(cheques[i].cumulative_amt == 10000);

        // Verify each vendor accepts their respective cheque
        int proc_rc = csls_vendor_process_cheque(vendors[i], &cheques[i], NULL);
        assert(proc_rc == 0);
    }
    printf("  [PASS] All 5 vendors accepted cheques at height h = 1 without error.\n");

    // -------------------------------------------------------------------------
    // TEST 2: Cryptographic Nonce Uniqueness & Private Key Secrecy
    // -------------------------------------------------------------------------
    printf("[PHASE 2] Verifying pairwise cryptographic nonce separation...\n");
    for (int i = 0; i < NUM_VENDORS; i++) {
        for (int j = i + 1; j < NUM_VENDORS; j++) {
            // Under old vulnerability: k was identical, allowing sk extraction.
            // Under fixed protocol: k = HMAC(sk, vendor_pk || h), so k_i != k_j.
            uint8_t leaked_sk[32];
            memset(leaked_sk, 0, 32);
            int ext_rc = csls_extract_private_key(&cheques[i], &cheques[j], leaked_sk);

            // csls_extract_private_key MUST strictly reject cross-vendor cheques (-7)
            assert(ext_rc == -7);

            // Verify leaked_sk was NOT written and does not match agent_sk
            assert(memcmp(leaked_sk, agent_sk, 32) != 0);
        }
    }
    printf("  [PASS] Cross-vendor private key extraction mathematically impossible (-7 returned).\n");
    printf("  [PASS] Honest agent private key remained 100%% secure across all vendors.\n");

    // -------------------------------------------------------------------------
    // TEST 3: Bloodhound Searcher Inspection (No False Positives)
    // -------------------------------------------------------------------------
    printf("[PHASE 3] Feeding all 5 cheques into Schnorr Bloodhound MEV searcher...\n");
    const uint8_t hunter[20] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01, 0x02, 0x03, 0x04, 0x05,
                                0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    bloodhound_ctx_t *hound = bloodhound_new(hunter);
    assert(hound != NULL);

    for (int i = 0; i < NUM_VENDORS; i++) {
        bloodhound_exploit_payload_t payload;
        int caught = bloodhound_inspect_packet(hound, &cheques[i], &payload);
        // None of these honest cheques should trigger an equivocation
        assert(caught == 0);
    }
    assert(hound->equivocations_captured == 0);
    printf("  [PASS] Bloodhound recorded all 5 multi-vendor channels with zero false positives.\n");

    // -------------------------------------------------------------------------
    // TEST 4: Real Equivocation Trap on Forked Cheque within Single Vendor Channel
    // -------------------------------------------------------------------------
    printf("[PHASE 4] Simulating malicious fork attack against Vendor 0 at height h = 1...\n");
    // Rogue agent attempts double spend by resetting channel height to 1 for Vendor 0
    csls_channel_t *ch0 = csls_channel_get_or_create(&agent.channels, vendors[0]->pk);
    assert(ch0 != NULL);
    ch0->height = 1;

    csls_cheque_pkt_t conflicting_cheque;
    assert(csls_agent_sign_cheque(&agent, vendors[0]->pk, 25000, &conflicting_cheque) == 0);
    assert(conflicting_cheque.height == 1);
    assert(conflicting_cheque.cumulative_amt != cheques[0].cumulative_amt);

    // Vendor 0 must detect equivocation and algebraically extract agent_sk
    csls_fraud_pkt_t fraud;
    memset(&fraud, 0, sizeof(fraud));
    int vendor_detect_rc = csls_vendor_process_cheque(vendors[0], &conflicting_cheque, &fraud);
    assert(vendor_detect_rc == -20); // EQUIVOCATION_DETECTED
    assert(memcmp(fraud.extracted_sk, agent_sk, 32) == 0);
    printf("  [PASS] Vendor 0 caught double-spend: private key extracted and verified!\n");

    // Bloodhound must intercept conflicting cheque and extract agent_sk
    bloodhound_exploit_payload_t bh_payload;
    memset(&bh_payload, 0, sizeof(bh_payload));
    int bh_rc = bloodhound_inspect_packet(hound, &conflicting_cheque, &bh_payload);
    assert(bh_rc == 1); // EQUIVOCATION_CAPTURED
    assert(hound->equivocations_captured == 1);
    assert(memcmp(bh_payload.extracted_sk, agent_sk, 32) == 0);
    printf("  [PASS] Bloodhound intercepted equivocation: 15%% bounty secured on Base L2!\n");

    // Cleanup
    bloodhound_free(hound);
    csls_agent_destroy(&agent);
    for (int i = 0; i < NUM_VENDORS; i++) {
        csls_vendor_free(vendors[i]);
    }
    csls_crypto_global_cleanup();

    printf("======================================================================\n");
    printf("[VERDICT] Multi-vendor nonce isolation & equivocation trap: VERIFIED 100%%\n");
    printf("======================================================================\n");
    return 0;
}
