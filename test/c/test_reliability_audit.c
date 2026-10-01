// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include "causal_daemon.h"

// -----------------------------------------------------------------------------
// TEST 1: False-Positive Equivocation Trigger with Corrupt Key Extraction
// -----------------------------------------------------------------------------
static void test_audit_equivocation_false_positive_corrupt_key(void) {
    printf("[AUDIT TEST 1] Verifying Ignored Return Code & Corrupt Key Extraction in Vendor Core...\n");

    uint8_t agent_sk[32];
    memset(agent_sk, 0x11, 32);
    csls_agent_ctx_t agent;
    assert(csls_agent_init(&agent, agent_sk, NULL) == 0);

    uint8_t vendor_sk[32];
    memset(vendor_sk, 0x22, 32);
    csls_vendor_ctx_t *vendor = csls_vendor_new(vendor_sk, 10000000ULL);
    assert(vendor != NULL);

    csls_cheque_pkt_t c_legit;
    csls_channel_t *chan1 = csls_channel_get_or_create(&agent.channels, vendor->pk);
    assert(chan1 != NULL);
    chan1->height = 100;
    assert(csls_agent_sign_cheque(&agent, vendor->pk, 50000, &c_legit) == 0);

    csls_fraud_pkt_t fraud;
    memset(&fraud, 0, sizeof(fraud));
    assert(csls_vendor_process_cheque(vendor, &c_legit, &fraud) == 0);

    // Attacker sends forged packet at height 100 with random challenge and random signature
    csls_cheque_pkt_t c_forged = c_legit;
    memset(c_forged.challenge_e, 0xAA, 32); // Forged challenge scalar
    memset(c_forged.sig_s, 0xBB, 32);       // Random junk signature

    // Direct extraction call returns -5 (key derivation mismatch)
    uint8_t test_extracted[32];
    int extract_res = csls_extract_private_key(&c_legit, &c_forged, test_extracted);
    assert(extract_res == -5); // Confirms extraction fails mathematically

    // Core fix: vendor process_cheque validates extraction and returns -23 (FORGED_CHALLENGE_HASH)
    int vendor_res = csls_vendor_process_cheque(vendor, &c_forged, &fraud);
    assert(vendor_res == -23); // Correctly rejects forged packet with invalid extraction

    printf("  FIX VERIFIED: Vendor validates key extraction and rejects forged packet with code -23.\n");
    printf("  PROTECTION: Prevents emitting unverified keys on-chain and saves finder commit bonds.\n");

    csls_agent_destroy(&agent);
    csls_vendor_free(vendor);
}

// -----------------------------------------------------------------------------
// TEST 2: Concurrency Out-Of-Order Stream Desynchronization
// -----------------------------------------------------------------------------
static void test_audit_concurrency_out_of_order_stream_desync(void) {
    printf("[AUDIT TEST 2] Verifying Concurrency Out-Of-Order Packet Rejection...\n");

    uint8_t agent_sk[32];
    memset(agent_sk, 0x33, 32);
    csls_agent_ctx_t agent;
    assert(csls_agent_init(&agent, agent_sk, NULL) == 0);

    uint8_t vendor_sk[32];
    memset(vendor_sk, 0x44, 32);
    csls_vendor_ctx_t *vendor = csls_vendor_new(vendor_sk, 10000000ULL);
    assert(vendor != NULL);

    csls_cheque_pkt_t pkt1, pkt2;
    assert(csls_agent_sign_cheque(&agent, vendor->pk, 1000, &pkt1) == 0);
    assert(csls_agent_sign_cheque(&agent, vendor->pk, 1000, &pkt2) == 0);

    assert(pkt1.height == 1 && pkt1.cumulative_amt == 1000);
    assert(pkt2.height == 2 && pkt2.cumulative_amt == 2000);

    // In concurrent multithreaded network execution, pkt2 arrives before pkt1
    csls_fraud_pkt_t fraud;
    assert(csls_vendor_process_cheque(vendor, &pkt2, &fraud) == 0);
    csls_channel_t *vchan2 = csls_channel_get_or_create(&vendor->channels, agent.pk);
    assert(vchan2 != NULL);
    assert(vchan2->height == 2);
    assert(vchan2->accumulated_amount == 2000);

    // When pkt1 arrives delayed, it is permanently rejected
    int res1 = csls_vendor_process_cheque(vendor, &pkt1, &fraud);
    assert(res1 == -11); // DECREASING_AMOUNT_ATTACK

    printf("  FINDING: Delayed packet h=1 rejected with code -11 after h=2 processed.\n");
    printf("  IMPACT: Multithreaded emission requires strict sequential delivery pipeline.\n");

    csls_agent_destroy(&agent);
    csls_vendor_free(vendor);
}

// -----------------------------------------------------------------------------
// TEST 3: Ring Buffer 64k Wrap-Around Missed Equivocation
// -----------------------------------------------------------------------------
static void test_audit_ring_buffer_wrap_missed_equivocation(void) {
    printf("[AUDIT TEST 3] Verifying Missed Equivocation on Ring Buffer 64k Wrap-Around...\n");

    uint8_t agent_sk[32];
    memset(agent_sk, 0x55, 32);
    csls_agent_ctx_t agent;
    assert(csls_agent_init(&agent, agent_sk, NULL) == 0);

    uint8_t vendor_sk[32];
    memset(vendor_sk, 0x66, 32);
    csls_vendor_ctx_t *vendor = csls_vendor_new(vendor_sk, 200000000ULL);
    assert(vendor != NULL);

    csls_fraud_pkt_t fraud;

    // Cheque 1 at height 1
    csls_cheque_pkt_t c_h1;
    csls_channel_t *chan3 = csls_channel_get_or_create(&agent.channels, vendor->pk);
    assert(chan3 != NULL);
    chan3->height = 1;
    chan3->cumulative_sent = 0;
    assert(csls_agent_sign_cheque(&agent, vendor->pk, 1000, &c_h1) == 0);
    assert(csls_vendor_process_cheque(vendor, &c_h1, &fraud) == 0);

    // Advance height to 65537 (same ring slot: 65537 & 65535 = 1)
    csls_cheque_pkt_t c_h65537;
    chan3->height = 65537;
    chan3->cumulative_sent = 1000;
    assert(csls_agent_sign_cheque(&agent, vendor->pk, 1000, &c_h65537) == 0);
    assert(csls_vendor_process_cheque(vendor, &c_h65537, &fraud) == 0);

    // Slot 1 is now overwritten with height 65537
    uint32_t slot = (uint32_t)(1 & CSLS_HISTORY_MASK);
    assert(vendor->history[slot].height == 65537);

    // Create a conflicting double-spend cheque at height 1
    csls_cheque_pkt_t c_conflict;
    chan3->height = 1;
    chan3->cumulative_sent = 5000;
    assert(csls_agent_sign_cheque(&agent, vendor->pk, 500, &c_conflict) == 0);

    // When submitted, vendor evaluates: entry->height (65537) == pkt->height (1) => FALSE
    // Followed by pkt->height (1) <= last_height (65537) => returns -22
    int res = csls_vendor_process_cheque(vendor, &c_conflict, &fraud);
    assert(res == -22); // OUT_OF_ORDER_OR_OLD_REPLAY, NOT -20!

    printf("  FINDING: Equivocation at height 1 missed (returned code -22 instead of -20).\n");
    printf("  IMPACT: Offender evades local key extraction if stream advances > 64k entries.\n");

    csls_agent_destroy(&agent);
    csls_vendor_free(vendor);
}

// -----------------------------------------------------------------------------
// TEST 4: Zero-Value Cheque Height Inflation
// -----------------------------------------------------------------------------
static void test_audit_zero_value_cheque_height_inflation(void) {
    printf("[AUDIT TEST 4] Verifying Zero-Value Cheque Height Progression...\n");

    uint8_t agent_sk[32];
    memset(agent_sk, 0x77, 32);
    csls_agent_ctx_t agent;
    assert(csls_agent_init(&agent, agent_sk, NULL) == 0);

    uint8_t vendor_sk[32];
    memset(vendor_sk, 0x88, 32);
    csls_vendor_ctx_t *vendor = csls_vendor_new(vendor_sk, 10000000ULL);
    assert(vendor != NULL);

    csls_cheque_pkt_t pkt1, pkt2;
    assert(csls_agent_sign_cheque(&agent, vendor->pk, 0, &pkt1) == 0);
    assert(csls_agent_sign_cheque(&agent, vendor->pk, 0, &pkt2) == 0);

    assert(pkt1.cumulative_amt == 0);
    assert(pkt2.cumulative_amt == 0);
    assert(pkt2.height == pkt1.height + 1);

    csls_fraud_pkt_t fraud;
    assert(csls_vendor_process_cheque(vendor, &pkt1, &fraud) == 0);
    assert(csls_vendor_process_cheque(vendor, &pkt2, &fraud) == 0);

    printf("  FINDING: Zero-delta cheques monotonically advance height and consume buffer slots.\n");

    csls_agent_destroy(&agent);
    csls_vendor_free(vendor);
}

int main(void) {
    printf("======================================================================\n");
    printf("[QA & RELIABILITY ARCHITECT] C Core Protocol Edge-Case Audit Suite\n");
    printf("======================================================================\n");

    int cr = csls_crypto_global_init();
    assert(cr == 0);

    test_audit_equivocation_false_positive_corrupt_key();
    test_audit_concurrency_out_of_order_stream_desync();
    test_audit_ring_buffer_wrap_missed_equivocation();
    test_audit_zero_value_cheque_height_inflation();

    csls_crypto_global_cleanup();

    printf("======================================================================\n");
    printf("[VERDICT] All 4 Protocol Edge-Case Invariant Audits Successfully Executed!\n");
    printf("======================================================================\n");
    return 0;
}
