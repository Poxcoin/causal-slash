// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include "schnorr_bloodhound.h"

static void test_bloodhound_keccak256_vector(void) {
    printf("[BLOODHOUND TEST 1] Verifying Keccak-256 standard Ethereum test vector...\n");
    uint8_t out[32];
    csls_keccak256((const uint8_t *)"", 0, out);

    // Known Ethereum keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    static const uint8_t EXPECTED_EMPTY_KECCAK[32] = {
        0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
        0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
        0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
        0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70
    };
    assert(memcmp(out, EXPECTED_EMPTY_KECCAK, 32) == 0);
    printf("  RESULT: Keccak-256 matches Ethereum specification exactly!\n");
}

static void test_bloodhound_equivocation_hunting(void) {
    printf("[BLOODHOUND TEST 2] Simulating Schnorr Bloodhound MEV Searcher Stream...\n");

    uint8_t hunter_addr[20] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                               0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    bloodhound_ctx_t *hound = bloodhound_new(hunter_addr);
    assert(hound != NULL);

    // Setup Rogue Agent
    uint8_t rogue_sk[32];
    memset(rogue_sk, 0x69, 32);
    csls_agent_ctx_t rogue;
    assert(csls_agent_init(&rogue, rogue_sk, NULL) == 0);

    // Setup honest vendor
    uint8_t vendor1_pk[33];
    memset(vendor1_pk, 0x02, 33);
    uint8_t vendor2_pk[33];
    memset(vendor2_pk, 0x03, 33);

    // Stream 1000 honest cheques to vendor 1
    csls_cheque_pkt_t pkt;
    for (uint32_t i = 1; i <= 500; i++) {
        assert(csls_agent_sign_cheque(&rogue, vendor1_pk, 1000, &pkt) == 0);
        bloodhound_exploit_payload_t payload;
        int caught = bloodhound_inspect_packet(hound, &pkt, &payload);
        assert(caught == 0); // No equivocation yet
    }
    assert(hound->packets_inspected == 500);

    // Save cheque at height 500 for collision attack
    csls_cheque_pkt_t legit_h500 = pkt;
    assert(legit_h500.height == 500);

    // Rogue agent forks: signs conflicting cheque at SAME height 500 to vendor 2 with different amount
    csls_cheque_pkt_t double_spend_h500;
    rogue.height = 500; // Reset height to forge double-spend
    assert(csls_agent_sign_cheque(&rogue, vendor2_pk, 5000, &double_spend_h500) == 0);
    assert(double_spend_h500.height == 500);

    // Bloodhound sniffs the double-spend cheque
    bloodhound_exploit_payload_t payload;
    memset(&payload, 0, sizeof(payload));
    int caught = bloodhound_inspect_packet(hound, &double_spend_h500, &payload);

    assert(caught == 1); // Equivocation detected!
    assert(hound->equivocations_captured == 1);
    assert(payload.collision_height == 500);

    // Extracted secret key MUST match rogue secret key exactly
    assert(memcmp(payload.extracted_sk, rogue_sk, 32) == 0);

    // Verify commit hash is generated
    uint8_t zero_hash[32] = {0};
    assert(memcmp(payload.commit_hash, zero_hash, 32) != 0);

    printf("  [PASS] Double-spend intercepted at height 500!\n");
    printf("  [PASS] Rogue private key extracted algebraically: MATCH!\n");
    printf("  [PASS] Commit-reveal transaction payload ready for Base L2 RPC!\n");
    printf("  [BOUNTY] 15%% Finder Bounty secured for Bloodhound searcher!\n");

    csls_agent_destroy(&rogue);
    bloodhound_free(hound);
}

int main(void) {
    printf("======================================================================\n");
    printf("[SCHNORR BLOODHOUND] Autonomous MEV Bounty Hunter Test Suite\n");
    printf("======================================================================\n");

    assert(csls_crypto_global_init() == 0);

    test_bloodhound_keccak256_vector();
    test_bloodhound_equivocation_hunting();

    csls_crypto_global_cleanup();

    printf("======================================================================\n");
    printf("[VERDICT] All Schnorr Bloodhound Tests Successfully Passed!\n");
    printf("======================================================================\n");
    return 0;
}
