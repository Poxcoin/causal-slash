// SPDX-License-Identifier: Apache-2.0
#ifndef SCHNORR_BLOODHOUND_H
#define SCHNORR_BLOODHOUND_H

#include <stdint.h>
#include <stdbool.h>
#include "causal_daemon.h"

#define BLOODHOUND_LRU_SIZE 65536
#define BLOODHOUND_LRU_MASK (BLOODHOUND_LRU_SIZE - 1)

typedef struct {
    uint8_t agent_pk[33];
    uint64_t height;
    uint64_t amount;
    uint8_t challenge_e[32];
    uint8_t sig_s[32];
    bool occupied;
} bloodhound_slot_t;

typedef struct {
    uint8_t hunter_address[20];
    uint64_t packets_inspected;
    uint64_t equivocations_captured;
    // Process-private slot entropy (SipHash-style). Prevents a double-spending
    // agent from computing the table index of its own evidence and destroying
    // it with crafted eviction packets. MUST NOT be logged or exported.
    uint64_t slot_seed;
    bloodhound_slot_t table[BLOODHOUND_LRU_SIZE];
} bloodhound_ctx_t;

typedef struct {
    uint8_t extracted_sk[32];
    uint8_t commit_salt[32];
    uint8_t commit_hash[32];
    uint8_t target_agent[20];
    uint64_t collision_height;
} bloodhound_exploit_payload_t;

bloodhound_ctx_t *bloodhound_new(const uint8_t *hunter_addr_20);
void               bloodhound_free(bloodhound_ctx_t *ctx);
void bloodhound_init(bloodhound_ctx_t *ctx, const uint8_t *hunter_addr_20);
// Deterministic seeding for reproducible test vectors and offline replay.
// Production entry point bloodhound_init() draws slot_seed from the CSPRNG.
void bloodhound_init_seeded(bloodhound_ctx_t *ctx, const uint8_t *hunter_addr_20,
                            uint64_t seed);
int  bloodhound_inspect_packet(bloodhound_ctx_t *ctx, const csls_cheque_pkt_t *pkt, 
                               bloodhound_exploit_payload_t *out_payload);

void csls_keccak256(const uint8_t *data, size_t len, uint8_t *out_hash_32);

#endif // SCHNORR_BLOODHOUND_H
