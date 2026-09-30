// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "schnorr_bloodhound.h"

// -----------------------------------------------------------------------------
// Standard Ethereum Keccak-256 Implementation (RFC 3.1.2 with 0x01 delimiter)
// -----------------------------------------------------------------------------
static const uint64_t KECCAKF_RNDC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int KECCAKF_ROTC[24] = {
    1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
    27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
};

static const int KECCAKF_PILN[24] = {
    10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
};

#define ROL64(a, offset) ((offset != 0) ? (((a) << (offset)) ^ ((a) >> (64 - (offset)))) : (a))

static void keccakf(uint64_t st[25]) {
    uint64_t bc[5], t;
    for (int round = 0; round < 24; round++) {
        // Theta
        for (int i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

        for (int i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROL64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5)
                st[j + i] ^= t;
        }

        // Rho and Pi
        t = st[1];
        for (int i = 0; i < 24; i++) {
            int j = KECCAKF_PILN[i];
            bc[0] = st[j];
            st[j] = ROL64(t, KECCAKF_ROTC[i]);
            t = bc[0];
        }

        // Chi
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++)
                bc[i] = st[j + i];
            for (int i = 0; i < 5; i++)
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }

        // Iota
        st[0] ^= KECCAKF_RNDC[round];
    }
}

void csls_keccak256(const uint8_t *data, size_t len, uint8_t *out_hash_32) {
    uint64_t st[25];
    memset(st, 0, sizeof(st));

    size_t rate = 136; // 1088 bits for Keccak-256

    while (len >= rate) {
        for (size_t i = 0; i < rate / 8; i++) {
            uint64_t word = 0;
            for (int b = 0; b < 8; b++) {
                word |= ((uint64_t)data[i * 8 + b]) << (b * 8);
            }
            st[i] ^= word;
        }
        keccakf(st);
        data += rate;
        len -= rate;
    }

    uint8_t buffer[136];
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, data, len);
    buffer[len] = 0x01; // Ethereum Keccak-256 domain padding delimiter
    buffer[rate - 1] |= 0x80;

    for (size_t i = 0; i < rate / 8; i++) {
        uint64_t word = 0;
        for (int b = 0; b < 8; b++) {
            word |= ((uint64_t)buffer[i * 8 + b]) << (b * 8);
        }
        st[i] ^= word;
    }
    keccakf(st);

    for (int i = 0; i < 4; i++) {
        for (int b = 0; b < 8; b++) {
            out_hash_32[i * 8 + b] = (uint8_t)((st[i] >> (b * 8)) & 0xFF);
        }
    }
}

// -----------------------------------------------------------------------------
// Schnorr Bloodhound MEV Searcher Engine
// -----------------------------------------------------------------------------

bloodhound_ctx_t *bloodhound_new(const uint8_t *hunter_addr_20) {
    bloodhound_ctx_t *ctx = (bloodhound_ctx_t *)calloc(1, sizeof(bloodhound_ctx_t));
    if (!ctx) return NULL;
    bloodhound_init(ctx, hunter_addr_20);
    return ctx;
}

void bloodhound_free(bloodhound_ctx_t *ctx) {
    if (ctx) {
        free(ctx);
    }
}

void bloodhound_init(bloodhound_ctx_t *ctx, const uint8_t *hunter_addr_20) {
    if (!ctx) return;
    memset(ctx, 0, sizeof(bloodhound_ctx_t));
    if (hunter_addr_20) {
        memcpy(ctx->hunter_address, hunter_addr_20, 20);
    }
}

int bloodhound_inspect_packet(bloodhound_ctx_t *ctx, const csls_cheque_pkt_t *pkt, 
                              bloodhound_exploit_payload_t *out_payload) {
    if (!ctx || !pkt) return -1;
    if (pkt->magic != CSLS_MAGIC || pkt->type != CSLS_PKT_CHEQUE) return -1;

    ctx->packets_inspected++;

    // Compute fast slot index from height and agent public key prefix
    uint32_t agent_hash = 0;
    memcpy(&agent_hash, pkt->agent_pk + 1, 4);
    uint32_t slot = (uint32_t)((pkt->height ^ agent_hash) & BLOODHOUND_LRU_MASK);
    bloodhound_slot_t *entry = &ctx->table[slot];

    // Check for height collision from same agent
    if (entry->occupied && entry->height == pkt->height && memcmp(entry->agent_pk, pkt->agent_pk, 33) == 0) {
        // If challenge differs, equivocation confirmed!
        if (memcmp(entry->challenge_e, pkt->challenge_e, 32) != 0) {
            csls_cheque_pkt_t c1;
            c1.magic = CSLS_MAGIC;
            c1.type = CSLS_PKT_CHEQUE;
            memcpy(c1.agent_pk, entry->agent_pk, 33);
            memset(c1.vendor_pk, 0, 33);
            c1.height = entry->height;
            c1.cumulative_amt = entry->amount;
            memcpy(c1.challenge_e, entry->challenge_e, 32);
            memcpy(c1.sig_s, entry->sig_s, 32);

            uint8_t extracted_sk[32];
            int rc = csls_extract_private_key(&c1, pkt, extracted_sk);
            if (rc == 0) {
                ctx->equivocations_captured++;

                if (out_payload) {
                    memcpy(out_payload->extracted_sk, extracted_sk, 32);
                    out_payload->collision_height = pkt->height;

                    // Generate deterministic salt for commit: hash(extracted_sk || hunter_addr)
                    uint8_t salt_seed[52];
                    memcpy(salt_seed, extracted_sk, 32);
                    memcpy(salt_seed + 32, ctx->hunter_address, 20);
                    csls_keccak256(salt_seed, sizeof(salt_seed), out_payload->commit_salt);

                    // Compute commitHash = keccak256(extracted_sk || hunter_address || salt)
                    // abi.encodePacked(uint256 extractedSk, address committer, bytes32 salt) => 32 + 20 + 32 = 84 bytes
                    uint8_t commit_preimage[84];
                    memcpy(commit_preimage, extracted_sk, 32);
                    memcpy(commit_preimage + 32, ctx->hunter_address, 20);
                    memcpy(commit_preimage + 52, out_payload->commit_salt, 32);
                    csls_keccak256(commit_preimage, sizeof(commit_preimage), out_payload->commit_hash);
                }
                return 1; // EQUIVOCATION_CAPTURED (15% bounty ready!)
            }
        }
        return 0; // Same challenge replay
    }

    // Record slot
    memcpy(entry->agent_pk, pkt->agent_pk, 33);
    entry->height = pkt->height;
    entry->amount = pkt->cumulative_amt;
    memcpy(entry->challenge_e, pkt->challenge_e, 32);
    memcpy(entry->sig_s, pkt->sig_s, 32);
    entry->occupied = true;

    return 0;
}
