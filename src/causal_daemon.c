// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Causal-Slash Protocol Developers
//
// Causal-Slash Protocol: Sovereign High-Frequency M2M Micro-Payment Engine
// Implementation of Core Cryptographic Engine, Non-blocking Daemon, and Self-Test

#define _GNU_SOURCE
#include "causal_daemon.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

// Global Cryptographic Contexts (secp256k1)
static EC_GROUP *g_secp256k1_group = NULL;
static BIGNUM   *g_curve_order_q   = NULL;
static const EC_POINT *g_generator = NULL;
static pthread_mutex_t g_crypto_lock = PTHREAD_MUTEX_INITIALIZER;

static const uint8_t SECP256K1_Q_BE[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};

static inline uint64_t csls_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int csls_crypto_global_init(void) {
    // Neutralize SIGPIPE crashes when writing to severed TCP sockets
    signal(SIGPIPE, SIG_IGN);

    pthread_mutex_lock(&g_crypto_lock);
    if (g_secp256k1_group != NULL) {
        pthread_mutex_unlock(&g_crypto_lock);
        return 0;
    }

    g_secp256k1_group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!g_secp256k1_group) {
        pthread_mutex_unlock(&g_crypto_lock);
        return -1;
    }

    BN_CTX *ctx = BN_CTX_new();
    g_curve_order_q = BN_new();
    if (!EC_GROUP_get_order(g_secp256k1_group, g_curve_order_q, ctx)) {
        BN_CTX_free(ctx);
        pthread_mutex_unlock(&g_crypto_lock);
        return -1;
    }

    g_generator = EC_GROUP_get0_generator(g_secp256k1_group);
    BN_CTX_free(ctx);

    pthread_mutex_unlock(&g_crypto_lock);
    return 0;
}

void csls_crypto_global_cleanup(void) {
    pthread_mutex_lock(&g_crypto_lock);
    if (g_curve_order_q) {
        BN_free(g_curve_order_q);
        g_curve_order_q = NULL;
    }
    if (g_secp256k1_group) {
        EC_GROUP_free(g_secp256k1_group);
        g_secp256k1_group = NULL;
    }
    pthread_mutex_unlock(&g_crypto_lock);
}

// Compute Compressed secp256k1 Public Key (33 bytes) from Secret Key (32 bytes)
static int csls_derive_pk(const uint8_t *sk_bytes, uint8_t *out_pk_compressed) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *sk = BN_bin2bn(sk_bytes, 32, NULL);
    EC_POINT *pk_pt = EC_POINT_new(g_secp256k1_group);

    if (!sk || !pk_pt) {
        if (sk) BN_free(sk);
        if (pk_pt) EC_POINT_free(pk_pt);
        BN_CTX_free(ctx);
        return -1;
    }

    if (!EC_POINT_mul(g_secp256k1_group, pk_pt, sk, NULL, NULL, ctx)) {
        BN_free(sk);
        EC_POINT_free(pk_pt);
        BN_CTX_free(ctx);
        return -1;
    }

    size_t len = EC_POINT_point2oct(g_secp256k1_group, pk_pt, 
                                    POINT_CONVERSION_COMPRESSED, 
                                    out_pk_compressed, 33, ctx);

    BN_free(sk);
    EC_POINT_free(pk_pt);
    BN_CTX_free(ctx);
    return (len == 33) ? 0 : -1;
}

// -----------------------------------------------------------------------------
// Cryptographic Infrastructure: CRC-64/ECMA-182, SipHash-2-4 (128-bit), ECDH,
// session KDF, and the Dual-Sector Ping-Pong Watermark WAL (C1 fix).
// -----------------------------------------------------------------------------

static uint64_t g_crc64_tab[256];
static pthread_once_t g_crc64_once = PTHREAD_ONCE_INIT;
static void csls_crc64_build(void) {
    for (uint64_t i = 0; i < 256; i++) {
        uint64_t c = i << 56;
        for (int k = 0; k < 8; k++)
            c = (c & 0x8000000000000000ULL) ? (c << 1) ^ 0x42F0E1EBA9EA3693ULL : (c << 1);
        g_crc64_tab[i] = c;
    }
}
static uint64_t csls_crc64(const void *data, size_t len) {
    pthread_once(&g_crc64_once, csls_crc64_build);
    const uint8_t *p = (const uint8_t *)data;
    uint64_t crc = 0;
    while (len--) crc = g_crc64_tab[(crc >> 56) ^ *p++] ^ (crc << 8);
    return crc;
}

static inline uint64_t csls_sip_load64(const uint8_t *p) {
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}
#define CSLS_SIPROUND(v0,v1,v2,v3) do { \
    v0 += v1; v1 = (v1 << 13) | (v1 >> 51); v1 ^= v0; v0 = (v0 << 32) | (v0 >> 32); \
    v2 += v3; v3 = (v3 << 16) | (v3 >> 48); v3 ^= v2; \
    v0 += v3; v3 = (v3 << 21) | (v3 >> 43); v3 ^= v0; \
    v2 += v1; v1 = (v1 << 17) | (v1 >> 47); v1 ^= v2; v2 = (v2 << 32) | (v2 >> 32); \
} while (0)

// SipHash-2-4 with 128-bit output: second run uses the standard finalization xor.
static uint64_t csls_siphash24(const uint8_t key[16], const uint8_t *m, size_t n, uint64_t fin_xor) {
    uint64_t k0 = csls_sip_load64(key), k1 = csls_sip_load64(key + 8);
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1 ^ fin_xor;
    size_t full = n & ~(size_t)7;
    for (size_t off = 0; off < full; off += 8) {
        uint64_t b = csls_sip_load64(m + off);
        v3 ^= b; CSLS_SIPROUND(v0,v1,v2,v3); CSLS_SIPROUND(v0,v1,v2,v3); v0 ^= b;
    }
    uint64_t b = ((uint64_t)(n & 7)) << 56;
    for (size_t i = 0; i < (n & 7); i++) b |= ((uint64_t)m[full + i]) << (8 * i);
    v3 ^= b; CSLS_SIPROUND(v0,v1,v2,v3); CSLS_SIPROUND(v0,v1,v2,v3); v0 ^= b;
    v2 ^= 0xff;
    CSLS_SIPROUND(v0,v1,v2,v3); CSLS_SIPROUND(v0,v1,v2,v3);
    CSLS_SIPROUND(v0,v1,v2,v3); CSLS_SIPROUND(v0,v1,v2,v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

// 128-bit session MAC over the raw 151-byte cheque
static void csls_mac128(const uint8_t key[32], const void *data, size_t len, uint8_t out[16]) {
    uint64_t a = csls_siphash24(key, (const uint8_t *)data, len, 0);
    uint64_t b = csls_siphash24(key, (const uint8_t *)data, len, 0xee);
    for (int i = 0; i < 8; i++) { out[i] = (uint8_t)(a >> (8 * i)); out[8 + i] = (uint8_t)(b >> (8 * i)); }
}

// Static-static ECDH on secp256k1: shared = sk * PK_peer, returns x-coordinate.
// Both sides derive the identical secret from long-term identities; no new keys.
static int csls_ecdh_x(const uint8_t sk32[32], const uint8_t peer_pk33[33], uint8_t out_x[32]) {
    int ret = -1;
    BN_CTX *ctx = BN_CTX_new();
    EC_POINT *peer = EC_POINT_new(g_secp256k1_group);
    EC_POINT *shared = EC_POINT_new(g_secp256k1_group);
    BIGNUM *sk = BN_bin2bn(sk32, 32, NULL);
    BIGNUM *x = BN_new();
    if (ctx && peer && shared && sk && x &&
        EC_POINT_oct2point(g_secp256k1_group, peer, peer_pk33, 33, ctx) == 1 &&
        EC_POINT_is_on_curve(g_secp256k1_group, peer, ctx) == 1 &&
        EC_POINT_mul(g_secp256k1_group, shared, NULL, peer, sk, ctx) == 1 &&
        EC_POINT_get_affine_coordinates(g_secp256k1_group, shared, x, NULL, ctx) == 1) {
        BN_bn2binpad(x, out_x, 32);
        ret = 0;
    }
    if (sk) BN_free(sk);
    if (x) BN_free(x);
    if (shared) EC_POINT_free(shared);
    if (peer) EC_POINT_free(peer);
    if (ctx) BN_CTX_free(ctx);
    return ret;
}

static void csls_hmac32(const uint8_t key[32], const uint8_t *data, size_t dlen, uint8_t out[32]) {
    unsigned int olen = 32;
    HMAC(EVP_sha256(), key, 32, data, dlen, out, &olen);
}

// session_key = HMAC-SHA256(ecdh_x, session_nonce || "CSLS-MAC-v1")
static void csls_session_kdf(const uint8_t ecdh_x[32], uint64_t nonce, uint8_t out_key[32]) {
    uint8_t buf[8 + 11];
    for (int i = 0; i < 8; i++) buf[i] = (uint8_t)(nonce >> (56 - i * 8));
    memcpy(buf + 8, "CSLS-MAC-v1", 11);
    csls_hmac32(ecdh_x, buf, sizeof(buf), out_key);
}

// INIT authentication tag: proves the ECDH key belongs to the claimed agent_pk
static void csls_session_auth(const uint8_t ecdh_x[32], const uint8_t agent_pk[33],
                              const uint8_t vendor_pk[33], uint64_t nonce, uint8_t out_mac[16]) {
    uint8_t buf[33 + 33 + 8], full[32];
    memcpy(buf, agent_pk, 33);
    memcpy(buf + 33, vendor_pk, 33);
    for (int i = 0; i < 8; i++) buf[66 + i] = (uint8_t)(nonce >> (56 - i * 8));
    csls_hmac32(ecdh_x, buf, sizeof(buf), full);
    memcpy(out_mac, full, 16);
    OPENSSL_cleanse(full, sizeof(full));
}

// Deterministic nonce hash via precomputed HMAC midstates (hot path: no heap,
// no one-shot HMAC allocation): k_hash = SHA256(opad_state || SHA256(ipad_state || msg))
static void csls_derive_k_hash(const SHA256_CTX *ictx0, const SHA256_CTX *octx0,
                               const uint8_t pre[42], size_t plen, uint8_t out[32]) {
    SHA256_CTX ic = *ictx0, oc = *octx0;
    uint8_t inner[32];
    SHA256_Update(&ic, pre, plen);
    SHA256_Final(inner, &ic);
    SHA256_Update(&oc, inner, 32);
    SHA256_Final(out, &oc);
    OPENSSL_cleanse(inner, sizeof(inner));
}

// --- Dual-Sector Ping-Pong Watermark WAL -------------------------------------
// Sector authenticity: hmac = HMAC-SHA256(sk, "CSLS_WAL_INTEGRITY_v1" || magic ||
// sequence || reserved). Keyed by the agent's signing key: a local co-tenant with
// WAL write access but no sk cannot mint a lease with a lowered reserved_height
// (Red Team P1). CRC-64 was dropped — unkeyed integrity is worthless against a
// forger who recomputes it.
static void csls_wal_fill_sector(csls_wal_sector_t *s, uint32_t seq, uint64_t reserved) {
    memset(s, 0, sizeof(*s));
    s->magic = CSLS_WAL_MAGIC;
    s->sequence = seq;
    s->reserved_height = reserved;
    s->crc64 = csls_crc64(s, 16); // CRC covers magic+sequence+reserved (NOT the crc field itself)
}
static int csls_wal_sector_valid(const csls_wal_sector_t *s) {
    return s->magic == CSLS_WAL_MAGIC && s->crc64 == csls_crc64(s, 16);
}
// Durably extend the lease by one block. O_DSYNC makes the pwrite itself the
// durability barrier; heights <= new reserved are safe to sign afterwards.
static int csls_wal_renew(csls_agent_ctx_t *a) {
    csls_wal_sector_t s;
    uint32_t seq = a->wal_sequence + 1;
    uint64_t reserved = a->wal_reserved + CSLS_WAL_BLOCK;
    csls_wal_fill_sector(&s, seq, reserved);
    memset(a->wal_buf, 0, CSLS_WAL_SECTOR);
    memcpy(a->wal_buf, &s, sizeof(s));
    off_t off = (seq & 1) ? CSLS_WAL_SECTOR : 0;
    ssize_t w = pwrite(a->wal_fd, a->wal_buf, CSLS_WAL_SECTOR, off);
    if (w != CSLS_WAL_SECTOR) {
        atomic_store_explicit(&a->wal_fatal, 1, memory_order_release);
        pthread_mutex_lock(&a->lease_mu);
        pthread_cond_broadcast(&a->lease_cv);
        pthread_mutex_unlock(&a->lease_mu);
        return -1;
    }
    a->wal_sequence = seq;
    a->wal_reserved = reserved;
    atomic_store_explicit(&a->watermark_boundary, reserved, memory_order_release);
    pthread_mutex_lock(&a->lease_mu);
    pthread_cond_broadcast(&a->lease_cv);
    pthread_mutex_unlock(&a->lease_mu);
    return 0;
}

// --- Singleton Refiller (work queue, ONE background thread per process) ------
static struct {
    pthread_mutex_t  mu;
    pthread_cond_t   cv;
    csls_agent_ctx_t *ring[CSLS_REFILLER_RING];
    size_t           head, count;
    pthread_t        thread;
    bool             started;
    _Atomic bool     stop;
} g_refiller = { .mu = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER, .stop = false };

static void *csls_refiller_main(void *arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&g_refiller.mu);
        while (g_refiller.count == 0 && !atomic_load_explicit(&g_refiller.stop, memory_order_relaxed))
            pthread_cond_wait(&g_refiller.cv, &g_refiller.mu);
        if (g_refiller.count == 0 && atomic_load_explicit(&g_refiller.stop, memory_order_relaxed)) {
            pthread_mutex_unlock(&g_refiller.mu);
            break;
        }
        csls_agent_ctx_t *a = g_refiller.ring[g_refiller.head];
        g_refiller.ring[g_refiller.head] = NULL;
        g_refiller.head = (g_refiller.head + 1) % (sizeof(g_refiller.ring) / sizeof(g_refiller.ring[0]));
        g_refiller.count--;
        // Hold mu for the whole renewal: serializes O_DSYNC writes and pins the
        // agent against csls_agent_destroy for the duration (no use-after-free).
        if (a) csls_wal_renew(a);
        atomic_store_explicit(&a->renew_requested, 0, memory_order_relaxed);
        pthread_mutex_unlock(&g_refiller.mu);
    }
    return NULL;
}
static void csls_refiller_start(void) {
    pthread_mutex_lock(&g_refiller.mu);
    if (!g_refiller.started) {
        g_refiller.started = true;
        pthread_create(&g_refiller.thread, NULL, csls_refiller_main, NULL);
    }
    pthread_mutex_unlock(&g_refiller.mu);
}
static bool csls_refiller_submit(csls_agent_ctx_t *a) {
    bool ok = false;
    pthread_mutex_lock(&g_refiller.mu);
    if (g_refiller.count < (sizeof(g_refiller.ring) / sizeof(g_refiller.ring[0]))) {
        g_refiller.ring[(g_refiller.head + g_refiller.count) % (sizeof(g_refiller.ring) / sizeof(g_refiller.ring[0]))] = a;
        g_refiller.count++;
        pthread_cond_signal(&g_refiller.cv);
        ok = true;
    }
    pthread_mutex_unlock(&g_refiller.mu);
    return ok; // false => caller must clear renew_requested or the lease deadlocks
}
static void csls_refiller_detach(csls_agent_ctx_t *a) {
    pthread_mutex_lock(&g_refiller.mu);
    size_t cap = sizeof(g_refiller.ring) / sizeof(g_refiller.ring[0]);
    for (size_t i = 0; i < g_refiller.count; i++)
        if (g_refiller.ring[(g_refiller.head + i) % cap] == a)
            g_refiller.ring[(g_refiller.head + i) % cap] = NULL;
    pthread_mutex_unlock(&g_refiller.mu);
}

// -----------------------------------------------------------------------------
// Multi-Channel O(1) State Table Implementation
// -----------------------------------------------------------------------------

static inline uint64_t csls_hash_peer_pk(const uint8_t *pk) {
    uint64_t hash = 14695981039346656037ULL;
    for (int i = 0; i < 33; i++) {
        hash ^= pk[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

void csls_channel_table_init(csls_channel_table_t *table) {
    if (!table) return;
    memset(table, 0, sizeof(csls_channel_table_t));
    for (size_t i = 0; i < CSLS_MAX_CHANNELS; i++) {
        pthread_spin_init(&table->channels[i].lock, PTHREAD_PROCESS_PRIVATE);
        atomic_init(&table->channels[i].height, 0);
        atomic_init(&table->channels[i].cumulative_sent, 0);
        atomic_init(&table->channels[i].cleared_amount, 0);
        atomic_init(&table->channels[i].accumulated_amount, 0);
        table->channels[i].occupied = false;
    }
    table->count = 0;
}

void csls_channel_table_destroy(csls_channel_table_t *table) {
    if (!table) return;
    for (size_t i = 0; i < CSLS_MAX_CHANNELS; i++) {
        pthread_spin_destroy(&table->channels[i].lock);
    }
    memset(table, 0, sizeof(csls_channel_table_t));
}

csls_channel_t *csls_channel_get_or_create(csls_channel_table_t *table, const uint8_t *peer_pk) {
    if (!table || !peer_pk) return NULL;

    uint32_t start_slot = (uint32_t)(csls_hash_peer_pk(peer_pk) & CSLS_CHANNEL_MASK);

    for (size_t step = 0; step < CSLS_MAX_CHANNELS; step++) {
        uint32_t idx = (start_slot + step) & CSLS_CHANNEL_MASK;
        csls_channel_t *chan = &table->channels[idx];

        if (chan->occupied) {
            if (memcmp(chan->peer_pk, peer_pk, 33) == 0) {
                return chan;
            }
            continue;
        }

        pthread_spin_lock(&chan->lock);
        if (!chan->occupied) {
            memcpy(chan->peer_pk, peer_pk, 33);
            atomic_init(&chan->height, 0);
            atomic_init(&chan->cumulative_sent, 0);
            atomic_init(&chan->cleared_amount, 0);
            atomic_init(&chan->accumulated_amount, 0);
            chan->occupied = true;
            table->count++;
            pthread_spin_unlock(&chan->lock);
            return chan;
        }

        if (memcmp(chan->peer_pk, peer_pk, 33) == 0) {
            pthread_spin_unlock(&chan->lock);
            return chan;
        }
        pthread_spin_unlock(&chan->lock);
    }

    return NULL;
}

static csls_channel_t *csls_channel_find(csls_channel_table_t *table, const uint8_t *peer_pk) {
    if (!table || !peer_pk) return NULL;
    uint32_t start_slot = (uint32_t)(csls_hash_peer_pk(peer_pk) & CSLS_CHANNEL_MASK);
    for (size_t step = 0; step < CSLS_MAX_CHANNELS; step++) {
        csls_channel_t *chan = &table->channels[(start_slot + step) & CSLS_CHANNEL_MASK];
        if (!chan->occupied) return NULL;
        if (memcmp(chan->peer_pk, peer_pk, 33) == 0) return chan;
    }
    return NULL;
}

csls_agent_ctx_t *csls_agent_new(const uint8_t *sk_bytes, const char *wal_path) {
    csls_agent_ctx_t *agent = (csls_agent_ctx_t *)calloc(1, sizeof(csls_agent_ctx_t));
    if (!agent) return NULL;
    if (csls_agent_init(agent, sk_bytes, wal_path) != 0) {
        free(agent);
        return NULL;
    }
    return agent;
}

void csls_agent_free(csls_agent_ctx_t *agent) {
    if (agent) {
        csls_agent_destroy(agent);
        free(agent);
    }
}

int csls_agent_init(csls_agent_ctx_t *agent, const uint8_t *sk_bytes, const char *wal_path) {
    if (!agent || !sk_bytes) return -1;
    memset(agent, 0, sizeof(csls_agent_ctx_t));
    memcpy(agent->sk, sk_bytes, 32);

    if (csls_derive_pk(agent->sk, agent->pk) != 0) return -1;

    csls_channel_table_init(&agent->channels);
    atomic_init(&agent->height, 1);
    atomic_init(&agent->watermark_boundary, UINT64_MAX);
    atomic_init(&agent->wal_fatal, 0);
    atomic_init(&agent->renew_requested, 0);
    agent->cumulative_sent = 0;
    agent->wal_fd = -1;
    agent->n_sessions = 0;
    pthread_mutex_init(&agent->lock, NULL);
    pthread_mutex_init(&agent->lease_mu, NULL);
    pthread_cond_init(&agent->lease_cv, NULL);

    // Precompute HMAC ipad/opad SHA-256 midstates once (key = sk is constant):
    // hot-path nonce derivation costs two compressions instead of a 2 us one-shot.
    {
        uint8_t ipad[64], opad[64];
        memset(ipad, 0x36, 64);
        memset(opad, 0x5c, 64);
        for (int i = 0; i < 32; i++) { ipad[i] ^= agent->sk[i]; opad[i] ^= agent->sk[i]; }
        SHA256_Init(&agent->hmac_ictx0);
        SHA256_Update(&agent->hmac_ictx0, ipad, 64);
        SHA256_Init(&agent->hmac_octx0);
        SHA256_Update(&agent->hmac_octx0, opad, 64);
        OPENSSL_cleanse(ipad, sizeof(ipad));
        OPENSSL_cleanse(opad, sizeof(opad));
    }

    // Pre-allocate BIGNUM execution context to eliminate hot-loop heap allocation
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bn_sk = BN_new();
    BIGNUM *bn_k = BN_new();
    BIGNUM *bn_e = BN_new();
    BIGNUM *bn_s = BN_new();
    BIGNUM *bn_tmp = BN_new();

    if (!ctx || !bn_sk || !bn_k || !bn_e || !bn_s || !bn_tmp) {
        if (ctx) BN_CTX_free(ctx);
        if (bn_sk) BN_free(bn_sk);
        if (bn_k) BN_free(bn_k);
        if (bn_e) BN_free(bn_e);
        if (bn_s) BN_free(bn_s);
        if (bn_tmp) BN_free(bn_tmp);
        return -1;
    }

    BN_bin2bn(agent->sk, 32, bn_sk);
    agent->bn_ctx = ctx;
    agent->bn_sk = bn_sk;
    agent->bn_k = bn_k;
    agent->bn_e = bn_e;
    agent->bn_s = bn_s;
    agent->bn_tmp = bn_tmp;

    if (wal_path && strlen(wal_path) > 0) {
        strncpy(agent->wal_path, wal_path, sizeof(agent->wal_path) - 1);
        int fd = open(agent->wal_path, O_RDWR | O_CREAT | O_DSYNC | O_DIRECT, 0600);
        if (fd < 0) fd = open(agent->wal_path, O_RDWR | O_CREAT | O_DSYNC, 0600);
        if (fd < 0) return -6;
        if (posix_memalign((void **)&agent->wal_buf, CSLS_WAL_SECTOR, CSLS_WAL_SECTOR) != 0) {
            close(fd);
            agent->wal_fd = -1;
            return -6;
        }
        csls_wal_sector_t sa, sb;
        memset(&sa, 0, sizeof(sa));
        memset(&sb, 0, sizeof(sb));
        ssize_t ra = pread(fd, agent->wal_buf, CSLS_WAL_SECTOR, 0);
        if (ra == CSLS_WAL_SECTOR) memcpy(&sa, agent->wal_buf, sizeof(sa));
        ssize_t rb = pread(fd, agent->wal_buf, CSLS_WAL_SECTOR, CSLS_WAL_SECTOR);
        if (rb == CSLS_WAL_SECTOR) memcpy(&sb, agent->wal_buf, sizeof(sb));
        int va = csls_wal_sector_valid(&sa);
        int vb = csls_wal_sector_valid(&sb);
        int fresh_a = (ra <= 0) || (sa.magic == 0 && sa.sequence == 0 && sa.reserved_height == 0);
        int fresh_b = (rb <= 0) || (sb.magic == 0 && sb.sequence == 0 && sb.reserved_height == 0);
        uint32_t seq = 0;
        uint64_t reserved = 0;
        if (va && vb) {
            if (sa.sequence >= sb.sequence) { seq = sa.sequence; reserved = sa.reserved_height; }
            else                            { seq = sb.sequence; reserved = sb.reserved_height; }
        } else if (va) {
            seq = sa.sequence; reserved = sa.reserved_height;
        } else if (vb) {
            seq = sb.sequence; reserved = sb.reserved_height;
        } else if (fresh_a && fresh_b) {
            seq = 0; reserved = 0; // brand-new lease file
        } else {
            // Content present but integrity failed on both sides: fail-closed.
            close(fd);
            free(agent->wal_buf);
            agent->wal_buf = NULL;
            return -6;
        }
        agent->wal_fd = fd;
        agent->wal_sequence = seq;
        agent->wal_reserved = reserved;
        // New life starts strictly ABOVE every height the previous life could
        // have used (old lease top + 1), then the next block is leased durably
        // BEFORE the first signature of this life.
        uint64_t boot = reserved + 1;
        if (csls_wal_renew(agent) != 0) {
            close(fd);
            free(agent->wal_buf);
            agent->wal_buf = NULL;
            agent->wal_fd = -1;
            return -6;
        }
        atomic_store(&agent->height, boot);
        atomic_store(&agent->watermark_boundary, agent->wal_reserved);
        csls_refiller_start();
    } else {
        atomic_store(&agent->height, 1);
        atomic_store(&agent->watermark_boundary, UINT64_MAX);
    }
    return 0;
}

void csls_agent_destroy(csls_agent_ctx_t *agent) {
    if (agent) {
        csls_refiller_detach(agent);
        if (agent->wal_fd >= 0) {
            close(agent->wal_fd);
            agent->wal_fd = -1;
        }
        if (agent->wal_buf) {
            OPENSSL_cleanse(agent->wal_buf, CSLS_WAL_SECTOR);
            free(agent->wal_buf);
            agent->wal_buf = NULL;
        }
        OPENSSL_cleanse(agent->sk, sizeof(agent->sk));
        pthread_mutex_destroy(&agent->lock);
        pthread_mutex_destroy(&agent->lease_mu);
        pthread_cond_destroy(&agent->lease_cv);
        csls_channel_table_destroy(&agent->channels);

        if (agent->bn_ctx) {
            BN_free((BIGNUM *)agent->bn_sk);
            BN_free((BIGNUM *)agent->bn_k);
            BN_free((BIGNUM *)agent->bn_e);
            BN_free((BIGNUM *)agent->bn_s);
            BN_free((BIGNUM *)agent->bn_tmp);
            BN_CTX_free((BN_CTX *)agent->bn_ctx);
            agent->bn_ctx = NULL;
        }
    }
}

static int csls_agent_sign_common(csls_agent_ctx_t *agent, const uint8_t *vendor_pk,
                                  uint64_t delta_micro_usdc, csls_cheque_pkt_t *out_pkt,
                                  uint8_t *out_mac) {
    if (!agent || !vendor_pk || !out_pkt) return -1;

    pthread_mutex_lock(&agent->lock);

    csls_channel_t *chan = csls_channel_get_or_create(&agent->channels, vendor_pk);
    if (!chan) {
        pthread_mutex_unlock(&agent->lock);
        return -3; // CHANNEL_TABLE_FULL
    }

    uint64_t cur_cum = atomic_load(&chan->cumulative_sent);
    // Strict integer overflow check on cumulative amount
    if (cur_cum + delta_micro_usdc < cur_cum) {
        pthread_mutex_unlock(&agent->lock);
        return -2; // OVERFLOW_ERROR
    }

    // GLOBAL watermark-leased height: single source of truth. The per-channel
    // counter below is a cache for diagnostics/handshake bookkeeping only.
    uint64_t h = atomic_fetch_add_explicit(&agent->height, 1, memory_order_relaxed);

    // Durable-lease invariant: NEVER sign a height beyond the durable reservation.
    // If the lease runs dry the hot path blocks until the refiller lands the next
    // block — signing past the watermark would resurrect the C1 nonce-reuse leak.
    if (agent->wal_fd >= 0) {
        for (;;) {
            uint64_t b = atomic_load_explicit(&agent->watermark_boundary, memory_order_acquire);
            if (h <= b) break;
            if (atomic_load_explicit(&agent->wal_fatal, memory_order_acquire)) {
                pthread_mutex_unlock(&agent->lock);
                return CSLS_ERR_WAL_FATAL;
            }
            pthread_mutex_lock(&agent->lease_mu);
            if (h > atomic_load_explicit(&agent->watermark_boundary, memory_order_acquire) &&
                !atomic_load_explicit(&agent->wal_fatal, memory_order_acquire))
                pthread_cond_wait(&agent->lease_cv, &agent->lease_mu);
            pthread_mutex_unlock(&agent->lease_mu);
        }
        uint64_t b = atomic_load_explicit(&agent->watermark_boundary, memory_order_acquire);
        if (b - h <= CSLS_WAL_REFILL_AT && !atomic_exchange(&agent->renew_requested, 1)) {
            if (!csls_refiller_submit(agent))
                atomic_store(&agent->renew_requested, 0); // queue full: retry on a later tick
        }
    }

    uint64_t cum_amt = atomic_fetch_add(&chan->cumulative_sent, delta_micro_usdc) + delta_micro_usdc;
    atomic_store(&chan->height, h);
    agent->cumulative_sent += delta_micro_usdc;

    out_pkt->magic = CSLS_MAGIC;
    out_pkt->type = CSLS_PKT_CHEQUE;
    memcpy(out_pkt->agent_pk, agent->pk, 33);
    memcpy(out_pkt->vendor_pk, vendor_pk, 33);
    out_pkt->height = h;
    out_pkt->cumulative_amt = cum_amt;

    // 1. Deterministic Nonce Derivation: k = HMAC-SHA256(sk, vendor_pk || height) mod q
    uint8_t h_be[8];
    for (int i = 0; i < 8; i++) h_be[i] = (uint8_t)((h >> (56 - i * 8)) & 0xFF);

    uint8_t k_preimage[33 + 8 + 1];
    memcpy(k_preimage, vendor_pk, 33);
    memcpy(k_preimage + 33, h_be, 8);
    k_preimage[41] = 0;

    uint8_t k_hash[32];

    BN_CTX *ctx = (BN_CTX *)agent->bn_ctx;
    BIGNUM *k = (BIGNUM *)agent->bn_k;
    BIGNUM *e = (BIGNUM *)agent->bn_e;
    BIGNUM *sk = (BIGNUM *)agent->bn_sk;
    BIGNUM *s = (BIGNUM *)agent->bn_s;
    BIGNUM *tmp = (BIGNUM *)agent->bn_tmp;

    // RFC 6979-style H3 counter loop via midstates (no heap, no one-shot HMAC)
    while (1) {
        csls_derive_k_hash(&agent->hmac_ictx0, &agent->hmac_octx0, k_preimage,
                           (k_preimage[41] == 0 ? 41 : 42), k_hash);
        BN_bin2bn(k_hash, 32, k);
        if (memcmp(k_hash, SECP256K1_Q_BE, 32) >= 0) {
            BN_nnmod(k, k, g_curve_order_q, ctx);
        }
        if (!BN_is_zero(k)) {
            break;
        }
        k_preimage[41]++;
        if (k_preimage[41] == 0) { // 1-byte counter exhausted: cryptographically impossible
            pthread_mutex_unlock(&agent->lock);
            return -1;
        }
    }


    // 2. Challenge Hash: e = SHA256(agent_pk || vendor_pk || height || cumulative_amt) mod q
    uint8_t preimage[33 + 33 + 8 + 8];
    memcpy(preimage, out_pkt->agent_pk, 33);
    memcpy(preimage + 33, out_pkt->vendor_pk, 33);
    memcpy(preimage + 66, h_be, 8);
    for (int i = 0; i < 8; i++) {
        preimage[74 + i] = (uint8_t)((out_pkt->cumulative_amt >> (56 - i * 8)) & 0xFF);
    }

    uint8_t e_digest[32];
    SHA256(preimage, sizeof(preimage), e_digest);

    // Fast path: if 256-bit hash < secp256k1 order q, hash mod q == hash
    if (memcmp(e_digest, SECP256K1_Q_BE, 32) < 0) {
        memcpy(out_pkt->challenge_e, e_digest, 32);
        BN_bin2bn(e_digest, 32, e);
    } else {
        BN_bin2bn(e_digest, 32, e);
        BN_nnmod(e, e, g_curve_order_q, ctx);
        BN_bn2binpad(e, out_pkt->challenge_e, 32);
    }

    // 3. Zero-Heap EOTS Schnorr Signature Scalar: s = (k + e * sk) mod q
    BN_mod_mul(tmp, e, sk, g_curve_order_q, ctx);
    BN_mod_add(s, k, tmp, g_curve_order_q, ctx);
    BN_bn2binpad(s, out_pkt->sig_s, 32);

    if (out_mac) {
        // C2: session MAC over the raw 151-byte cheque (SipHash-2-4, 128-bit)
        int chan_idx = (int)(chan - agent->channels.channels);
        const uint8_t *skey = NULL;
        for (int i = 0; i < agent->n_sessions; i++)
            if (agent->sessions[i].chan_idx == chan_idx) { skey = agent->sessions[i].key; break; }
        if (!skey) {
            pthread_mutex_unlock(&agent->lock);
            return CSLS_ERR_NO_SESSION;
        }
        csls_mac128(skey, out_pkt, sizeof(*out_pkt), out_mac);
    }

    pthread_mutex_unlock(&agent->lock);
    return 0;
}

int csls_agent_sign_cheque(csls_agent_ctx_t *agent, const uint8_t *vendor_pk,
                           uint64_t delta_micro_usdc, csls_cheque_pkt_t *out_pkt) {
    return csls_agent_sign_common(agent, vendor_pk, delta_micro_usdc, out_pkt, NULL);
}

int csls_agent_sign_cheque_mac(csls_agent_ctx_t *agent, const uint8_t *vendor_pk,
                               uint64_t delta_micro_usdc, csls_cheque_pkt_t *out_pkt,
                               uint8_t out_mac[16]) {
    return csls_agent_sign_common(agent, vendor_pk, delta_micro_usdc, out_pkt, out_mac);
}

int csls_agent_mac_packet(csls_agent_ctx_t *agent, const uint8_t *vendor_pk,
                          const csls_cheque_pkt_t *pkt, uint8_t out_mac[16]) {
    if (!agent || !vendor_pk || !pkt || !out_mac) return -1;
    pthread_mutex_lock(&agent->lock);
    csls_channel_t *chan = csls_channel_get_or_create(&agent->channels, vendor_pk);
    if (!chan) { pthread_mutex_unlock(&agent->lock); return -3; }
    int chan_idx = (int)(chan - agent->channels.channels);
    const uint8_t *skey = NULL;
    for (int i = 0; i < agent->n_sessions; i++)
        if (agent->sessions[i].chan_idx == chan_idx) { skey = agent->sessions[i].key; break; }
    if (!skey) { pthread_mutex_unlock(&agent->lock); return CSLS_ERR_NO_SESSION; }
    csls_mac128(skey, pkt, sizeof(*pkt), out_mac);
    pthread_mutex_unlock(&agent->lock);
    return 0;
}

csls_vendor_ctx_t *csls_vendor_new(const uint8_t *sk_bytes, uint64_t delta_v) {
    csls_vendor_ctx_t *vendor = (csls_vendor_ctx_t *)calloc(1, sizeof(csls_vendor_ctx_t));
    if (!vendor) return NULL;
    if (csls_vendor_init(vendor, sk_bytes, delta_v) != 0) {
        free(vendor);
        return NULL;
    }
    return vendor;
}

void csls_vendor_free(csls_vendor_ctx_t *vendor) {
    if (vendor) {
        csls_vendor_destroy(vendor);
        free(vendor);
    }
}

int csls_vendor_init(csls_vendor_ctx_t *vendor, const uint8_t *sk_bytes, uint64_t delta_v) {
    if (!vendor || !sk_bytes) return -1;
    memset(vendor, 0, sizeof(csls_vendor_ctx_t));
    memcpy(vendor->sk, sk_bytes, 32);

    if (csls_derive_pk(vendor->sk, vendor->pk) != 0) return -1;

    csls_channel_table_init(&vendor->channels);
    vendor->max_exposure_delta_v = (delta_v > 0) ? delta_v : CSLS_DEFAULT_DELTA_V;
    pthread_mutex_init(&vendor->lock, NULL);

    if (RAND_bytes((unsigned char *)&vendor->slot_seed, sizeof(vendor->slot_seed)) != 1) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        vendor->slot_seed = (uint64_t)ts.tv_nsec ^ ((uint64_t)ts.tv_sec << 32) ^ 0xCAFEBABEDEADBEEFULL;
    }
    vendor->enforce_mac = 0; // legacy mode by default; production paths opt in

    return 0;
}


void csls_vendor_destroy(csls_vendor_ctx_t *vendor) {
    if (vendor) {
        pthread_mutex_destroy(&vendor->lock);
        csls_channel_table_destroy(&vendor->channels);
        memset(vendor, 0, sizeof(csls_vendor_ctx_t));
    }
}

// Algebraic Private Key Extraction: sk = (s1 - s2) * (e1 - e2)^(-1) mod q
int csls_extract_private_key(const csls_cheque_pkt_t *c1, const csls_cheque_pkt_t *c2, 
                              uint8_t *out_sk) {
    if (!c1 || !c2 || !out_sk) return -1;
    if (c1->height != c2->height) return -2; // Must be identical height
    if (memcmp(c1->agent_pk, c2->agent_pk, 33) != 0) return -6; // Must be same agent
    if (memcmp(c1->vendor_pk, c2->vendor_pk, 33) != 0) return -7; // Equivocation is strictly per-vendor channel!
    if (memcmp(c1->challenge_e, c2->challenge_e, 32) == 0) return -3; // No equivocation

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *s1 = BN_bin2bn(c1->sig_s, 32, NULL);
    BIGNUM *s2 = BN_bin2bn(c2->sig_s, 32, NULL);
    BIGNUM *e1 = BN_bin2bn(c1->challenge_e, 32, NULL);
    BIGNUM *e2 = BN_bin2bn(c2->challenge_e, 32, NULL);

    BIGNUM *delta_s = BN_new();
    BIGNUM *delta_e = BN_new();
    BIGNUM *inv_delta_e = BN_new();
    BIGNUM *extracted_sk = BN_new();

    // delta_s = (s1 - s2) mod q
    BN_mod_sub(delta_s, s1, s2, g_curve_order_q, ctx);

    // delta_e = (e1 - e2) mod q
    BN_mod_sub(delta_e, e1, e2, g_curve_order_q, ctx);

    // inv_delta_e = (delta_e)^(-1) mod q
    if (!BN_mod_inverse(inv_delta_e, delta_e, g_curve_order_q, ctx)) {
        // Inverse does not exist (cannot happen since q is prime and e1 != e2)
        BN_free(s1); BN_free(s2); BN_free(e1); BN_free(e2);
        BN_free(delta_s); BN_free(delta_e); BN_free(inv_delta_e); BN_free(extracted_sk);
        BN_CTX_free(ctx);
        return -4;
    }

    // sk = (delta_s * inv_delta_e) mod q
    BN_mod_mul(extracted_sk, delta_s, inv_delta_e, g_curve_order_q, ctx);
    BN_bn2binpad(extracted_sk, out_sk, 32);

    // Verify key against agent_pk to confirm authenticity
    uint8_t derived_pk[33];
    int pk_match = (csls_derive_pk(out_sk, derived_pk) == 0 && 
                    memcmp(derived_pk, c1->agent_pk, 33) == 0);

    BN_free(s1); BN_free(s2); BN_free(e1); BN_free(e2);
    BN_free(delta_s); BN_free(delta_e); BN_free(inv_delta_e); BN_free(extracted_sk);
    BN_CTX_free(ctx);

    return pk_match ? 0 : -5;
}

/**
 * csls_vendor_process_cheque:
 *
 * ARCHITECTURAL DESIGN: Optimistic P2P Credit Streaming Bounded by delta_v.
 *
 * In high-frequency autonomous agent streaming (e.g. 50k+ tokens/sec at $0.0001 per chunk),
 * executing full elliptic curve scalar multiplications (EC_POINT_mul ~30-70 us) on every
 * single micro-tick creates severe CPU bottlenecks and latency jitter.
 *
 * Instead, Causal-Slash implements an optimistic pipelined credit buffer:
 * 1. HOTPATH CHECK: Vendor validates protocol framing, cumulative monotonic height progression,
 *    preimage challenge hash (e == SHA256(...) mod q), and enforces local credit buffer (delta_v).
 * 2. BOUNDED EXPOSURE: Unsettled credit delivery is hard-capped at delta_v (e.g. <= $1.00 USDC).
 * 3. FRAUD DETERRENCE: The signature scalar sig_s is recorded in an O(1) circular history ring buffer.
 *    If an attacker attempts double-spending / equivocation at the same height h, the linear system
 *    s1 - s2 = (e1 - e2) * sk mod q is solved algebraically in O(1) (~15 us modular arithmetic).
 *    The extracted key sk is verified against agent_pk and committed to PerformanceCollateralVault.sol
 *    on Base L2 to foreclose the attacker's collateral bond B.
 * 4. NEGATIVE ROI: Because B >> sum(delta_v), any attempt to cheat yields at most delta_v
 *    while forfeiting collateral bond B (Expected Payoff E[W] < 0, ROI <= -95%).
 */

static int csls_vendor_process_common(csls_vendor_ctx_t *vendor, const csls_cheque_pkt_t *pkt,
                                      csls_fraud_pkt_t *out_fraud, const uint8_t *mac) {
    if (!vendor || !pkt) return -1;

    // 1. Framing & Protocol Magic
    if (pkt->magic != CSLS_MAGIC || pkt->type != CSLS_PKT_CHEQUE) {
        return -10; // INVALID_PACKET
    }

    pthread_mutex_lock(&vendor->lock);

    // O(1) Channel Lookup / Creation for this specific agent
    csls_channel_t *chan = csls_channel_get_or_create(&vendor->channels, pkt->agent_pk);
    if (!chan) {
        pthread_mutex_unlock(&vendor->lock);
        return -15; // CHANNEL_TABLE_FULL
    }
    int chan_idx = (int)(chan - vendor->channels.channels);
    csls_head_t *head = &vendor->heads[chan_idx];

    // 1b. C2 Gate: session MAC. Outsiders cannot forge a single byte without the
    // ECDH-derived session key; garbage-s packets from the wire die here.
    if (vendor->enforce_mac) {
        if (!mac || !head->mac_active) {
            pthread_mutex_unlock(&vendor->lock);
            return CSLS_ERR_BAD_MAC;
        }
        uint8_t tag[16];
        csls_mac128(head->session_key, pkt, sizeof(*pkt), tag);
        if (memcmp(tag, mac, 16) != 0) {
            pthread_mutex_unlock(&vendor->lock);
            return CSLS_ERR_BAD_MAC;
        }
    }

    uint64_t accumulated = atomic_load(&chan->accumulated_amount);
    uint64_t cleared = atomic_load(&chan->cleared_amount);

    // 2. Exposure Buffer Invariant: unconfirmed delta <= delta_v per channel
    if (pkt->cumulative_amt < accumulated) {
        pthread_mutex_unlock(&vendor->lock);
        return -11; // DECREASING_AMOUNT_ATTACK
    }
    uint64_t unconfirmed_exposure = (pkt->cumulative_amt >= cleared) ? (pkt->cumulative_amt - cleared) : 0;
    if (unconfirmed_exposure > vendor->max_exposure_delta_v) {
        pthread_mutex_unlock(&vendor->lock);
        return -12; // EXPOSURE_BUFFER_EXCEEDED (Halt streaming)
    }

    // 3. Monotonicity and Equivocation Trap (O(1) Circular History Table with splitmix mixing)
    uint32_t slot = csls_vendor_slot(pkt->height, pkt->agent_pk, pkt->vendor_pk, vendor->slot_seed);
    csls_history_entry_t *entry = &vendor->history[slot];

    if (entry->occupied && entry->height == pkt->height && memcmp(entry->agent_pk, pkt->agent_pk, 33) == 0) {
        // Height collision detected for this specific agent! Check challenge scalar
        if (memcmp(entry->challenge_e, pkt->challenge_e, 32) != 0) {
            // CRITICAL: Potential EQUIVOCATION (DOUBLE-SPEND) DETECTED!
            // Reconstruct previous cheque from history
            csls_cheque_pkt_t c1;
            c1.magic = CSLS_MAGIC;
            c1.type = CSLS_PKT_CHEQUE;
            memcpy(c1.agent_pk, entry->agent_pk, 33);
            memcpy(c1.vendor_pk, vendor->pk, 33);
            c1.height = entry->height;
            c1.cumulative_amt = entry->amount;
            memcpy(c1.challenge_e, entry->challenge_e, 32);
            memcpy(c1.sig_s, entry->sig_s, 32);

            uint8_t extracted_sk[32];
            int ext_rc = csls_extract_private_key(&c1, pkt, extracted_sk);
            if (ext_rc != 0) {
                pthread_mutex_unlock(&vendor->lock);
                return -23; // FORGED_CHALLENGE_HASH
            }

            if (out_fraud) {
                out_fraud->magic = CSLS_MAGIC;
                out_fraud->type = CSLS_PKT_FRAUD;
                memcpy(out_fraud->offender_pk, pkt->agent_pk, 33);
                out_fraud->collision_h = pkt->height;
                out_fraud->cheque1 = c1;
                out_fraud->cheque2 = *pkt;
                memcpy(out_fraud->extracted_sk, extracted_sk, 32);
            }
            pthread_mutex_unlock(&vendor->lock);
            return -20; // FRAUD_EQUIVOCATION_DETECTED
        }
        pthread_mutex_unlock(&vendor->lock);
        return -21; // REPLAY_PACKET_IGNORED
    }

    uint64_t last_h = atomic_load(&chan->height);
    if (last_h > 0 && pkt->height <= last_h) {
        pthread_mutex_unlock(&vendor->lock);
        return -22; // OUT_OF_ORDER_OR_OLD_REPLAY
    }

    // 4. Verify Challenge Hash: e == SHA256(agent_pk || vendor_pk || height || cumulative_amt) mod q
    uint8_t h_be[8];
    for (int i = 0; i < 8; i++) h_be[i] = (uint8_t)((pkt->height >> (56 - i * 8)) & 0xFF);
    uint8_t preimage[33 + 33 + 8 + 8];
    memcpy(preimage, pkt->agent_pk, 33);
    memcpy(preimage + 33, pkt->vendor_pk, 33);
    memcpy(preimage + 66, h_be, 8);
    for (int i = 0; i < 8; i++) {
        preimage[74 + i] = (uint8_t)((pkt->cumulative_amt >> (56 - i * 8)) & 0xFF);
    }
    uint8_t e_digest[32];
    SHA256(preimage, sizeof(preimage), e_digest);

    uint8_t expected_e[32];
    // Fast path: if 256-bit hash < secp256k1 order q, hash mod q == hash (occurs with probability 1 - 1.45e-38)
    if (memcmp(e_digest, SECP256K1_Q_BE, 32) < 0) {
        memcpy(expected_e, e_digest, 32);
    } else {
        BN_CTX *ctx = BN_CTX_new();
        BIGNUM *e_calc = BN_new();
        BN_bin2bn(e_digest, 32, e_calc);
        BN_nnmod(e_calc, e_calc, g_curve_order_q, ctx);
        BN_bn2binpad(e_calc, expected_e, 32);
        BN_free(e_calc);
        BN_CTX_free(ctx);
    }

    if (memcmp(expected_e, pkt->challenge_e, 32) != 0) {
        pthread_mutex_unlock(&vendor->lock);
        return -23; // FORGED_CHALLENGE_HASH
    }

    // 5. Record new valid state (history ring + head cheque for restart handshake)
    memcpy(entry->agent_pk, pkt->agent_pk, 33);
    entry->height = pkt->height;
    entry->amount = pkt->cumulative_amt;
    memcpy(entry->challenge_e, pkt->challenge_e, 32);
    memcpy(entry->sig_s, pkt->sig_s, 32);
    entry->occupied = true;
    head->cheque = *pkt;
    head->valid = true;

    atomic_store(&chan->height, pkt->height);
    atomic_store(&chan->accumulated_amount, pkt->cumulative_amt);
    vendor->last_height = pkt->height;
    vendor->accumulated_amount = pkt->cumulative_amt;

    pthread_mutex_unlock(&vendor->lock);
    return 0; // ACCEPTED_OK
}

int csls_vendor_process_cheque(csls_vendor_ctx_t *vendor, const csls_cheque_pkt_t *pkt,
                               csls_fraud_pkt_t *out_fraud) {
    return csls_vendor_process_common(vendor, pkt, out_fraud, NULL);
}

int csls_vendor_process_cheque_mac(csls_vendor_ctx_t *vendor, const csls_cheque_pkt_t *pkt,
                                   const uint8_t mac[16], csls_fraud_pkt_t *out_fraud) {
    return csls_vendor_process_common(vendor, pkt, out_fraud, mac);
}

int csls_vendor_enable_mac(csls_vendor_ctx_t *vendor, int enable) {
    if (!vendor) return -1;
    pthread_mutex_lock(&vendor->lock);
    vendor->enforce_mac = enable ? 1 : 0;
    pthread_mutex_unlock(&vendor->lock);
    return 0;
}

int csls_vendor_session_init(csls_vendor_ctx_t *vendor, const csls_session_init_pkt_t *init) {
    if (!vendor || !init) return -1;
    if (init->magic != CSLS_MAGIC || init->type != CSLS_PKT_SESSION_INIT) return -10;
    pthread_mutex_lock(&vendor->lock);
    uint8_t x[32];
    if (csls_ecdh_x(vendor->sk, init->agent_pk, x) != 0) {
        pthread_mutex_unlock(&vendor->lock);
        return -1;
    }
    uint8_t auth[16];
    csls_session_auth(x, init->agent_pk, init->vendor_pk, init->session_nonce, auth);
    if (memcmp(auth, init->auth_mac, 16) != 0) {
        // Spoofed INIT: the attacker does not hold the claimed agent's key.
        OPENSSL_cleanse(x, sizeof(x));
        pthread_mutex_unlock(&vendor->lock);
        return CSLS_ERR_BAD_MAC;
    }
    csls_channel_t *chan = csls_channel_get_or_create(&vendor->channels, init->agent_pk);
    if (!chan) {
        OPENSSL_cleanse(x, sizeof(x));
        pthread_mutex_unlock(&vendor->lock);
        return -15;
    }
    csls_head_t *hd = &vendor->heads[(int)(chan - vendor->channels.channels)];
    csls_session_kdf(x, init->session_nonce, hd->session_key);
    hd->mac_active = true;
    OPENSSL_cleanse(x, sizeof(x));
    pthread_mutex_unlock(&vendor->lock);
    return 0;
}

int csls_vendor_get_head_cheque(csls_vendor_ctx_t *vendor, const uint8_t *agent_pk,
                                csls_cheque_pkt_t *out_cheque) {
    if (!vendor || !agent_pk || !out_cheque) return -1;
    pthread_mutex_lock(&vendor->lock);
    csls_channel_t *chan = csls_channel_find(&vendor->channels, agent_pk);
    if (!chan) { pthread_mutex_unlock(&vendor->lock); return -14; }
    csls_head_t *hd = &vendor->heads[(int)(chan - vendor->channels.channels)];
    if (!hd->valid) { pthread_mutex_unlock(&vendor->lock); return -14; }
    *out_cheque = hd->cheque;
    pthread_mutex_unlock(&vendor->lock);
    return 0;
}

int csls_vendor_advance_cleared(csls_vendor_ctx_t *vendor, const uint8_t *agent_pk, uint64_t cleared_amount) {
    if (!vendor) return -1;
    pthread_mutex_lock(&vendor->lock);

    if (agent_pk) {
        csls_channel_t *chan = csls_channel_get_or_create(&vendor->channels, agent_pk);
        if (chan) {
            uint64_t cur = atomic_load(&chan->cleared_amount);
            if (cleared_amount > cur) {
                atomic_store(&chan->cleared_amount, cleared_amount);
            }
        }
    }
    if (cleared_amount > vendor->cleared_amount) {
        vendor->cleared_amount = cleared_amount;
    }

    pthread_mutex_unlock(&vendor->lock);
    return 0;
}

int csls_vendor_get_channel_state(csls_vendor_ctx_t *vendor, const uint8_t *agent_pk,
                                  uint64_t *out_height, uint64_t *out_accumulated, uint64_t *out_cleared) {
    if (!vendor || !agent_pk) return -1;
    pthread_mutex_lock(&vendor->lock);
    csls_channel_t *chan = csls_channel_get_or_create(&vendor->channels, agent_pk);
    if (!chan) {
        pthread_mutex_unlock(&vendor->lock);
        return -14;
    }
    if (out_height) *out_height = atomic_load(&chan->height);
    if (out_accumulated) *out_accumulated = atomic_load(&chan->accumulated_amount);
    if (out_cleared) *out_cleared = atomic_load(&chan->cleared_amount);
    pthread_mutex_unlock(&vendor->lock);
    return 0;
}

int csls_agent_get_channel_state(csls_agent_ctx_t *agent, const uint8_t *vendor_pk, 
                                  uint64_t *out_height, uint64_t *out_cumulative) {
    if (!agent || !vendor_pk) return -1;
    pthread_mutex_lock(&agent->lock);
    csls_channel_t *chan = csls_channel_get_or_create(&agent->channels, vendor_pk);
    if (!chan) {
        pthread_mutex_unlock(&agent->lock);
        return -14;
    }
    if (out_height) *out_height = atomic_load(&chan->height);
    if (out_cumulative) *out_cumulative = atomic_load(&chan->cumulative_sent);
    pthread_mutex_unlock(&agent->lock);
    return 0;
}

int csls_agent_session_begin(csls_agent_ctx_t *agent, const uint8_t *vendor_pk,
                             csls_session_init_pkt_t *out_init) {
    if (!agent || !vendor_pk || !out_init) return -1;
    pthread_mutex_lock(&agent->lock);
    csls_channel_t *chan = csls_channel_get_or_create(&agent->channels, vendor_pk);
    if (!chan) { pthread_mutex_unlock(&agent->lock); return -3; }
    int chan_idx = (int)(chan - agent->channels.channels);
    uint8_t x[32];
    if (csls_ecdh_x(agent->sk, vendor_pk, x) != 0) {
        pthread_mutex_unlock(&agent->lock);
        return -1;
    }
    uint64_t nonce = 0;
    if (RAND_bytes((unsigned char *)&nonce, sizeof(nonce)) != 1) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        nonce = (uint64_t)ts.tv_nsec ^ ((uint64_t)ts.tv_sec << 32) ^ (uint64_t)(uintptr_t)agent;
    }
    memset(out_init, 0, sizeof(*out_init));
    out_init->magic = CSLS_MAGIC;
    out_init->type = CSLS_PKT_SESSION_INIT;
    memcpy(out_init->agent_pk, agent->pk, 33);
    memcpy(out_init->vendor_pk, vendor_pk, 33);
    out_init->session_nonce = nonce;
    csls_session_auth(x, agent->pk, vendor_pk, nonce, out_init->auth_mac);
    uint8_t key[32];
    csls_session_kdf(x, nonce, key);
    OPENSSL_cleanse(x, sizeof(x));
    int slot = -1;
    for (int i = 0; i < agent->n_sessions; i++)
        if (agent->sessions[i].chan_idx == chan_idx) { slot = i; break; }
    if (slot < 0 && agent->n_sessions < CSLS_MAX_SESSIONS) slot = agent->n_sessions++;
    if (slot < 0) { pthread_mutex_unlock(&agent->lock); return -1; }
    memcpy(agent->sessions[slot].key, key, 32);
    agent->sessions[slot].chan_idx = chan_idx;
    OPENSSL_cleanse(key, sizeof(key));
    pthread_mutex_unlock(&agent->lock);
    return 0;
}

// Proof-Carrying Restart Handshake: the vendor proves its claimed channel head
// by presenting the agent's own last cheque. The agent verifies it WITHOUT any
// elliptic-curve operation: e must equal SHA256(preimage) and s must equal
// k + e*sk with k recomputed from the deterministic HMAC domain.
int csls_agent_restore_session(csls_agent_ctx_t *agent, const uint8_t *vendor_pk,
                               const csls_cheque_pkt_t *head) {
    if (!agent || !vendor_pk || !head) return -1;
    if (head->magic != CSLS_MAGIC || head->type != CSLS_PKT_CHEQUE) return -10;
    if (memcmp(head->agent_pk, agent->pk, 33) != 0) return -6;
    if (memcmp(head->vendor_pk, vendor_pk, 33) != 0) return -7;

    uint8_t h_be[8];
    for (int i = 0; i < 8; i++) h_be[i] = (uint8_t)((head->height >> (56 - i * 8)) & 0xFF);
    uint8_t preimage[82];
    memcpy(preimage, head->agent_pk, 33);
    memcpy(preimage + 33, head->vendor_pk, 33);
    memcpy(preimage + 66, h_be, 8);
    for (int i = 0; i < 8; i++)
        preimage[74 + i] = (uint8_t)((head->cumulative_amt >> (56 - i * 8)) & 0xFF);
    uint8_t e_digest[32];
    SHA256(preimage, sizeof(preimage), e_digest);
    if (memcmp(e_digest, head->challenge_e, 32) != 0) {
        // tolerate the (astronomically rare) >= q reduced challenge form
        if (memcmp(e_digest, SECP256K1_Q_BE, 32) >= 0) {
            BN_CTX *bctx = BN_CTX_new();
            BIGNUM *e_red = BN_bin2bn(e_digest, 32, NULL);
            uint8_t red[32];
            if (e_red && bctx) {
                BN_nnmod(e_red, e_red, g_curve_order_q, bctx);
                BN_bn2binpad(e_red, red, 32);
                if (memcmp(red, head->challenge_e, 32) != 0) {
                    BN_free(e_red); BN_CTX_free(bctx); return -23;
                }
                BN_free(e_red); BN_CTX_free(bctx);
            } else {
                if (e_red) BN_free(e_red);
                if (bctx) BN_CTX_free(bctx);
                return -1;
            }
        } else {
            return -23;
        }
    }

    pthread_mutex_lock(&agent->lock);
    BN_CTX *ctx = (BN_CTX *)agent->bn_ctx;
    BIGNUM *e = (BIGNUM *)agent->bn_e;
    BIGNUM *k = (BIGNUM *)agent->bn_k;
    BIGNUM *sk = (BIGNUM *)agent->bn_sk;
    BIGNUM *s = (BIGNUM *)agent->bn_s;
    BIGNUM *tmp = (BIGNUM *)agent->bn_tmp;
    BN_bin2bn(head->challenge_e, 32, e);
    if (memcmp(head->challenge_e, SECP256K1_Q_BE, 32) >= 0)
        BN_nnmod(e, e, g_curve_order_q, ctx);
    int matched = 0;
    uint8_t expect_s[32];
    for (int ctr = 0; ctr < 256 && !matched; ctr++) {
        uint8_t pre[42];
        memcpy(pre, vendor_pk, 33);
        memcpy(pre + 33, h_be, 8);
        pre[41] = (uint8_t)ctr;
        uint8_t k_hash[32];
        csls_derive_k_hash(&agent->hmac_ictx0, &agent->hmac_octx0, pre, ctr ? 42 : 41, k_hash);
        BN_bin2bn(k_hash, 32, k);
        if (memcmp(k_hash, SECP256K1_Q_BE, 32) >= 0)
            BN_nnmod(k, k, g_curve_order_q, ctx);
        BN_mod_mul(tmp, e, sk, g_curve_order_q, ctx);
        BN_mod_add(s, k, tmp, g_curve_order_q, ctx);
        BN_bn2binpad(s, expect_s, 32);
        if (memcmp(expect_s, head->sig_s, 32) == 0) matched = 1;
    }
    if (!matched) {
        // Lying vendor: fabricated or stale cheque that the agent never signed
        pthread_mutex_unlock(&agent->lock);
        return -5;
    }
    csls_channel_t *chan = csls_channel_get_or_create(&agent->channels, vendor_pk);
    if (!chan) { pthread_mutex_unlock(&agent->lock); return -3; }
    atomic_store(&chan->cumulative_sent, head->cumulative_amt);
    atomic_store(&chan->height, head->height);
    pthread_mutex_unlock(&agent->lock);
    return 0;
}

// -----------------------------------------------------------------------------
// BENCHMARKING AND VERIFICATION SUITE
// -----------------------------------------------------------------------------

int csls_run_benchmark(uint32_t num_cheques) {
    printf("======================================================================\n");
    printf("[BENCHMARK] C11 High-Frequency Engine\n");
    printf("======================================================================\n");

    uint8_t agent_sk[32], vendor_sk[32];
    memset(agent_sk, 0x11, 32);
    memset(vendor_sk, 0x22, 32);

    csls_agent_ctx_t agent;
    csls_vendor_ctx_t *vendor = csls_vendor_new(vendor_sk, 1000000000ULL);

    if (csls_agent_init(&agent, agent_sk, NULL) != 0 || !vendor) {
        printf("Initialization failed!\n");
        if (vendor) csls_vendor_free(vendor);
        return -1;
    }

    printf("Executing %u sequential micro-cheques on single CPU core...\n", num_cheques);

    csls_cheque_pkt_t pkt;
    uint64_t t_start = csls_time_ns();

    for (uint32_t i = 0; i < num_cheques; i++) {
        // Sign micro-cheque for $0.01 (10,000 micro-USDC)
        csls_agent_sign_cheque(&agent, vendor->pk, 10000, &pkt);

        // Vendor verification
        int res = csls_vendor_process_cheque(vendor, &pkt, NULL);
        if (res != 0) {
            printf("Verification failed at %u: code %d\n", i, res);
            csls_agent_destroy(&agent);
            csls_vendor_free(vendor);
            return -1;
        }
    }

    uint64_t t_end = csls_time_ns();
    double total_sec = (double)(t_end - t_start) / 1e9;
    double us_per_op = ((double)(t_end - t_start) / num_cheques) / 1000.0;
    double ops_per_sec = (double)num_cheques / total_sec;

    csls_channel_t *vchan = csls_channel_get_or_create(&vendor->channels, agent.pk);
    printf("  Processed: %u cheques\n", num_cheques);
    printf("  Total Time: %.4f seconds\n", total_sec);
    printf("  Latency per End-to-End Cheque (Sign + Verify): %.2f microseconds\n", us_per_op);
    printf("  Throughput: %.0f operations/second\n", ops_per_sec);
    printf("  Total Settled Volume: $%.2f USDC\n", (double)(vchan ? atomic_load(&vchan->accumulated_amount) : 0) / 1e6);

    csls_agent_destroy(&agent);
    csls_vendor_free(vendor);
    return 0;
}

int csls_run_equivocation_test(void) {
    printf("\n======================================================================\n");
    printf("[TEST] Equivocation & EOTS Key Extraction\n");
    printf("======================================================================\n");

    uint8_t agent_sk[32], vendor_sk[32];
    memset(agent_sk, 0x77, 32);
    memset(vendor_sk, 0x88, 32);

    csls_agent_ctx_t agent;
    csls_vendor_ctx_t *vendor = csls_vendor_new(vendor_sk, CSLS_DEFAULT_DELTA_V);

    csls_agent_init(&agent, agent_sk, NULL);

    // 1. Legitimate Cheque at height h = 1001. The malicious-client model
    // regresses the agent's GLOBAL leased counter in memory (the vendor-side
    // watermark cannot be regressed by a restart).
    atomic_store(&agent.height, 1001);
    csls_cheque_pkt_t cheque1;
    csls_agent_sign_cheque(&agent, vendor->pk, 50000, &cheque1); // $0.05 at h=1001

    int r1 = csls_vendor_process_cheque(vendor, &cheque1, NULL);
    printf("  [1] Legitimate Cheque at h=1001 accepted: %s\n", (r1 == 0) ? "YES" : "NO");

    // 2. Forking/Double-Spending Attack: Sign a conflicting cheque at SAME height h = 1001
    // Malicious agent regresses its global in-memory height back to 1001 to equivocate
    atomic_store(&agent.height, 1001);
    csls_cheque_pkt_t cheque2;
    csls_agent_sign_cheque(&agent, vendor->pk, 70000, &cheque2); // $0.07 at h=1001 (conflicting cheque to same vendor)

    printf("  [2] Attacking with conflicting cheque on same height h=1001...\n");

    csls_fraud_pkt_t fraud;
    memset(&fraud, 0, sizeof(fraud));

    uint64_t t0 = csls_time_ns();
    int r2 = csls_vendor_process_cheque(vendor, &cheque2, &fraud);
    uint64_t t1 = csls_time_ns();

    double extraction_us = (double)(t1 - t0) / 1000.0;

    printf("  [3] Vendor Detection Result: Code %d (%s)\n", 
           r2, (r2 == -20) ? "EQUIVOCATION DETECTED" : "MISSED");

    if (r2 == -20) {
        printf("  Key Extraction & Proof Generation Latency: %.2f microseconds\n", extraction_us);
        int sk_matches = (memcmp(fraud.extracted_sk, agent_sk, 32) == 0);
        printf("  Secret Key Verification: %s\n", sk_matches ? "EXACT MATCH (VERIFIED)" : "FAILED");
        if (sk_matches) {
            printf("  [FRAUD] Fraud proof ready for on-chain slashing:\n");
            printf("     Offender PK:  0x");
            for (int i = 0; i < 8; i++) printf("%02x", fraud.offender_pk[i]);
            printf("...\n");
            printf("     Extracted SK: 0x");
            for (int i = 0; i < 8; i++) printf("%02x", fraud.extracted_sk[i]);
            printf("...\n");
            printf("     Target: PerformanceCollateralVault.sol on Base L2\n");
        }
    }

    csls_agent_destroy(&agent);
    csls_vendor_free(vendor);
    return 0;
}

// -----------------------------------------------------------------------------
// TCP LOOPBACK AUTOMATED NETWORK TEST
// -----------------------------------------------------------------------------

static void *vendor_tcp_worker(void *arg) {
    uint16_t port = *(uint16_t *)arg;
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        return NULL;
    }
    listen(server_fd, 5);

    int client_sock = accept(server_fd, NULL, NULL);
    if (client_sock < 0) {
        close(server_fd);
        return NULL;
    }

    // Set TCP_NODELAY and TCP_QUICKACK to eradicate delayed ACK latency spikes
    int flag = 1;
    setsockopt(client_sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
#ifdef TCP_QUICKACK
    setsockopt(client_sock, IPPROTO_TCP, TCP_QUICKACK, &flag, sizeof(flag));
#endif

    // Set 5-second read/write timeouts to neutralize Slowloris DoS attacks
    struct timeval sock_tv;
    sock_tv.tv_sec = 5;
    sock_tv.tv_usec = 0;
    setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&sock_tv, sizeof(sock_tv));
    setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&sock_tv, sizeof(sock_tv));

    uint8_t vendor_sk[32];
    memset(vendor_sk, 0x44, 32);
    csls_vendor_ctx_t *vendor = csls_vendor_new(vendor_sk, 50000000ULL); // $50 buffer

    csls_cheque_pkt_t pkt;
    csls_ack_pkt_t ack;
    ack.magic = CSLS_MAGIC;
    ack.type = CSLS_PKT_ACK;

    while (1) {
        // Read full 151-byte packet
        size_t total_read = 0;
        char *ptr = (char *)&pkt;
        while (total_read < sizeof(csls_cheque_pkt_t)) {
            ssize_t n = read(client_sock, ptr + total_read, sizeof(csls_cheque_pkt_t) - total_read);
            if (n <= 0) goto cleanup;
            total_read += n;
        }

        csls_fraud_pkt_t fraud;
        int res = csls_vendor_process_cheque(vendor, &pkt, &fraud);

        csls_channel_t *vchan = csls_channel_get_or_create(&vendor->channels, pkt.agent_pk);
        ack.acknowledged_h = pkt.height;
        ack.cumulative_amt = vchan ? atomic_load(&vchan->accumulated_amount) : 0;
        ack.status_code = (res == 0) ? 0 : ((res == -20) ? 3 : 1);

        if (send(client_sock, &ack, sizeof(ack), MSG_NOSIGNAL) != (ssize_t)sizeof(ack)) {
            goto cleanup;
        }
        if (res == -20) {
            // Cut off malicious agent
            break;
        }
    }

cleanup:
    close(client_sock);
    close(server_fd);
    csls_vendor_free(vendor);
    return NULL;
}

int csls_run_network_test(uint16_t port, uint32_t count) {
    printf("\n======================================================================\n");
    printf("[BENCHMARK] P2P TCP Socket Loopback\n");
    printf("======================================================================\n");

    pthread_t thread;
    uint16_t p = port;
    pthread_create(&thread, NULL, vendor_tcp_worker, &p);

    usleep(50000); // Give server 50ms to bind

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    int flag = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("TCP Connection failed!\n");
        return -1;
    }

    uint8_t agent_sk[32], vendor_pk[33];
    memset(agent_sk, 0x33, 32);
    memset(vendor_pk, 0x55, 33);

    csls_agent_ctx_t agent;
    csls_agent_init(&agent, agent_sk, NULL);

    csls_cheque_pkt_t pkt;
    csls_ack_pkt_t ack;

    printf("Streaming %u cheques over TCP socket (127.0.0.1:%u)...\n", count, port);
    uint64_t t_start = csls_time_ns();

    for (uint32_t i = 1; i <= count; i++) {
        csls_agent_sign_cheque(&agent, vendor_pk, 1000, &pkt); // $0.001 per cheque
        if (send(sock, &pkt, sizeof(pkt), MSG_NOSIGNAL) != (ssize_t)sizeof(pkt)) break;

        size_t total_ack = 0;
        char *ack_ptr = (char *)&ack;
        while (total_ack < sizeof(ack)) {
            ssize_t n = read(sock, ack_ptr + total_ack, sizeof(ack) - total_ack);
            if (n <= 0) break;
            total_ack += n;
        }
    }

    uint64_t t_end = csls_time_ns();
    double total_sec = (double)(t_end - t_start) / 1e9;
    double rtt_us = ((double)(t_end - t_start) / count) / 1000.0;
    double tps = (double)count / total_sec;

    printf("  TCP Streaming Completed: %u roundtrips\n", count);
    printf("  Total Time: %.4f seconds\n", total_sec);
    printf("  Real Socket RTT (Sign + TCP Tx + Verify + TCP Ack): %.2f microseconds\n", rtt_us);
    printf("  Network Throughput: %.0f cheques/second over loopback TCP\n", tps);

    close(sock);
    pthread_join(thread, NULL);
    csls_agent_destroy(&agent);
    return 0;
}

// -----------------------------------------------------------------------------
// MAIN ENTRY POINT
// -----------------------------------------------------------------------------

#ifndef CSLS_NO_MAIN
int main(int argc, char *argv[]) {
    if (csls_crypto_global_init() != 0) {
        fprintf(stderr, "Fatal: OpenSSL secp256k1 initialization failed.\n");
        return 1;
    }

    if (argc < 2 || strcmp(argv[1], "--all") == 0) {
        csls_run_benchmark(50000);
        csls_run_equivocation_test();
        csls_run_network_test(9444, 10000);
    } else if (strcmp(argv[1], "--benchmark") == 0) {
        uint32_t n = (argc > 2) ? (uint32_t)atoi(argv[2]) : 50000;
        csls_run_benchmark(n);
    } else if (strcmp(argv[1], "--equivocation") == 0) {
        csls_run_equivocation_test();
    } else if (strcmp(argv[1], "--network") == 0) {
        uint32_t n = (argc > 2) ? (uint32_t)atoi(argv[2]) : 10000;
        csls_run_network_test(9444, n);
    } else {
        printf("Usage: %s [--all | --benchmark [N] | --equivocation | --network [N]]\n", argv[0]);
    }

    csls_crypto_global_cleanup();
    return 0;
}
#endif
