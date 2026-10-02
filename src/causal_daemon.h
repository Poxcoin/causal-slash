// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Causal-Slash Protocol Developers
//
// Causal-Slash Protocol: High-Frequency M2M Micro-Payment Engine
// Optimistic P2P Credit Streaming Bounded by delta_v with O(1) Algebraic Equivocation Slashing
// Denominated strictly in USD / USDC (6 decimal places: 1,000,000 micro_usdc = $1.00)
//
// DURABILITY MODEL (P0, owner-approved):
//   Heights are leased from a GLOBAL monotonic counter backed by a Dual-Sector
//   Ping-Pong WAL (two 4096-byte sectors, CRC64, O_DSYNC). A lease of 1,000,000
//   heights is durable BEFORE any of its heights are used; the hot path performs
//   ZERO syscalls. On crash the agent resumes at reserved_height + 1, so a nonce
//   k = HMAC-SHA256(sk, PK_vendor || h) can NEVER repeat => honest-agent key
//   extraction (false slashing) is structurally impossible.

#ifndef CAUSAL_DAEMON_H
#define CAUSAL_DAEMON_H

#define OPENSSL_SUPPRESS_DEPRECATED
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <string.h>
#include <pthread.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/sha.h>

#define CSLS_MAGIC 0x43534C53 // "CSLS" in ASCII
#define CSLS_DEFAULT_PORT 9444

// Packet types
#define CSLS_PKT_CHEQUE       0x01
#define CSLS_PKT_ACK          0x02
#define CSLS_PKT_FRAUD        0x03
#define CSLS_PKT_HALT         0x04
#define CSLS_PKT_SESSION_INIT 0x05

// Error codes (negative returns)
#define CSLS_ERR_BAD_MAC    (-24) // missing/invalid session MAC (C2 gate)
#define CSLS_ERR_NO_SESSION (-25) // MAC signing requested without an established session
#define CSLS_ERR_WAL_FATAL  (-27) // both WAL sectors corrupt (fail-closed: refuse to sign)

// Exposure and Ring Buffer Constants
#define CSLS_DEFAULT_DELTA_V 1000000ULL // $1.00 USDC (6 decimals)
#define CSLS_HISTORY_SIZE    65536      // 64K entries circular window
#define CSLS_HISTORY_MASK    (CSLS_HISTORY_SIZE - 1)

// Watermark Lease (Dual-Sector Ping-Pong WAL)
#define CSLS_WAL_MAGIC            0x4353574CU // "CSWL"
#define CSLS_WAL_SECTOR           4096
#define CSLS_WAL_BLOCK            1000000ULL  // heights per durable lease
#define CSLS_WAL_REFILL_AT        500000ULL   // background refill threshold
#define CSLS_MAX_SESSIONS         16          // per-agent MAC sessions (sparse)
#define CSLS_REFILLER_RING        4096        // renewal work-queue capacity

#pragma pack(push, 1)

// 151-byte zero-copy streaming cheque packet
typedef struct {
    uint32_t magic;           // CSLS_MAGIC (0x43534C53)
    uint8_t  type;            // CSLS_PKT_CHEQUE (0x01)
    uint8_t  agent_pk[33];    // Compressed secp256k1 public key of agent
    uint8_t  vendor_pk[33];   // Compressed secp256k1 public key of vendor
    uint64_t height;          // Monotonically increasing height counter h
    uint64_t cumulative_amt;  // Cumulative micro-USDC (6 decimals, e.g. 10,000 = $0.01)
    uint8_t  challenge_e[32]; // Challenge hash scalar e mod q
    uint8_t  sig_s[32];       // EOTS Schnorr signature scalar s = (k + e * sk) mod q
} csls_cheque_pkt_t;

// 16-byte SipHash-2-4 session MAC riding after the 151-byte cheque on the wire
typedef struct {
    csls_cheque_pkt_t pkt;
    uint8_t           mac[16];
} csls_cheque_wire_t;

// Session bootstrap: authenticates the ECDH-derived session key.
// auth_mac = HMAC-SHA256(ecdh_x, agent_pk || vendor_pk || session_nonce)[0..15]
typedef struct {
    uint32_t magic;
    uint8_t  type;            // CSLS_PKT_SESSION_INIT
    uint8_t  agent_pk[33];
    uint8_t  vendor_pk[33];
    uint64_t session_nonce;
    uint8_t  auth_mac[16];
} csls_session_init_pkt_t;    // 95 bytes

// Acknowledgement packet sent by vendor to client
typedef struct {
    uint32_t magic;           // CSLS_MAGIC
    uint8_t  type;            // CSLS_PKT_ACK
    uint64_t acknowledged_h;  // Height acknowledged
    uint64_t cumulative_amt;  // Verified cumulative amount
    uint8_t  status_code;     // 0 = OK, 1 = EXPOSURE_CAP_REACHED, 2 = REPLAY, 3 = FRAUD
} csls_ack_pkt_t;

// Compact Fraud Proof containing extracted private key and conflicting cheques
typedef struct {
    uint32_t magic;           // CSLS_MAGIC
    uint8_t  type;            // CSLS_PKT_FRAUD
    uint8_t  offender_pk[33]; // Public key of offending agent
    uint64_t collision_h;     // Equivocation height h
    uint8_t  extracted_sk[32];// Algebraically extracted private key sk
    csls_cheque_pkt_t cheque1;// First signed cheque
    csls_cheque_pkt_t cheque2;// Conflicting signed cheque on same height
} csls_fraud_pkt_t;

// Dual-Sector Ping-Pong WAL sector (exactly one disk sector: torn-write proof).
// Authenticity: hmac = HMAC-SHA256(sk, "CSLS_WAL_INTEGRITY_v1" || magic ||
// sequence || reserved_height), compared in constant time (CRYPTO_memcmp).
// A local co-tenant without the agent's sk cannot forge a sector with a lowered
// reserved_height (Red Team P1: CRC-forgery AND wipe/truncate vectors closed).
// Owner-side forgery is self-harm (own key burns).
typedef struct {
    uint32_t magic;            // CSLS_WAL_MAGIC ("CSWL")
    uint32_t sequence;         // Monotonic lease version (odd/even => sector A/B)
    uint64_t reserved_height;  // Durable lease top; heights <= reserved are safe
    uint8_t  hmac[32];         // HMAC-SHA256(sk, domain || magic || seq || reserved)
    uint8_t  _pad[4048];
} csls_wal_sector_t;           // 4096 bytes

// Legacy per-signature WAL record (kept for ABI compatibility with old tooling)
typedef struct {
    uint8_t  peer_pk[33];
    uint64_t height;
    uint64_t cumulative_sent;
} csls_wal_record_t;

#pragma pack(pop)

#if defined(__GNUC__)
_Static_assert(sizeof(csls_wal_sector_t) == CSLS_WAL_SECTOR, "WAL sector must be 4096 bytes");
_Static_assert(sizeof(csls_session_init_pkt_t) == 95, "session init packet size drift");
#endif

// History entry for equivocation detection
typedef struct {
    uint8_t  agent_pk[33];
    uint64_t height;
    uint64_t amount;
    uint8_t  challenge_e[32];
    uint8_t  sig_s[32];
    bool     occupied;
    bool     disputed;   // fraud already proven for this (agent, height): fast -20,
                         // no re-extraction (trap-spam rate limit, Red Team P2)
} csls_history_entry_t;

// Multi-Channel O(1) State Table
#define CSLS_MAX_CHANNELS 1024
#define CSLS_CHANNEL_MASK (CSLS_MAX_CHANNELS - 1)

typedef struct {
    uint8_t  peer_pk[33];
    _Atomic uint64_t height;
    _Atomic uint64_t cumulative_sent;
    _Atomic uint64_t cleared_amount;
    _Atomic uint64_t accumulated_amount;
    pthread_spinlock_t lock;
    bool occupied;
} csls_channel_t;

typedef struct {
    csls_channel_t channels[CSLS_MAX_CHANNELS];
    size_t count;
} csls_channel_table_t;

// Per-channel vendor-side head state: last accepted cheque (restart handshake
// evidence) + session MAC key (C2). Indexed by the channel table slot index.
typedef struct {
    csls_cheque_pkt_t cheque;
    uint8_t           session_key[32];
    bool              valid;
    bool              mac_active;
} csls_head_t;

// Client (Agent) Context
typedef struct {
    uint8_t sk[32];
    uint8_t pk[33];
    uint8_t _pad[7];
    _Atomic uint64_t height;              // GLOBAL watermark-leased height (single source of truth)
    _Atomic uint64_t watermark_boundary;  // Durable lease top (UINT64_MAX without WAL)
    _Atomic int      wal_fatal;           // both sectors corrupt => fail-closed
    _Atomic int      renew_requested;
    uint64_t         cumulative_sent;
    csls_channel_table_t channels;
    char wal_path[256];
    int wal_fd;
    uint64_t wal_sequence;
    uint64_t wal_reserved;
    uint8_t *wal_buf;                     // 4096-aligned sector staging buffer
    pthread_mutex_t lease_mu;
    pthread_cond_t  lease_cv;
    SHA256_CTX hmac_ictx0, hmac_octx0;    // HMAC midstates (key = sk, constant)
    struct { int chan_idx; uint8_t key[32]; } sessions[CSLS_MAX_SESSIONS];
    int n_sessions;
    pthread_mutex_t lock;
    void *bn_ctx;
    void *bn_sk;
    void *bn_k;
    void *bn_e;
    void *bn_s;
    void *bn_tmp;
} csls_agent_ctx_t;

// Vendor Context
typedef struct {
    uint8_t sk[32];
    uint8_t pk[33];
    uint8_t _pad[7];
    uint64_t last_height;
    uint64_t cleared_amount;
    uint64_t accumulated_amount;
    uint64_t max_exposure_delta_v;
    uint64_t slot_seed;
    int      enforce_mac;                 // reject cheques without a valid session MAC
    csls_channel_table_t channels;
    pthread_mutex_t lock;
    csls_history_entry_t history[CSLS_HISTORY_SIZE];
    csls_head_t heads[CSLS_MAX_CHANNELS];
} csls_vendor_ctx_t;

// SplitMix64 history slot mixer to eliminate slot collisions across multi-agent streams
static inline uint32_t csls_slot_mix(uint64_t x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return (uint32_t)(x & CSLS_HISTORY_MASK);
}

static inline uint32_t csls_vendor_slot(uint64_t height, const uint8_t *agent_pk, const uint8_t *vendor_pk, uint64_t seed) {
    uint32_t agent_hash = 0;
    memcpy(&agent_hash, agent_pk + 1, 4);
    uint32_t vendor_hash = 0;
    memcpy(&vendor_hash, vendor_pk + 1, 4);
    return csls_slot_mix(height ^ (uint64_t)agent_hash ^ ((uint64_t)vendor_hash << 16) ^ seed);
}

// Channel Table API (O(1) Linear Probing)
void            csls_channel_table_init(csls_channel_table_t *table);
void            csls_channel_table_destroy(csls_channel_table_t *table);
csls_channel_t *csls_channel_get_or_create(csls_channel_table_t *table, const uint8_t *peer_pk);

// Core Protocol Functions
int  csls_crypto_global_init(void);
void csls_crypto_global_cleanup(void);

// Dynamic Memory Allocation Helpers (for cross-language FFI bindings)
csls_agent_ctx_t  *csls_agent_new(const uint8_t *sk_bytes, const char *wal_path);
void               csls_agent_free(csls_agent_ctx_t *agent);
csls_vendor_ctx_t *csls_vendor_new(const uint8_t *sk_bytes, uint64_t delta_v);
void               csls_vendor_free(csls_vendor_ctx_t *vendor);

// Agent API
int  csls_agent_init(csls_agent_ctx_t *agent, const uint8_t *sk_bytes, const char *wal_path);
void csls_agent_destroy(csls_agent_ctx_t *agent);
int  csls_agent_sign_cheque(csls_agent_ctx_t *agent, const uint8_t *vendor_pk,
                            uint64_t delta_micro_usdc, csls_cheque_pkt_t *out_pkt);
int  csls_agent_get_channel_state(csls_agent_ctx_t *agent, const uint8_t *vendor_pk,
                                  uint64_t *out_height, uint64_t *out_cumulative);

// Agent API: MAC session (C2) — wire = 151-byte cheque + 16-byte SipHash tag
int  csls_agent_session_begin(csls_agent_ctx_t *agent, const uint8_t *vendor_pk,
                              csls_session_init_pkt_t *out_init);
int  csls_agent_sign_cheque_mac(csls_agent_ctx_t *agent, const uint8_t *vendor_pk,
                                uint64_t delta_micro_usdc, csls_cheque_pkt_t *out_pkt,
                                uint8_t out_mac[16]);
// MAC an externally-built packet with the agent's own session key (insider statements)
int  csls_agent_mac_packet(csls_agent_ctx_t *agent, const uint8_t *vendor_pk,
                           const csls_cheque_pkt_t *pkt, uint8_t out_mac[16]);
// Proof-Carrying Restart Handshake: verify vendor's head cheque by nonce
// recomputation (pure bignum, no EC), then adopt its cumulative amount.
int  csls_agent_restore_session(csls_agent_ctx_t *agent, const uint8_t *vendor_pk,
                                const csls_cheque_pkt_t *head_cheque);

// Vendor API
int  csls_vendor_init(csls_vendor_ctx_t *vendor, const uint8_t *sk_bytes, uint64_t delta_v);
void csls_vendor_destroy(csls_vendor_ctx_t *vendor);
int  csls_vendor_process_cheque(csls_vendor_ctx_t *vendor, const csls_cheque_pkt_t *pkt,
                                csls_fraud_pkt_t *out_fraud);
int  csls_vendor_advance_cleared(csls_vendor_ctx_t *vendor, const uint8_t *agent_pk,
                                uint64_t cleared_amount);
int  csls_vendor_get_channel_state(csls_vendor_ctx_t *vendor, const uint8_t *agent_pk,
                                  uint64_t *out_height, uint64_t *out_accumulated, uint64_t *out_cleared);

// Vendor API: MAC enforcement (C2)
int  csls_vendor_enable_mac(csls_vendor_ctx_t *vendor, int enable);
int  csls_vendor_session_init(csls_vendor_ctx_t *vendor, const csls_session_init_pkt_t *init);
int  csls_vendor_process_cheque_mac(csls_vendor_ctx_t *vendor, const csls_cheque_pkt_t *pkt,
                                    const uint8_t mac[16], csls_fraud_pkt_t *out_fraud);
// Head cheque for the Proof-Carrying Restart Handshake
int  csls_vendor_get_head_cheque(csls_vendor_ctx_t *vendor, const uint8_t *agent_pk,
                                 csls_cheque_pkt_t *out_cheque);

// Mathematical EOTS Slashing Engine
int  csls_extract_private_key(const csls_cheque_pkt_t *c1, const csls_cheque_pkt_t *c2,
                              uint8_t *out_sk);

// Verification and Diagnostics
int  csls_run_benchmark(uint32_t num_cheques);
int  csls_run_equivocation_test(void);
int  csls_run_network_test(uint16_t port, uint32_t count);

#endif // CAUSAL_DAEMON_H
