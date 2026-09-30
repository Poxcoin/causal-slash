// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers
//
// Causal-Slash Protocol: High-Frequency M2M Micro-Payment Engine
// Optimistic P2P Credit Streaming Bounded by delta_v with O(1) Algebraic Equivocation Slashing
// Denominated strictly in USD / USDC (6 decimal places: 1,000,000 micro_usdc = $1.00)

#ifndef CAUSAL_DAEMON_H
#define CAUSAL_DAEMON_H

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

#define CSLS_MAGIC 0x43534C53 // "CSLS" in ASCII
#define CSLS_DEFAULT_PORT 9444

// Packet types
#define CSLS_PKT_CHEQUE 0x01
#define CSLS_PKT_ACK    0x02
#define CSLS_PKT_FRAUD  0x03
#define CSLS_PKT_HALT   0x04

// Exposure and Ring Buffer Constants
#define CSLS_DEFAULT_DELTA_V 1000000ULL // $1.00 USDC (6 decimals)
#define CSLS_HISTORY_SIZE    65536      // 64K entries circular window
#define CSLS_HISTORY_MASK    (CSLS_HISTORY_SIZE - 1)

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

#pragma pack(pop)

// History entry for equivocation detection
typedef struct {
    uint64_t height;
    uint64_t amount;
    uint8_t  challenge_e[32];
    uint8_t  sig_s[32];
    bool     occupied;
} csls_history_entry_t;

// Client (Agent) Context
typedef struct {
    uint8_t sk[32];
    uint8_t pk[33];
    _Atomic uint64_t height;
    uint64_t cumulative_sent;
    char wal_path[256];
    int wal_fd;
    pthread_mutex_t lock;
} csls_agent_ctx_t;

// Vendor Context
typedef struct {
    uint8_t sk[32];
    uint8_t pk[33];
    uint64_t last_height;
    uint64_t cleared_amount;
    uint64_t accumulated_amount;
    uint64_t max_exposure_delta_v;
    csls_history_entry_t history[CSLS_HISTORY_SIZE];
} csls_vendor_ctx_t;

// Core Protocol Functions
int  csls_crypto_global_init(void);
void csls_crypto_global_cleanup(void);

// Agent API
int  csls_agent_init(csls_agent_ctx_t *agent, const uint8_t *sk_bytes, const char *wal_path);
void csls_agent_destroy(csls_agent_ctx_t *agent);
int  csls_agent_sign_cheque(csls_agent_ctx_t *agent, const uint8_t *vendor_pk, 
                            uint64_t delta_micro_usdc, csls_cheque_pkt_t *out_pkt);

// Vendor API
int  csls_vendor_init(csls_vendor_ctx_t *vendor, const uint8_t *sk_bytes, uint64_t delta_v);
void csls_vendor_destroy(csls_vendor_ctx_t *vendor);
int  csls_vendor_process_cheque(csls_vendor_ctx_t *vendor, const csls_cheque_pkt_t *pkt, 
                                csls_fraud_pkt_t *out_fraud);

// Mathematical EOTS Slashing Engine
int  csls_extract_private_key(const csls_cheque_pkt_t *c1, const csls_cheque_pkt_t *c2, 
                              uint8_t *out_sk);

// Verification and Diagnostics
int  csls_run_benchmark(uint32_t num_cheques);
int  csls_run_equivocation_test(void);
int  csls_start_vendor_daemon(uint16_t port, uint64_t delta_v);
int  csls_run_agent_client(const char *host, uint16_t port, uint32_t count, uint64_t delta_micro_usdc);

#endif // CAUSAL_DAEMON_H
