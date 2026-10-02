// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers
//
// CSLS Network Daemon (Terminal 1 / causal_term1_core)
//
// Standalone TCP frontend for the C11 clearing core. One vendor identity per
// process; connection threads share the internally-locked csls_vendor_ctx_t.
//
// WIRE PROTOCOL (per connection):
//   daemon -> client : csls_welcome_pkt_t       (38 B, vendor identity)
//   client -> daemon : csls_session_init_pkt_t  (95 B, ECDH-authenticated MAC session)
//   daemon -> client : csls_ack_pkt_t           (22 B, status_code 0=session established)
//   client -> daemon : csls_cheque_wire_t       (167 B: 151 B cheque + 16 B SipHash-128 MAC)
//   daemon -> client : csls_ack_pkt_t           (22 B)
//
// ACK status_code: 0=OK, 1=EXPOSURE_CAP_REACHED (-12), 2=REPLAY/OUT_OF_ORDER
// (-21/-22), 3=FRAUD_EQUIVOCATION (-20), 4=MAC_REJECTED (-24/-25),
// 5=INVALID_PACKET (everything else). Every status except 0 and 1 severs the
// connection immediately; status 3 additionally emits the fraud proof (log +
// fraud_cb) with the algebraically extracted secret key (AXIOM 6, O(1)).
//
// With --no-mac (enforce_mac=0) the daemon also accepts legacy 151-byte
// csls_cheque_pkt_t frames: the first short cheque frame adopts 151-byte
// framing for that connection after the 5-second frame deadline.

#ifndef CSLS_DAEMON_NET_H
#define CSLS_DAEMON_NET_H

#include <stdint.h>

#include "causal_daemon.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CSLS_DAEMON_DEFAULT_CONNS    64
#define CSLS_DAEMON_SOCK_TIMEOUT_SEC 5

typedef struct csls_daemon_cfg {
    uint16_t port;            // listen port (default CSLS_DEFAULT_PORT 9444)
    uint8_t  vendor_sk[32];   // vendor secret key, raw 32 bytes
    uint64_t delta_v;         // per-channel exposure cap, micro-USDC
    int      enforce_mac;     // 1 (default): SESSION_INIT + 167B MAC cheques required
    int      max_conns;       // concurrent connection cap (default 64)
    const char *bind_addr;    // "a.b.c.d" or NULL/"" for INADDR_ANY
    void   (*fraud_cb)(const csls_fraud_pkt_t *proof, void *user); // optional, conn thread
    void    *fraud_user;
} csls_daemon_cfg_t;

// Blocks until csls_daemon_stop() (or the stop signal via the binary's main).
// One daemon per process; returns 0 on graceful shutdown.
int  csls_daemon_run(const csls_daemon_cfg_t *cfg);

// Async-signal-safe: wakes the accept loop and all connection threads.
void csls_daemon_stop(void);

#ifdef __cplusplus
}
#endif

#endif // CSLS_DAEMON_NET_H
