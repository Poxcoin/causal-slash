// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers
//
// Live loopback TCP test for the CSLS network daemon (Terminal 1).
// The daemon runs in-process on a real listening socket (csls_daemon_run in a
// pthread, zero mocks), clients speak the real wire protocol over 127.0.0.1.
//
// Scenarios:
//   S1  welcome frame + SESSION_INIT + 2000 streaming 167 B MAC cheques -> ACK 0
//   S2  replay of an already-accepted cheque        -> ACK 2 + connection severed
//   S3  double-sign at the same height (equivocation) -> ACK 3 + severed +
//       fraud_cb proof with the EXACT agent secret key (AXIOM 6)
//   S4  outsider cheque without a session (garbage MAC) -> ACK 4 + severed
//   S5  spoofed SESSION_INIT (wrong auth_mac)        -> ACK 4 + severed
//   S6  exposure cap (--buffer) exceeded            -> ACK 1, connection alive
//   S7  legacy 151 B frame under MAC enforcement    -> severed, no ACK (anti-Slowloris)
//
// Build: gcc -DCSLS_NO_MAIN -DCSLS_DAEMON_NO_MAIN test_csls_daemon_net.c
//            src/causal_daemon.c src/csls_daemon.c -lcrypto -lpthread

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "causal_daemon.h"
#include "csls_daemon.h"

#define TEST_PORT 19444

#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "[TEST-FAIL] %s:%d: ", __FILE__, __LINE__);        \
            fprintf(stderr, __VA_ARGS__);                                      \
            fprintf(stderr, "\n");                                             \
            exit(1);                                                           \
        }                                                                      \
    } while (0)

static int64_t t_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000ll + (int64_t)ts.tv_nsec;
}

// ---- daemon harness ---------------------------------------------------------

static csls_daemon_cfg_t g_cfg;
static int g_run_rc = -12345;

static void *daemon_thread(void *arg) {
    (void)arg;
    g_run_rc = csls_daemon_run(&g_cfg);
    return NULL;
}

static pthread_mutex_t g_fraud_mu = PTHREAD_MUTEX_INITIALIZER;
static csls_fraud_pkt_t g_fraud;
static int g_fraud_seen = 0;

static void on_fraud(const csls_fraud_pkt_t *proof, void *user) {
    (void)user;
    pthread_mutex_lock(&g_fraud_mu);
    g_fraud = *proof;
    g_fraud_seen = 1;
    pthread_mutex_unlock(&g_fraud_mu);
}

// ---- wire helpers -----------------------------------------------------------

static int tcp_connect(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        close(fd);
        return -1;
    }
    int f = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &f, sizeof(f));
    struct timeval tv;
    tv.tv_sec = 8;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
    return fd;
}

static int rx_exact(int fd, void *buf, size_t n) {
    uint8_t *p = (uint8_t *)buf;
    size_t off = 0;
    while (off < n) {
        ssize_t r = recv(fd, p + off, n - off, 0);
        if (r <= 0) {
            if (r < 0 && errno == EINTR) continue;
            return -1;
        }
        off += (size_t)r;
    }
    return 0;
}

static int tx_all(int fd, const void *buf, size_t n) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0;
    while (off < n) {
        ssize_t s = send(fd, p + off, n - off, MSG_NOSIGNAL);
        if (s < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)s;
    }
    return 0;
}

// Expect orderly EOF (connection severed) within the socket timeout.
static ssize_t expect_severed(int fd) {
    char sink[64];
    return recv(fd, sink, sizeof(sink), 0);
}

static void open_session(int fd, csls_agent_ctx_t *agent, const uint8_t *vendor_pk,
                         csls_session_init_pkt_t *init) {
    CHECK(csls_agent_session_begin(agent, vendor_pk, init) == 0,
          "agent session_begin failed");
    CHECK(tx_all(fd, init, sizeof(*init)) == 0, "failed to send SESSION_INIT");
    csls_ack_pkt_t ack;
    CHECK(rx_exact(fd, &ack, sizeof(ack)) == 0, "no ACK for SESSION_INIT");
    CHECK(ack.magic == CSLS_MAGIC && ack.type == CSLS_PKT_ACK,
          "malformed ACK for SESSION_INIT");
    CHECK(ack.status_code == 0, "SESSION_INIT rejected, status=%u", ack.status_code);
}

static void build_wire(csls_cheque_wire_t *wire, const csls_cheque_pkt_t *pkt,
                       const uint8_t mac[16]) {
    memcpy(&wire->pkt, pkt, sizeof(*pkt));
    memcpy(wire->mac, mac, 16);
}

int main(void) {
    printf("======================================================================\n");
    printf("[TEST] CSLS Network Daemon — live loopback TCP (port %d)\n", TEST_PORT);
    printf("======================================================================\n");

    CHECK(csls_crypto_global_init() == 0, "crypto global init failed");

    // Daemon config: $50 exposure buffer, MAC enforcement ON (боевой режим).
    memset(&g_cfg, 0, sizeof(g_cfg));
    g_cfg.port = TEST_PORT;
    memset(g_cfg.vendor_sk, 0x44, 32);
    g_cfg.delta_v = 50000000ULL; // $50.00
    g_cfg.enforce_mac = 1;
    g_cfg.max_conns = 64;
    g_cfg.fraud_cb = on_fraud;

    // Expected vendor identity for the welcome frame.
    csls_vendor_ctx_t *probe = csls_vendor_new(g_cfg.vendor_sk, 1000);
    CHECK(probe != NULL, "probe vendor alloc failed");
    uint8_t vendor_pk[33];
    memcpy(vendor_pk, probe->pk, 33);
    csls_vendor_free(probe);

    pthread_t dth;
    CHECK(pthread_create(&dth, NULL, daemon_thread, NULL) == 0, "daemon thread failed");

    // Wait for the listener.
    int fd = -1;
    for (int i = 0; i < 250; i++) {
        fd = tcp_connect((uint16_t)TEST_PORT);
        if (fd >= 0) break;
        usleep(20000);
    }
    CHECK(fd >= 0, "daemon did not come up on port %d", TEST_PORT);

    // ---- S1: welcome + session + honest streaming ---------------------------
    csls_welcome_pkt_t w;
    CHECK(rx_exact(fd, &w, sizeof(w)) == 0, "no welcome frame");
    CHECK(w.magic == CSLS_MAGIC && w.type == CSLS_PKT_WELCOME, "bad welcome header");
    CHECK(memcmp(w.vendor_pk, vendor_pk, 33) == 0, "welcome vendor_pk mismatch");

    csls_agent_ctx_t agent;
    uint8_t agent_sk[32];
    memset(agent_sk, 0x33, 32);
    CHECK(csls_agent_init(&agent, agent_sk, NULL) == 0, "agent init failed");

    csls_session_init_pkt_t init;
    open_session(fd, &agent, vendor_pk, &init);

    const int N = 2000;
    uint64_t t0 = (uint64_t)t_now_ns();
    csls_cheque_wire_t last_wire;
    memset(&last_wire, 0, sizeof(last_wire));
    csls_cheque_pkt_t last_pkt;
    for (int i = 0; i < N; i++) {
        uint8_t mac[16];
        CHECK(csls_agent_sign_cheque_mac(&agent, vendor_pk, 1000, &last_pkt, mac) == 0,
              "sign failed at i=%d", i);
        build_wire(&last_wire, &last_pkt, mac);
        CHECK(tx_all(fd, &last_wire, sizeof(last_wire)) == 0, "send failed at i=%d", i);
        csls_ack_pkt_t ack;
        CHECK(rx_exact(fd, &ack, sizeof(ack)) == 0, "no ACK at i=%d", i);
        CHECK(ack.status_code == 0, "cheque %d rejected, status=%u", i, ack.status_code);
        CHECK(ack.acknowledged_h == last_pkt.height,
              "ACK h=%llu != signed h=%llu",
              (unsigned long long)ack.acknowledged_h, (unsigned long long)last_pkt.height);
        CHECK(ack.cumulative_amt == last_pkt.cumulative_amt, "ACK cumulative mismatch");
    }
    uint64_t t1 = (uint64_t)t_now_ns();
    double sec = (double)(t1 - t0) / 1e9;
    double rtt_us = (double)(t1 - t0) / (double)N / 1000.0;
    printf("  [S1] %d MAC cheques streamed: 0 rejects, avg RTT %.2f us, %.0f cheques/s\n",
           N, rtt_us, (double)N / sec);

    // ---- S2: replay of an accepted cheque -> ACK 2 + sever ------------------
    CHECK(tx_all(fd, &last_wire, sizeof(last_wire)) == 0, "replay send failed");
    csls_ack_pkt_t ack;
    CHECK(rx_exact(fd, &ack, sizeof(ack)) == 0, "no ACK for replay");
    CHECK(ack.status_code == 2, "replay not flagged as REPLAY, status=%u", ack.status_code);
    CHECK(expect_severed(fd) == 0, "connection not severed after replay");
    close(fd);
    printf("  [S2] replay rejected (status 2), connection severed\n");

    // ---- S3: equivocation (double-sign) -> ACK 3 + proof with exact sk ------
    fd = tcp_connect((uint16_t)TEST_PORT);
    CHECK(fd >= 0, "reconnect for S3 failed");
    CHECK(rx_exact(fd, &w, sizeof(w)) == 0, "no welcome for S3");
    open_session(fd, &agent, vendor_pk, &init);

    uint8_t mac[16];
    csls_cheque_pkt_t base;
    CHECK(csls_agent_sign_cheque_mac(&agent, vendor_pk, 1000, &base, mac) == 0, "S3 base sign");
    csls_cheque_wire_t base_wire;
    build_wire(&base_wire, &base, mac);
    CHECK(tx_all(fd, &base_wire, sizeof(base_wire)) == 0, "S3 base send");
    CHECK(rx_exact(fd, &ack, sizeof(ack)) == 0 && ack.status_code == 0, "S3 base rejected");

    uint64_t h_conflict = base.height;
    atomic_store(&agent.height, h_conflict); // malicious height regression
    csls_cheque_pkt_t conflict;
    CHECK(csls_agent_sign_cheque_mac(&agent, vendor_pk, 7777, &conflict, mac) == 0,
          "S3 conflict sign");
    CHECK(conflict.height == h_conflict, "conflict height drifted");
    csls_cheque_wire_t conflict_wire;
    build_wire(&conflict_wire, &conflict, mac);

    t0 = (uint64_t)t_now_ns();
    CHECK(tx_all(fd, &conflict_wire, sizeof(conflict_wire)) == 0, "S3 conflict send");
    CHECK(rx_exact(fd, &ack, sizeof(ack)) == 0, "no ACK for double-sign");
    t1 = (uint64_t)t_now_ns();
    CHECK(ack.status_code == 3, "double-sign not flagged as FRAUD, status=%u", ack.status_code);
    CHECK(expect_severed(fd) == 0, "connection not severed after double-sign");
    close(fd);
    printf("  [S3] double-sign caught at h=%llu, detect+extract RTT %.1f us, conn severed\n",
           (unsigned long long)h_conflict, (double)(t1 - t0) / 1000.0);

    for (int i = 0; i < 200; i++) { // up to 2 s
        pthread_mutex_lock(&g_fraud_mu);
        int seen_now = g_fraud_seen;
        pthread_mutex_unlock(&g_fraud_mu);
        if (seen_now) break;
        usleep(10000);
    }
    pthread_mutex_lock(&g_fraud_mu);
    int seen = g_fraud_seen;
    csls_fraud_pkt_t proof = g_fraud;
    pthread_mutex_unlock(&g_fraud_mu);
    CHECK(seen, "fraud_cb was not invoked");
    CHECK(memcmp(proof.extracted_sk, agent_sk, 32) == 0,
          "EXTRACTED SK DOES NOT MATCH the offender key (AXIOM 6 violated?)");
    CHECK(proof.collision_h == h_conflict, "fraud collision_h mismatch");
    CHECK(memcmp(proof.cheque2.sig_s, conflict.sig_s, 32) == 0, "fraud cheque2 mismatch");
    printf("  [S3] fraud proof verified: extracted sk == agent sk, collision h=%llu\n",
           (unsigned long long)proof.collision_h);

    // ---- S4: outsider cheque without a session (garbage MAC) ----------------
    fd = tcp_connect((uint16_t)TEST_PORT);
    CHECK(fd >= 0, "reconnect for S4 failed");
    CHECK(rx_exact(fd, &w, sizeof(w)) == 0, "no welcome for S4");
    csls_cheque_wire_t outsider;
    memset(&outsider, 0x5A, sizeof(outsider));
    outsider.pkt.magic = CSLS_MAGIC;
    outsider.pkt.type = CSLS_PKT_CHEQUE;
    memcpy(outsider.pkt.vendor_pk, vendor_pk, 33);
    outsider.pkt.height = 999999;
    outsider.pkt.cumulative_amt = 1;
    CHECK(tx_all(fd, &outsider, sizeof(outsider)) == 0, "S4 send");
    CHECK(rx_exact(fd, &ack, sizeof(ack)) == 0, "no ACK for outsider");
    CHECK(ack.status_code == 4, "outsider not MAC-rejected, status=%u", ack.status_code);
    CHECK(expect_severed(fd) == 0, "outsider connection not severed");
    close(fd);
    printf("  [S4] outsider garbage-MAC cheque rejected (status 4), conn severed\n");

    // ---- S5: spoofed SESSION_INIT (valid EC pk, wrong auth_mac) -------------
    // The attacker claims a real agent identity but cannot produce the
    // ECDH-derived auth_mac: the vendor must reject on the MAC gate (-24).
    csls_agent_ctx_t agent_c;
    uint8_t agent_c_sk[32];
    memset(agent_c_sk, 0x88, 32);
    CHECK(csls_agent_init(&agent_c, agent_c_sk, NULL) == 0, "agent C init failed");
    fd = tcp_connect((uint16_t)TEST_PORT);
    CHECK(fd >= 0, "reconnect for S5 failed");
    CHECK(rx_exact(fd, &w, sizeof(w)) == 0, "no welcome for S5");
    csls_session_init_pkt_t spoof;
    memset(&spoof, 0, sizeof(spoof));
    spoof.magic = CSLS_MAGIC;
    spoof.type = CSLS_PKT_SESSION_INIT;
    memcpy(spoof.agent_pk, agent_c.pk, 33); // valid point, wrong key holder
    memcpy(spoof.vendor_pk, vendor_pk, 33);
    spoof.session_nonce = 1;
    memset(spoof.auth_mac, 0xAB, 16);
    CHECK(tx_all(fd, &spoof, sizeof(spoof)) == 0, "S5 send");
    CHECK(rx_exact(fd, &ack, sizeof(ack)) == 0, "no ACK for spoofed INIT");
    CHECK(ack.status_code == 4, "spoofed INIT not rejected, status=%u", ack.status_code);
    CHECK(expect_severed(fd) == 0, "spoofed INIT connection not severed");
    close(fd);
    csls_agent_destroy(&agent_c);
    printf("  [S5] spoofed SESSION_INIT rejected (status 4), conn severed\n");

    // ---- S6: exposure cap reached -> ACK 1, connection stays alive ----------
    csls_agent_ctx_t agent_b;
    uint8_t agent_b_sk[32];
    memset(agent_b_sk, 0x77, 32);
    CHECK(csls_agent_init(&agent_b, agent_b_sk, NULL) == 0, "agent B init failed");
    fd = tcp_connect((uint16_t)TEST_PORT);
    CHECK(fd >= 0, "reconnect for S6 failed");
    CHECK(rx_exact(fd, &w, sizeof(w)) == 0, "no welcome for S6");
    open_session(fd, &agent_b, vendor_pk, &init);

    csls_cheque_pkt_t big;
    uint8_t big_mac[16];
    CHECK(csls_agent_sign_cheque_mac(&agent_b, vendor_pk, 60000000ULL, &big, big_mac) == 0,
          "S6 sign ($60 > $50 cap)");
    csls_cheque_wire_t big_wire;
    build_wire(&big_wire, &big, big_mac);
    CHECK(tx_all(fd, &big_wire, sizeof(big_wire)) == 0, "S6 send");
    CHECK(rx_exact(fd, &ack, sizeof(ack)) == 0, "no ACK for S6");
    CHECK(ack.status_code == 1, "exposure cap not reported, status=%u", ack.status_code);

    // Connection must survive the cap halt: next small cheque still capped.
    csls_cheque_pkt_t small;
    uint8_t small_mac[16];
    CHECK(csls_agent_sign_cheque_mac(&agent_b, vendor_pk, 1, &small, small_mac) == 0, "S6 sign2");
    csls_cheque_wire_t small_wire;
    build_wire(&small_wire, &small, small_mac);
    CHECK(tx_all(fd, &small_wire, sizeof(small_wire)) == 0, "S6 send2");
    CHECK(rx_exact(fd, &ack, sizeof(ack)) == 0, "no ACK for S6 #2");
    CHECK(ack.status_code == 1, "second cap cheque status=%u", ack.status_code);
    close(fd);
    csls_agent_destroy(&agent_b);
    printf("  [S6] exposure cap enforced (status 1), connection kept alive\n");

    // ---- S7: legacy 151 B frame under MAC enforcement -> silent sever -------
    fd = tcp_connect((uint16_t)TEST_PORT);
    CHECK(fd >= 0, "reconnect for S7 failed");
    CHECK(rx_exact(fd, &w, sizeof(w)) == 0, "no welcome for S7");
    csls_cheque_pkt_t legacy;
    memset(&legacy, 0, sizeof(legacy));
    legacy.magic = CSLS_MAGIC;
    legacy.type = CSLS_PKT_CHEQUE;
    memset(legacy.agent_pk, 0x66, 33);
    memcpy(legacy.vendor_pk, vendor_pk, 33);
    legacy.height = 1;
    legacy.cumulative_amt = 100;
    CHECK(tx_all(fd, &legacy, sizeof(legacy)) == 0, "S7 send");
    int64_t s7_t0 = t_now_ns();
    ssize_t rn = expect_severed(fd); // no ACK: short frame -> 5 s deadline -> sever
    int64_t s7_t1 = t_now_ns();
    CHECK(rn == 0, "legacy short frame must be severed without ACK (rn=%zd)", rn);
    close(fd);
    printf("  [S7] legacy 151 B frame under MAC mode severed with no ACK (after %.1f s)\n",
           (double)(s7_t1 - s7_t0) / 1e9);

    // ---- shutdown: graceful drain, no leaks, clean exit ---------------------
    csls_daemon_stop();
    pthread_join(dth, NULL);
    CHECK(g_run_rc == 0, "daemon run rc=%d", g_run_rc);
    csls_agent_destroy(&agent);
    csls_crypto_global_cleanup();

    printf("----------------------------------------------------------------------\n");
    printf("[TEST] ALL SCENARIOS PASS — daemon drained cleanly (rc=0)\n");
    return 0;
}
