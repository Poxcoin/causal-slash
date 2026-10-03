// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers
//
// RED TEAM PoC (Terminal 3): Schnorr EOTS double-signing against the LIVE
// csls_daemon wire protocol + Bloodhound O(1) key extraction timing.
//
// Vectors:
//   E1  honest baseline: SESSION_INIT + 100 MAC cheques over real TCP
//   E2  equivocation: two conflicting cheques at the SAME channel height
//       (deterministic nonce => same R-point), different cumulative amounts,
//       delivered over TWO DIFFERENT TCP connections -> vendor must catch the
//       second cheque (-20), sever the fraudster, and emit a fraud proof whose
//       extracted_sk equals the offender's real secret key (AXIOM 6)
//   E3  replay of an accepted cheque over a fresh connection -> -21 + sever
//   E4  O(1) gate: 1000x csls_extract_private_key + bloodhound_inspect_packet
//       must average < 500 microseconds (contract: ~320 us)
//
// Repro:
//   gcc -O2 -Wall -Wextra -Isrc -DCSLS_NO_MAIN -DCSLS_DAEMON_NO_MAIN
//       test/c/poc_tcp_eots.c src/causal_daemon.c src/schnorr_bloodhound.c
//       src/csls_daemon.c -lcrypto -lpthread -o /tmp/poc_tcp_eots && /tmp/poc_tcp_eots

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
#include "schnorr_bloodhound.h"

#define EOTS_PORT 19512

#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "[POC-FAIL] %s:%d: ", __FILE__, __LINE__);         \
            fprintf(stderr, __VA_ARGS__);                                      \
            fprintf(stderr, "\n");                                             \
            exit(1);                                                           \
        }                                                                      \
    } while (0)

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

static int64_t t_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000ll + (int64_t)ts.tv_nsec;
}

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

static ssize_t expect_severed(int fd) {
    char sink[64];
    return recv(fd, sink, sizeof(sink), 0);
}

// open a fresh connection and establish an authenticated MAC session
static int open_attacker_session(uint16_t port, const uint8_t *vendor_pk,
                                 csls_agent_ctx_t *agent, const uint8_t *agent_sk) {
    int fd = tcp_connect(port);
    CHECK(fd >= 0, "connect");
    csls_welcome_pkt_t w;
    CHECK(rx_exact(fd, &w, sizeof(w)) == 0, "welcome");
    CHECK(w.magic == CSLS_MAGIC && w.type == CSLS_PKT_WELCOME, "welcome header");
    CHECK(csls_agent_init(agent, agent_sk, NULL) == 0, "agent init");
    csls_session_init_pkt_t init;
    CHECK(csls_agent_session_begin(agent, vendor_pk, &init) == 0, "session begin");
    CHECK(tx_all(fd, &init, sizeof(init)) == 0, "send init");
    csls_ack_pkt_t ack;
    CHECK(rx_exact(fd, &ack, sizeof(ack)) == 0, "init ACK");
    CHECK(ack.status_code == 0, "init rejected %u", ack.status_code);
    return fd;
}

static void send_cheque(int fd, csls_agent_ctx_t *agent, const uint8_t *vendor_pk,
                        uint64_t delta, csls_cheque_wire_t *out_wire,
                        csls_cheque_pkt_t *out_pkt) {
    uint8_t mac[16];
    CHECK(csls_agent_sign_cheque_mac(agent, vendor_pk, delta, out_pkt, mac) == 0, "sign");
    memcpy(&out_wire->pkt, out_pkt, sizeof(*out_pkt));
    memcpy(out_wire->mac, mac, 16);
    CHECK(tx_all(fd, out_wire, sizeof(*out_wire)) == 0, "send wire");
}

int main(void) {
    printf("======================================================================\n");
    printf("[RED TEAM PoC] EOTS double-sign vs live daemon (port %d)\n", EOTS_PORT);
    printf("======================================================================\n");

    CHECK(csls_crypto_global_init() == 0, "crypto init");

    memset(&g_cfg, 0, sizeof(g_cfg));
    g_cfg.port = EOTS_PORT;
    memset(g_cfg.vendor_sk, 0x44, 32);
    g_cfg.delta_v = 50000000ULL; // $50 exposure buffer
    g_cfg.enforce_mac = 1;
    g_cfg.max_conns = 64;
    g_cfg.fraud_cb = on_fraud;

    csls_vendor_ctx_t *probe = csls_vendor_new(g_cfg.vendor_sk, 1000);
    CHECK(probe != NULL, "probe vendor");
    uint8_t vendor_pk[33];
    memcpy(vendor_pk, probe->pk, 33);
    csls_vendor_free(probe);

    pthread_t dth;
    CHECK(pthread_create(&dth, NULL, daemon_thread, NULL) == 0, "daemon thread");
    int fd = -1;
    for (int i = 0; i < 250; i++) {
        fd = tcp_connect((uint16_t)EOTS_PORT);
        if (fd >= 0) break;
        usleep(20000);
    }
    CHECK(fd >= 0, "daemon did not come up");
    close(fd);

    uint8_t agent_sk[32];
    memset(agent_sk, 0x33, 32);

    // ---- E1: honest baseline -------------------------------------------------
    csls_agent_ctx_t agent;
    fd = open_attacker_session((uint16_t)EOTS_PORT, vendor_pk, &agent, agent_sk);
    csls_cheque_wire_t wire, last_wire;
    csls_cheque_pkt_t pkt, last_pkt;
    csls_ack_pkt_t ack;
    memset(&last_wire, 0, sizeof(last_wire));
    memset(&last_pkt, 0, sizeof(last_pkt));

    int64_t t0 = t_now_ns();
    for (int i = 0; i < 100; i++) {
        send_cheque(fd, &agent, vendor_pk, 1000, &wire, &pkt);
        CHECK(rx_exact(fd, &ack, sizeof(ack)) == 0, "E1 ACK %d", i);
        CHECK(ack.status_code == 0, "E1 cheque %d rejected %u", i, ack.status_code);
        last_wire = wire;
        last_pkt = pkt;
    }
    int64_t rtt_us = (t_now_ns() - t0) / 1000 / 100;
    printf("  [E1] 100 honest MAC cheques settled, avg RTT %lld us\n", (long long)rtt_us);

    // ---- E2: equivocation across two DIFFERENT TCP connections ---------------
    send_cheque(fd, &agent, vendor_pk, 1000, &wire, &pkt);
    CHECK(rx_exact(fd, &ack, sizeof(ack)) == 0 && ack.status_code == 0, "E2 base");
    uint64_t h_conflict = pkt.height;

    // Second connection, same offender: deterministic nonce k = HMAC(sk, vendor||h)
    // makes the second cheque at the same height reuse the same R-point.
    int fd2 = open_attacker_session((uint16_t)EOTS_PORT, vendor_pk, &agent, agent_sk);
    atomic_store(&agent.height, h_conflict); // malicious height regression
    send_cheque(fd2, &agent, vendor_pk, 7777, &wire, &pkt);
    CHECK(pkt.height == h_conflict, "E2 height drifted");
    t0 = t_now_ns();
    CHECK(rx_exact(fd2, &ack, sizeof(ack)) == 0, "E2 no ACK");
    int64_t detect_us = (t_now_ns() - t0) / 1000;
    CHECK(ack.status_code == 3, "E2 double-sign NOT flagged (status=%u) — VULN!", ack.status_code);
    CHECK(expect_severed(fd2) == 0, "E2 fraudster connection not severed");
    close(fd2);
    printf("  [E2] cross-connection double-sign caught at h=%llu, detect+extract %lld us\n",
           (unsigned long long)h_conflict, (long long)detect_us);

    for (int i = 0; i < 200 && !g_fraud_seen; i++) {
        pthread_mutex_lock(&g_fraud_mu);
        int s = g_fraud_seen;
        pthread_mutex_unlock(&g_fraud_mu);
        if (s) break;
        usleep(10000);
    }
    pthread_mutex_lock(&g_fraud_mu);
    csls_fraud_pkt_t proof = g_fraud;
    int seen = g_fraud_seen;
    pthread_mutex_unlock(&g_fraud_mu);
    CHECK(seen, "E2 fraud_cb not invoked");
    CHECK(memcmp(proof.extracted_sk, agent_sk, 32) == 0,
          "E2 EXTRACTED SK != OFFENDER KEY — false slashing risk!");
    CHECK(proof.collision_h == h_conflict, "E2 collision height mismatch");
    printf("  [E2] fraud proof: extracted sk == offender sk (byte-exact), AXIOM 6 holds\n");

    // ---- E3: replay of an accepted cheque on a fresh connection --------------
    // Realistic attacker: reconnects (fresh ECDH session), re-MACs the OLD
    // accepted cheque under the CURRENT session key, and replays the height.
    int fd3 = open_attacker_session((uint16_t)EOTS_PORT, vendor_pk, &agent, agent_sk);
    uint8_t rmac[16];
    CHECK(csls_agent_mac_packet(&agent, vendor_pk, &last_pkt, rmac) == 0, "E3 re-mac");
    csls_cheque_wire_t rwire;
    memcpy(&rwire.pkt, &last_pkt, sizeof(last_pkt));
    memcpy(rwire.mac, rmac, 16);
    CHECK(tx_all(fd3, &rwire, sizeof(rwire)) == 0, "E3 send");
    CHECK(rx_exact(fd3, &ack, sizeof(ack)) == 0, "E3 no ACK");
    CHECK(ack.status_code == 2, "E3 replay not flagged (status=%u)", ack.status_code);
    CHECK(expect_severed(fd3) == 0, "E3 connection not severed");
    close(fd3);
    printf("  [E3] replay of accepted cheque (re-MACed) -> status 2, severed\n");
    close(fd);

    // ---- E4: O(1) extraction timing gate (< 500 us) --------------------------
    // The canonical equivocation pair: both cheques share height h_conflict
    // (hence the same deterministic nonce k / R-point) with different payloads.
    csls_cheque_pkt_t c1 = proof.cheque1;
    csls_cheque_pkt_t c2 = proof.cheque2;
    CHECK(c1.height == c2.height && c1.height == h_conflict, "E4 pair heights");
    enum { N_ITERS = 1000 };
    uint8_t sk_out[32];
    int64_t worst = 0, sum = 0;
    for (int i = 0; i < N_ITERS; i++) {
        int64_t a = t_now_ns();
        int rc = csls_extract_private_key(&c1, &c2, sk_out);
        int64_t dt = t_now_ns() - a;
        CHECK(rc == 0, "E4 extraction rc=%d", rc);
        CHECK(memcmp(sk_out, agent_sk, 32) == 0, "E4 extraction mismatch iter %d", i);
        sum += dt;
        if (dt > worst) worst = dt;
    }
    int64_t avg_us = sum / N_ITERS / 1000;
    CHECK(avg_us < 500, "E4 avg extraction %lld us >= 500 us — O(1) gate violated", (long long)avg_us);
    printf("  [E4] csls_extract_private_key x%d: avg %lld us, max %lld us (gate < 500 us)\n",
           N_ITERS, (long long)avg_us, (long long)(worst / 1000));

    // Bloodhound watchtower: capture + extraction from the packet stream itself.
    // 50 independent watchtowers: avg-of-captures is the fair O(1) metric
    // (a single wall-clock sample carries scheduler noise, like max() does).
    uint8_t hunter[20];
    memset(hunter, 0xC0, 20);
    bloodhound_exploit_payload_t payload;
    memset(&payload, 0, sizeof(payload));
    enum { N_HOUND = 50 };
    int64_t hsum = 0, hmax = 0, psum = 0;
    for (int i = 0; i < N_HOUND; i++) {
        bloodhound_ctx_t *hound = bloodhound_new(hunter);
        CHECK(hound != NULL, "bloodhound alloc %d", i);
        CHECK(bloodhound_inspect_packet(hound, &c1, NULL) == 0, "hound record c1 %d", i);
        // detection + O(1) extraction only (no forensic payload build-out)
        t0 = t_now_ns();
        int hrc = bloodhound_inspect_packet(hound, &c2, NULL);
        int64_t dt = t_now_ns() - t0;
        CHECK(hrc == 1, "hound capture rc=%d (1 = EQUIVOCATION_CAPTURED)", hrc);
        CHECK(atomic_load(&hound->packets_inspected) == 2, "hound packet counter");
        CHECK(atomic_load(&hound->equivocations_captured) == 1, "hound capture counter");
        bloodhound_free(hound);
        hsum += dt;
        if (dt > hmax) hmax = dt;
    }
    // full bounty-ready payload (adds ETH address derivation + commit hash)
    for (int i = 0; i < 10; i++) {
        bloodhound_ctx_t *hound = bloodhound_new(hunter);
        CHECK(hound != NULL, "bloodhound alloc p %d", i);
        CHECK(bloodhound_inspect_packet(hound, &c1, NULL) == 0, "hound record c1 p %d", i);
        t0 = t_now_ns();
        int hrc = bloodhound_inspect_packet(hound, &c2, &payload);
        int64_t dt = t_now_ns() - t0;
        bloodhound_free(hound);
        CHECK(hrc == 1, "hound payload capture rc=%d", hrc);
        CHECK(memcmp(payload.extracted_sk, agent_sk, 32) == 0, "hound extracted sk mismatch");
        CHECK(payload.collision_height == h_conflict, "hound collision height");
        psum += dt;
    }
    int64_t havg_us = hsum / N_HOUND / 1000;
    int64_t pavg_us = psum / 10 / 1000;
    CHECK(havg_us < 500, "hound avg detect+extract %lld us >= 500 us", (long long)havg_us);
    CHECK(pavg_us < 1000, "hound avg full payload %lld us >= 1000 us", (long long)pavg_us);
    printf("  [E4] bloodhound x%d: detect+extract avg %lld us, max %lld us (gate < 500 us)\n",
           N_HOUND, (long long)havg_us, (long long)(hmax / 1000));
    printf("  [E4] full bounty payload (extract + ETH address + commit hash): avg %lld us\n",
           (long long)pavg_us);

    // ---- shutdown ------------------------------------------------------------
    csls_daemon_stop();
    pthread_join(dth, NULL);
    CHECK(g_run_rc == 0, "daemon run rc=%d", g_run_rc);
    csls_crypto_global_cleanup();

    printf("----------------------------------------------------------------------\n");
    printf("[POC] VERDICT: equivocation + replay repelled on the live wire; O(1) gate PASS\n");
    return 0;
}
