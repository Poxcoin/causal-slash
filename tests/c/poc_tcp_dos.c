// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers
//
// RED TEAM PoC (Terminal 3): denial-of-service campaign vs csls_daemon.
//
// Vectors:
//   D1  torn cheque frames (3-5 TCP segments, sub-deadline gaps) -> must still
//       assemble and settle: latency budget is 5 s per frame, not per packet
//   D2  torn frame held PAST the 5 s deadline -> severed, no ACK, daemon alive
//   D3  sequence-height collision flood: hundreds of equivocation traps across
//       fresh connections (each forces one O(1) key extraction) while a
//       concurrent honest stream is measured -> honest p99 must stay bounded
//   D4  height extremes: h=0 first cheque, h=UINT64_MAX channel exhaustion
//       (self-DoS only; vendor keeps serving everyone else)
//   D5  wire desync: junk bytes injected between valid frames -> severed,
//       honest reconnect unimpaired
//
// Repro:
//   gcc -O2 -Wall -Wextra -Isrc -DCSLS_NO_MAIN -DCSLS_DAEMON_NO_MAIN
//       test/c/poc_tcp_dos.c src/causal_daemon.c src/csls_daemon.c
//       -lcrypto -lpthread -o /tmp/poc_tcp_dos && /tmp/poc_tcp_dos

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

#define DOS_PORT 19513
#define FLOOD_ROUNDS 300
#define PROBE_CHEQUES 400

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
    tv.tv_sec = 9;
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

static int open_session(uint16_t port, const uint8_t *vendor_pk, csls_agent_ctx_t *agent,
                        const uint8_t *sk) {
    int fd = tcp_connect(port);
    CHECK(fd >= 0, "connect");
    csls_welcome_pkt_t w;
    CHECK(rx_exact(fd, &w, sizeof(w)) == 0, "welcome");
    CHECK(w.magic == CSLS_MAGIC && w.type == CSLS_PKT_WELCOME, "welcome header");
    CHECK(csls_agent_init(agent, sk, NULL) == 0, "agent init");
    csls_session_init_pkt_t init;
    CHECK(csls_agent_session_begin(agent, vendor_pk, &init) == 0, "session begin");
    CHECK(tx_all(fd, &init, sizeof(init)) == 0, "send init");
    csls_ack_pkt_t ack;
    CHECK(rx_exact(fd, &ack, sizeof(ack)) == 0, "init ACK");
    CHECK(ack.status_code == 0, "init rejected %u", ack.status_code);
    return fd;
}

static void sign_wire(csls_agent_ctx_t *agent, const uint8_t *vendor_pk,
                      uint64_t delta, csls_cheque_wire_t *wire, csls_cheque_pkt_t *pkt) {
    uint8_t mac[16];
    CHECK(csls_agent_sign_cheque_mac(agent, vendor_pk, delta, pkt, mac) == 0, "sign");
    memcpy(&wire->pkt, pkt, sizeof(*pkt));
    memcpy(wire->mac, mac, 16);
}

static void send_wire(int fd, csls_agent_ctx_t *agent, const uint8_t *vendor_pk,
                      uint64_t delta, csls_cheque_wire_t *wire, csls_cheque_pkt_t *pkt) {
    sign_wire(agent, vendor_pk, delta, wire, pkt);
    CHECK(tx_all(fd, wire, sizeof(*wire)) == 0, "send");
}

// ---- D3: concurrent honest stream probe --------------------------------------

static pthread_mutex_t g_probe_mu = PTHREAD_MUTEX_INITIALIZER;
static int64_t g_probe_rtt[PROBE_CHEQUES];
static int g_probe_count = 0;
static _Atomic int g_probe_stop = 0;
static const uint8_t *g_vendor_pk;
static uint16_t g_port;

static void *probe_thread(void *arg) {
    (void)arg;
    csls_agent_ctx_t agent;
    uint8_t sk[32];
    memset(sk, 0x77, 32);
    int fd = open_session(g_port, g_vendor_pk, &agent, sk);
    csls_ack_pkt_t ack;
    for (int i = 0; i < PROBE_CHEQUES && !atomic_load(&g_probe_stop); i++) {
        csls_cheque_wire_t wire;
        csls_cheque_pkt_t pkt;
        uint8_t mac[16];
        if (csls_agent_sign_cheque_mac(&agent, g_vendor_pk, 1000, &pkt, mac) != 0) break;
        memcpy(&wire.pkt, &pkt, sizeof(pkt));
        memcpy(wire.mac, mac, 16);
        int64_t t0 = t_now_ns();
        if (tx_all(fd, &wire, sizeof(wire)) != 0) break;
        if (rx_exact(fd, &ack, sizeof(ack)) != 0) break;
        int64_t dt = t_now_ns() - t0;
        if (ack.status_code != 0) break;
        pthread_mutex_lock(&g_probe_mu);
        g_probe_rtt[g_probe_count++] = dt;
        pthread_mutex_unlock(&g_probe_mu);
    }
    close(fd);
    csls_agent_destroy(&agent);
    return NULL;
}

static int cmp_i64(const void *a, const void *b) {
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return (x > y) - (x < y);
}

int main(void) {
    printf("======================================================================\n");
    printf("[RED TEAM PoC] csls_daemon DoS: torn packets + height-collision flood (port %d)\n",
           DOS_PORT);
    printf("======================================================================\n");

    CHECK(csls_crypto_global_init() == 0, "crypto init");

    memset(&g_cfg, 0, sizeof(g_cfg));
    g_cfg.port = DOS_PORT;
    memset(g_cfg.vendor_sk, 0x44, 32);
    g_cfg.delta_v = 50000000ULL;
    g_cfg.enforce_mac = 1;
    g_cfg.max_conns = 64;

    csls_vendor_ctx_t *probe_vendor = csls_vendor_new(g_cfg.vendor_sk, 1000);
    CHECK(probe_vendor != NULL, "probe vendor");
    static uint8_t vendor_pk[33];
    memcpy(vendor_pk, probe_vendor->pk, 33);
    g_vendor_pk = vendor_pk;
    csls_vendor_free(probe_vendor);
    g_port = DOS_PORT;

    pthread_t dth;
    CHECK(pthread_create(&dth, NULL, daemon_thread, NULL) == 0, "daemon thread");
    int fd = -1;
    for (int i = 0; i < 250; i++) {
        fd = tcp_connect((uint16_t)DOS_PORT);
        if (fd >= 0) break;
        usleep(20000);
    }
    CHECK(fd >= 0, "daemon did not come up");
    close(fd);

    // ---- D1: torn frames inside the deadline still settle --------------------
    {
        csls_agent_ctx_t agent;
        uint8_t sk[32];
        memset(sk, 0x11, 32);
        fd = open_session((uint16_t)DOS_PORT, vendor_pk, &agent, sk);
        static const size_t plans[][2] = {{3, 100}, {1, 1}, {80, 87}, {166, 1}};
        for (size_t p = 0; p < sizeof(plans) / sizeof(plans[0]); p++) {
            csls_cheque_wire_t wire;
            csls_cheque_pkt_t pkt;
            sign_wire(&agent, vendor_pk, 1000, &wire, &pkt); // sign ONLY, tear the only copy
            size_t a = plans[p][0], b = plans[p][1];
            CHECK(tx_all(fd, &wire, a) == 0, "D1 torn part 1");
            usleep(60000);
            if (tx_all(fd, (const uint8_t *)&wire + a, b) != 0)
                CHECK(0, "D1 torn part 2 failed: errno=%d (%s)", errno, strerror(errno));
            usleep(60000);
            if (tx_all(fd, (const uint8_t *)&wire + a + b, sizeof(wire) - a - b) != 0)
                CHECK(0, "D1 torn part 3 failed: errno=%d (%s)", errno, strerror(errno));
            csls_ack_pkt_t ack;
            CHECK(rx_exact(fd, &ack, sizeof(ack)) == 0, "D1 no ACK for torn frame");
            CHECK(ack.status_code == 0, "D1 torn frame rejected %u", ack.status_code);
        }
        close(fd);
        csls_agent_destroy(&agent);
        printf("  [D1] torn frames (3 segments, 60 ms gaps) all assembled and settled\n");
    }

    // ---- D2: frame held past the deadline is severed --------------------------
    {
        csls_agent_ctx_t agent;
        uint8_t sk[32];
        memset(sk, 0x12, 32);
        fd = open_session((uint16_t)DOS_PORT, vendor_pk, &agent, sk);
        csls_cheque_wire_t wire;
        csls_cheque_pkt_t pkt;
        sign_wire(&agent, vendor_pk, 1000, &wire, &pkt);
        CHECK(tx_all(fd, &wire, 80) == 0, "D2 first half");
        usleep(6000000); // 6 s > 5 s frame deadline
        ssize_t rn = recv(fd, (uint8_t *)&wire, sizeof(wire), 0);
        CHECK(rn == 0, "D2 connection not severed after deadline (rn=%zd)", rn);
        close(fd);
        csls_agent_destroy(&agent);
        printf("  [D2] frame stalled 6 s -> severed at the 5 s deadline, no ACK\n");
    }

    // ---- D3: height-collision trap flood vs concurrent honest stream ----------
    {
        pthread_t probe;
        CHECK(pthread_create(&probe, NULL, probe_thread, NULL) == 0, "probe thread");
        usleep(50000);

        // ONE persistent attacker context: heights advance globally across
        // rounds; only the MAC session is re-established per connection.
        csls_agent_ctx_t agent;
        uint8_t sk[32];
        memset(sk, 0x99, 32);
        CHECK(csls_agent_init(&agent, sk, NULL) == 0, "D3 agent init");
        int traps_fired = 0;
        for (int i = 0; i < FLOOD_ROUNDS; i++) {
            fd = tcp_connect((uint16_t)DOS_PORT);
            CHECK(fd >= 0, "D3 connect %d", i);
            csls_welcome_pkt_t w;
            CHECK(rx_exact(fd, &w, sizeof(w)) == 0, "D3 welcome %d", i);
            csls_session_init_pkt_t init;
            CHECK(csls_agent_session_begin(&agent, vendor_pk, &init) == 0, "D3 session %d", i);
            CHECK(tx_all(fd, &init, sizeof(init)) == 0, "D3 send init %d", i);
            csls_ack_pkt_t iack;
            CHECK(rx_exact(fd, &iack, sizeof(iack)) == 0 && iack.status_code == 0,
                  "D3 init ack %d", i);
            csls_cheque_wire_t wire;
            csls_cheque_pkt_t pkt;
            csls_ack_pkt_t ack;
            // honest-looking cheque, accepted
            send_wire(fd, &agent, vendor_pk, 1000, &wire, &pkt);
            CHECK(rx_exact(fd, &ack, sizeof(ack)) == 0, "D3 base ACK %d", i);
            CHECK(ack.status_code == 0, "D3 base rejected %d (%u)", i, ack.status_code);
            uint64_t h = pkt.height;
            // conflicting double-sign at the SAME height -> O(1) extraction + sever
            atomic_store(&agent.height, h);
            send_wire(fd, &agent, vendor_pk, 9999, &wire, &pkt);
            CHECK(pkt.height == h, "D3 height drift %d", i);
            CHECK(rx_exact(fd, &ack, sizeof(ack)) == 0, "D3 trap ACK %d", i);
            CHECK(ack.status_code == 3, "D3 trap not flagged %d (%u)", i, ack.status_code);
            close(fd);
            traps_fired++;
        }
        csls_agent_destroy(&agent);

        atomic_store(&g_probe_stop, 1);
        pthread_join(probe, NULL);
        CHECK(g_probe_count >= PROBE_CHEQUES - 1, "D3 honest stream died under flood (%d/%d)",
              g_probe_count, PROBE_CHEQUES);
        int64_t rtts[PROBE_CHEQUES];
        memcpy(rtts, g_probe_rtt, sizeof(int64_t) * g_probe_count);
        qsort(rtts, g_probe_count, sizeof(int64_t), cmp_i64);
        int64_t p50 = rtts[g_probe_count / 2] / 1000;
        int64_t p99 = rtts[g_probe_count * 99 / 100] / 1000;
        CHECK(p99 < 20000, "D3 honest p99 %lld us >= 20 ms under trap flood", (long long)p99);
        printf("  [D3] %d equivocation traps fired; honest stream %d/%d cheques, "
               "p50 %lld us, p99 %lld us\n",
               traps_fired, g_probe_count, PROBE_CHEQUES, (long long)p50, (long long)p99);
    }

    // ---- D4: height extremes --------------------------------------------------
    {
        // h = 0 first cheque is protocol-legal and accepted.
        csls_agent_ctx_t agent;
        uint8_t sk[32];
        memset(sk, 0x13, 32);
        fd = open_session((uint16_t)DOS_PORT, vendor_pk, &agent, sk);
        atomic_store(&agent.height, 0);
        csls_cheque_wire_t wire;
        csls_cheque_pkt_t pkt;
        csls_ack_pkt_t ack;
        send_wire(fd, &agent, vendor_pk, 1000, &wire, &pkt);
        CHECK(pkt.height == 0, "D4 h=0 not signed");
        CHECK(rx_exact(fd, &ack, sizeof(ack)) == 0 && ack.status_code == 0, "D4 h=0 rejected");
        close(fd);
        csls_agent_destroy(&agent);

        // h = UINT64_MAX exhausts the attacker's OWN channel only.
        memset(sk, 0x14, 32);
        fd = open_session((uint16_t)DOS_PORT, vendor_pk, &agent, sk);
        atomic_store(&agent.height, UINT64_MAX);
        send_wire(fd, &agent, vendor_pk, 1000, &wire, &pkt);
        CHECK(pkt.height == UINT64_MAX, "D4 h=max not signed");
        CHECK(rx_exact(fd, &ack, sizeof(ack)) == 0 && ack.status_code == 0, "D4 h=max rejected");
        // next height wraps to 0 -> vendor rejects the regression, connection dies
        send_wire(fd, &agent, vendor_pk, 1000, &wire, &pkt);
        CHECK(rx_exact(fd, &ack, sizeof(ack)) == 0, "D4 no ACK after wrap");
        CHECK(ack.status_code == 2, "D4 wrap not rejected (%u)", ack.status_code);
        close(fd);
        csls_agent_destroy(&agent);
        printf("  [D4] h=0 and h=UINT64_MAX accepted; channel exhaustion is self-inflicted only\n");
    }

    // ---- D5: wire desync via junk between frames ------------------------------
    {
        csls_agent_ctx_t agent;
        uint8_t sk[32];
        memset(sk, 0x15, 32);
        fd = open_session((uint16_t)DOS_PORT, vendor_pk, &agent, sk);
        csls_cheque_wire_t wire;
        csls_cheque_pkt_t pkt;
        csls_ack_pkt_t ack;
        send_wire(fd, &agent, vendor_pk, 1000, &wire, &pkt);
        CHECK(rx_exact(fd, &ack, sizeof(ack)) == 0 && ack.status_code == 0, "D5 base");
        // inject junk: the next frame header read is now misaligned
        uint8_t junk[2] = {0xDE, 0xAD};
        CHECK(tx_all(fd, junk, sizeof(junk)) == 0, "D5 junk");
        send_wire(fd, &agent, vendor_pk, 1000, &wire, &pkt);
        // server must sever (bad magic) without ever emitting a fraudulent ACK
        char sink[64];
        ssize_t rn = recv(fd, sink, sizeof(sink), 0);
        CHECK(rn <= 0, "D5 desynced connection kept serving (rn=%zd)", rn);
        close(fd);
        printf("  [D5] junk between frames -> header desync detected, connection severed\n");

        // honest reconnect of the SAME agent (heights keep advancing globally)
        fd = tcp_connect((uint16_t)DOS_PORT);
        CHECK(fd >= 0, "D5 reconnect connect");
        csls_welcome_pkt_t w2;
        CHECK(rx_exact(fd, &w2, sizeof(w2)) == 0, "D5 reconnect welcome");
        csls_session_init_pkt_t init2;
        CHECK(csls_agent_session_begin(&agent, vendor_pk, &init2) == 0, "D5 re-session");
        CHECK(tx_all(fd, &init2, sizeof(init2)) == 0, "D5 re-init send");
        csls_ack_pkt_t iack2;
        CHECK(rx_exact(fd, &iack2, sizeof(iack2)) == 0 && iack2.status_code == 0,
              "D5 re-init ack");
        send_wire(fd, &agent, vendor_pk, 1000, &wire, &pkt);
        CHECK(rx_exact(fd, &ack, sizeof(ack)) == 0 && ack.status_code == 0, "D5 reconnect");
        close(fd);
        csls_agent_destroy(&agent);
        printf("  [D5] honest reconnect after desync: settled\n");
    }

    // ---- shutdown -------------------------------------------------------------
    csls_daemon_stop();
    pthread_join(dth, NULL);
    CHECK(g_run_rc == 0, "daemon run rc=%d", g_run_rc);
    csls_crypto_global_cleanup();

    printf("----------------------------------------------------------------------\n");
    printf("[POC] VERDICT: no DoS achieved; daemon bounded, alive and fair under all vectors\n");
    return 0;
}
