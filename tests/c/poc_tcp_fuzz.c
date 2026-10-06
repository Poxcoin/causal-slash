// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers
//
// RED TEAM PoC (Terminal 3): TCP parser fuzzing vs csls_daemon.
// Zone compliance: product code (src/*, Makefile) is NOT modified; this PoC
// only ATTACKS through the live loopback TCP surface, hosting the daemon
// in-process for a deterministic kill criterion (a crash kills this process).
//
// Attack vectors:
//   F1  seeded random garbage frames (bad magic, wrong types, random lengths,
//       1 MiB zero bursts)                          -> daemon must survive
//   F2  truncated cheque frames (0..166 of 167 B)   -> severed, no ACK 0
//   F3  Slowloris: 64 conns hold every slot with a
//       2-byte partial header                       -> bounded ~5s degradation,
//                                                      honest flow still lands
//   F4  honest liveness probe after EVERY phase     -> settlement unimpaired
//
// Repro:
//   gcc -O2 -Wall -Wextra -Isrc -DCSLS_NO_MAIN -DCSLS_DAEMON_NO_MAIN
//       test/c/poc_tcp_fuzz.c src/causal_daemon.c src/csls_daemon.c
//       -lcrypto -lpthread -o /tmp/poc_tcp_fuzz && /tmp/poc_tcp_fuzz

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
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

#define FUZZ_PORT 19511
#define MAX_CONNS 64

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

// deterministic xorshift64* (reproducible campaign)
static uint64_t g_rng = 0x9E3779B97F4A7C15ull;
static uint64_t rnd(void) {
    g_rng ^= g_rng >> 12;
    g_rng ^= g_rng << 25;
    g_rng ^= g_rng >> 27;
    return g_rng * 0x2545F4914F6CDD1Dull;
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
    tv.tv_sec = 6;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
    return fd;
}

// recv() until orderly close; returns total bytes seen (welcome included).
static long drain_until_close(int fd) {
    uint8_t sink[4096];
    long total = 0;
    for (;;) {
        ssize_t r = recv(fd, sink, sizeof(sink), 0);
        if (r <= 0) {
            if (r < 0 && (errno == EINTR)) continue;
            return total;
        }
        total += r;
    }
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

// An honest agent proves the daemon is still fully operational.
// Each probe gets a UNIQUE key: vendor channel state (height/cumulative) is
// per-agent and persists across probes; a fresh context with a reused key
// would regress the channel and get honestly rejected as a replay.
static int g_probe_seq = 0;
static void honest_liveness_probe(uint16_t port, const uint8_t *vendor_pk, int cheques,
                                  const char *phase) {
    int fd = tcp_connect(port);
    CHECK(fd >= 0, "%s: honest connect failed", phase);
    csls_welcome_pkt_t w;
    CHECK(rx_exact(fd, &w, sizeof(w)) == 0, "%s: no welcome", phase);
    CHECK(w.magic == CSLS_MAGIC && w.type == CSLS_PKT_WELCOME, "%s: bad welcome", phase);

    csls_agent_ctx_t agent;
    uint8_t sk[32];
    memset(sk, 0x50 + (g_probe_seq++), 32);
    CHECK(csls_agent_init(&agent, sk, NULL) == 0, "%s: agent init", phase);
    csls_session_init_pkt_t init;
    CHECK(csls_agent_session_begin(&agent, vendor_pk, &init) == 0, "%s: session begin", phase);
    CHECK(tx_all(fd, &init, sizeof(init)) == 0, "%s: send init", phase);
    csls_ack_pkt_t ack;
    CHECK(rx_exact(fd, &ack, sizeof(ack)) == 0, "%s: no init ACK", phase);
    CHECK(ack.status_code == 0, "%s: init rejected %u", phase, ack.status_code);

    for (int i = 0; i < cheques; i++) {
        csls_cheque_pkt_t pkt;
        uint8_t mac[16];
        CHECK(csls_agent_sign_cheque_mac(&agent, vendor_pk, 1000, &pkt, mac) == 0,
              "%s: sign %d", phase, i);
        csls_cheque_wire_t wire;
        memcpy(&wire.pkt, &pkt, sizeof(pkt));
        memcpy(wire.mac, mac, 16);
        CHECK(tx_all(fd, &wire, sizeof(wire)) == 0, "%s: send %d", phase, i);
        CHECK(rx_exact(fd, &ack, sizeof(ack)) == 0, "%s: no ACK %d", phase, i);
        CHECK(ack.status_code == 0, "%s: cheque %d rejected %u", phase, i, ack.status_code);
    }
    close(fd);
    csls_agent_destroy(&agent);
    printf("  [%s] liveness OK (%d cheques settled)\n", phase, cheques);
}

int main(void) {
    printf("======================================================================\n");
    printf("[RED TEAM PoC] csls_daemon TCP parser fuzzing (port %d)\n", FUZZ_PORT);
    printf("======================================================================\n");

    CHECK(csls_crypto_global_init() == 0, "crypto init");

    memset(&g_cfg, 0, sizeof(g_cfg));
    g_cfg.port = FUZZ_PORT;
    memset(g_cfg.vendor_sk, 0x44, 32);
    g_cfg.delta_v = 50000000ULL;
    g_cfg.enforce_mac = 1;
    g_cfg.max_conns = MAX_CONNS;

    csls_vendor_ctx_t *probe = csls_vendor_new(g_cfg.vendor_sk, 1000);
    CHECK(probe != NULL, "probe vendor");
    uint8_t vendor_pk[33];
    memcpy(vendor_pk, probe->pk, 33);
    csls_vendor_free(probe);

    pthread_t dth;
    CHECK(pthread_create(&dth, NULL, daemon_thread, NULL) == 0, "daemon thread");
    int fd = -1;
    for (int i = 0; i < 250; i++) {
        fd = tcp_connect((uint16_t)FUZZ_PORT);
        if (fd >= 0) break;
        usleep(20000);
    }
    CHECK(fd >= 0, "daemon did not come up");
    close(fd);

    // ---- F1: seeded random garbage campaign ---------------------------------
    int garbage_rounds = 300, connected = 0, bursts = 0;
    uint8_t frame[512];
    for (int i = 0; i < garbage_rounds; i++) {
        fd = tcp_connect((uint16_t)FUZZ_PORT);
        if (fd < 0) continue; // slot exhaustion under fuzz is survivable, retry next round
        // consume welcome (may be absent if the server closed us)
        uint8_t wbuf[64];
        ssize_t wr = recv(fd, wbuf, sizeof(wbuf), MSG_DONTWAIT);
        (void)wr;

        size_t len = (size_t)(rnd() % 400);
        memset(frame, 0, sizeof(frame));
        for (size_t j = 0; j < len; j++) frame[j] = (uint8_t)(rnd() & 0xFF);
        if (len >= 5 && (rnd() & 3) == 0) {
            uint32_t magic = CSLS_MAGIC;
            memcpy(frame, &magic, 4);
            frame[4] = (uint8_t)(rnd() % 8); // valid magic, random type
        }
        if (tx_all(fd, frame, len) == 0) {
            connected++;
            if (i % 16 == 0) {
                static uint8_t zeros[8192];
                for (int b = 0; b < 128 && tx_all(fd, zeros, sizeof(zeros)) == 0; b++) {
                }
                bursts++;
            }
        }
        shutdown(fd, SHUT_WR); // half-close: no 5s deadline hold on garbage
        drain_until_close(fd);
        close(fd);
    }
    printf("  [F1] %d garbage frames + %d x 1MiB zero bursts fired, daemon alive\n",
           connected, bursts);
    honest_liveness_probe((uint16_t)FUZZ_PORT, vendor_pk, 50, "F1-liveness");

    // ---- F2: truncated cheque frames ----------------------------------------
    size_t trunc_lens[] = {0, 1, 2, 3, 4, 5, 6, 94, 95, 150, 151, 160, 166, 167};
    csls_agent_ctx_t agent;
    uint8_t sk[32];
    memset(sk, 0x22, 32); // dedicated key: F2 owns its channel state
    CHECK(csls_agent_init(&agent, sk, NULL) == 0, "agent init F2");

    for (size_t t = 0; t < sizeof(trunc_lens) / sizeof(trunc_lens[0]); t++) {
        size_t len = trunc_lens[t];
        fd = tcp_connect((uint16_t)FUZZ_PORT);
        CHECK(fd >= 0, "F2 connect %zu", len);
        csls_welcome_pkt_t w;
        CHECK(rx_exact(fd, &w, sizeof(w)) == 0, "F2 welcome %zu", len);

        // a genuinely signed, properly MACed cheque, truncated on the wire
        csls_session_init_pkt_t init;
        CHECK(csls_agent_session_begin(&agent, vendor_pk, &init) == 0, "F2 session %zu", len);
        CHECK(tx_all(fd, &init, sizeof(init)) == 0, "F2 send init %zu", len);
        csls_ack_pkt_t ack;
        CHECK(rx_exact(fd, &ack, sizeof(ack)) == 0, "F2 init ack %zu", len);
        CHECK(ack.status_code == 0, "F2 init rejected %zu", len);

        csls_cheque_pkt_t pkt;
        uint8_t mac[16];
        CHECK(csls_agent_sign_cheque_mac(&agent, vendor_pk, 1000, &pkt, mac) == 0, "F2 sign");
        csls_cheque_wire_t wire;
        memcpy(&wire.pkt, &pkt, sizeof(pkt));
        memcpy(wire.mac, mac, 16);

        CHECK(tx_all(fd, &wire, len) == 0, "F2 send %zu", len);
        shutdown(fd, SHUT_WR);
        long seen = drain_until_close(fd);
        if (len == sizeof(csls_cheque_wire_t)) {
            CHECK(seen >= (long)sizeof(csls_ack_pkt_t), "F2 full frame must be ACKed (%zu)", len);
        } else {
            // no full 22-byte ACK(status 0) may ever come out of a truncated frame
            CHECK(seen < (long)sizeof(csls_ack_pkt_t), "F2 truncated frame %zu produced an ACK!", len);
        }
        close(fd);
    }
    csls_agent_destroy(&agent);
    printf("  [F2] 14 truncation lengths (0..167 B): no ACK ever escaped a partial frame\n");
    honest_liveness_probe((uint16_t)FUZZ_PORT, vendor_pk, 50, "F2-liveness");

    // ---- F3: Slowloris against the bounded connection pool -------------------
    int slowfds[MAX_CONNS];
    int nslow = 0;
    for (; nslow < MAX_CONNS; nslow++) {
        slowfds[nslow] = tcp_connect((uint16_t)FUZZ_PORT);
        if (slowfds[nslow] < 0) break;
        // read welcome (server sends it before reading our header), then stall
        uint8_t wbuf[64];
        ssize_t wr = recv(slowfds[nslow], wbuf, sizeof(wbuf), 0);
        (void)wr;
        uint8_t partial[2] = {0x53, 0x4C}; // 2 bytes of the magic, then silence
        if (tx_all(slowfds[nslow], partial, sizeof(partial)) != 0) break;
    }
    printf("  [F3] %d Slowloris sockets hold the pool with 2-byte headers\n", nslow);

    int64_t t0 = t_now_ns();
    int recovered = 0;
    for (int attempt = 0; attempt < 16 && !recovered; attempt++) {
        usleep(500000);
        fd = tcp_connect((uint16_t)FUZZ_PORT);
        if (fd < 0) continue;
        csls_welcome_pkt_t w;
        if (rx_exact(fd, &w, sizeof(w)) != 0) { // refused while pool is full
            close(fd);
            continue;
        }
        csls_agent_ctx_t a2;
        uint8_t sk2[32];
        memset(sk2, 0x77, 32);
        if (csls_agent_init(&a2, sk2, NULL) != 0) { close(fd); continue; }
        csls_session_init_pkt_t init;
        if (csls_agent_session_begin(&a2, vendor_pk, &init) != 0 ||
            tx_all(fd, &init, sizeof(init)) != 0) {
            csls_agent_destroy(&a2);
            close(fd);
            continue;
        }
        csls_ack_pkt_t ack;
        if (rx_exact(fd, &ack, sizeof(ack)) != 0 || ack.status_code != 0) {
            csls_agent_destroy(&a2);
            close(fd);
            continue;
        }
        int ok = 1;
        for (int i = 0; i < 20 && ok; i++) {
            csls_cheque_pkt_t pkt;
            uint8_t mac[16];
            if (csls_agent_sign_cheque_mac(&a2, vendor_pk, 1000, &pkt, mac) != 0) { ok = 0; break; }
            csls_cheque_wire_t wire;
            memcpy(&wire.pkt, &pkt, sizeof(pkt));
            memcpy(wire.mac, mac, 16);
            if (tx_all(fd, &wire, sizeof(wire)) != 0) { ok = 0; break; }
            if (rx_exact(fd, &ack, sizeof(ack)) != 0 || ack.status_code != 0) ok = 0;
        }
        csls_agent_destroy(&a2);
        close(fd);
        if (ok) recovered = 1;
    }
    int64_t elapsed_ms = (t_now_ns() - t0) / 1000000;
    CHECK(recovered, "honest settlement never recovered from Slowloris (unbounded DoS!)");
    printf("  [F3] honest settlement recovered in %ld ms (frame deadline %.1fs bound) — no hang\n",
           elapsed_ms, (double)CSLS_DAEMON_SOCK_TIMEOUT_SEC);
    for (int i = 0; i < nslow; i++) close(slowfds[i]);

    // ---- F4: bad magic with exact wire length -------------------------------
    fd = tcp_connect((uint16_t)FUZZ_PORT);
    CHECK(fd >= 0, "F4 connect");
    csls_welcome_pkt_t w;
    CHECK(rx_exact(fd, &w, sizeof(w)) == 0, "F4 welcome");
    uint8_t bad[167];
    memset(bad, 0xAB, sizeof(bad)); // wrong magic on purpose
    CHECK(tx_all(fd, bad, sizeof(bad)) == 0, "F4 send");
    shutdown(fd, SHUT_WR);
    drain_until_close(fd);
    close(fd);
    printf("  [F4] 167 B frame with forged magic dropped\n");
    honest_liveness_probe((uint16_t)FUZZ_PORT, vendor_pk, 50, "F4-liveness");

    // ---- shutdown ------------------------------------------------------------
    csls_daemon_stop();
    pthread_join(dth, NULL);
    CHECK(g_run_rc == 0, "daemon run rc=%d", g_run_rc);
    csls_crypto_global_cleanup();

    printf("----------------------------------------------------------------------\n");
    printf("[POC] VERDICT: daemon SURVIVED the full fuzz campaign (rc=0, no hang, no crash)\n");
    return 0;
}
