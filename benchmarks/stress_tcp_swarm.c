// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers
//
// Industrial TCP streaming stress generator for the CSLS network daemon.
// Terminal 1 (causal_term1_core) / Blue Team high-throughput benchmark.
//
// ZERO-MOCK: every cheque is a real csls_agent_sign_cheque_mac() signature
// (Schnorr EOTS nonce k = HMAC(sk, PK_vendor || h)) over a real TCP socket,
// validated by the live daemon, ACKed with a real 22-byte csls_ack_pkt_t.
//
// Each agent thread opens its own connection: welcome(38B) -> SESSION_INIT
// (95B) -> N x [167B MAC cheque -> 22B ACK]. Latency is measured per cheque
// (send -> ACK), aggregated into p50/p99/p999/max. Peak TPS is sampled over
// 100 ms global buckets.
//
// Build: gcc -O3 -Wall -Wextra -pthread -Isrc -DCSLS_NO_MAIN -o /tmp/stress_swarm
//            benchmarks/stress_tcp_swarm.c src/causal_daemon.c -lcrypto
// Run:   /tmp/stress_swarm --port 9444 --agents 12 --cheques 100000
//            --delta 1000 --json /tmp/stress_ledger.json

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/crypto.h>
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

#define MAX_BUCKETS 60000 // 100 ms buckets => 100 minutes of headroom

typedef struct {
    int    idx;
    int    port;
    long   cheques;
    long   delta_micro;
    double *lat_us;      // per-cheque RTT, microseconds
    long   done;
    int    rejected;     // non-zero ACK statuses
    int    ok;
    uint64_t final_height;
    uint64_t final_cumulative;
    uint8_t  pk[33];
    int    rc;
} agent_arg_t;

static _Atomic uint64_t g_buckets[MAX_BUCKETS];
static _Atomic long     g_total_ok;
static _Atomic long     g_total_reject;
static int64_t          g_t_start;

static int64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000ll + (int64_t)ts.tv_nsec;
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

static int cmp_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static void *agent_worker(void *raw) {
    agent_arg_t *A = (agent_arg_t *)raw;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { A->rc = -1; return NULL; }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)A->port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        A->rc = -2;
        return NULL;
    }
    int flag = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
#ifdef TCP_QUICKACK
    setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &flag, sizeof(flag));
#endif
    struct timeval tv = { .tv_sec = 15, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));

    uint8_t sk[32];
    for (int i = 0; i < 32; i++) sk[i] = (uint8_t)(0x50 + A->idx);
    csls_agent_ctx_t *agent = csls_agent_new(sk, NULL);
    if (!agent) { close(fd); A->rc = -3; return NULL; }
    memcpy(A->pk, agent->pk, 33);

    csls_welcome_pkt_t w;
    if (rx_exact(fd, &w, sizeof(w)) != 0 || w.type != CSLS_PKT_WELCOME) {
        csls_agent_free(agent);
        close(fd);
        A->rc = -5;
        return NULL;
    }
    csls_session_init_pkt_t init;
    if (csls_agent_session_begin(agent, w.vendor_pk, &init) != 0 ||
        tx_all(fd, &init, sizeof(init)) != 0) {
        csls_agent_free(agent);
        close(fd);
        A->rc = -6;
        return NULL;
    }
    csls_ack_pkt_t ack;
    if (rx_exact(fd, &ack, sizeof(ack)) != 0 || ack.status_code != 0) {
        csls_agent_free(agent);
        close(fd);
        A->rc = -7;
        return NULL;
    }

    csls_cheque_pkt_t pkt;
    uint8_t mac[16];
    csls_cheque_wire_t wire;
    long latency_cap = A->cheques;
    A->lat_us = (double *)malloc((size_t)latency_cap * sizeof(double));
    if (!A->lat_us) { csls_agent_free(agent); close(fd); A->rc = -8; return NULL; }

    int rc = 0;
    for (long i = 0; i < A->cheques; i++) {
        if (csls_agent_sign_cheque_mac(agent, w.vendor_pk,
                                       (uint64_t)A->delta_micro, &pkt, mac) != 0) {
            rc = -9;
            break;
        }
        memcpy(&wire.pkt, &pkt, sizeof(pkt));
        memcpy(wire.mac, mac, 16);

        int64_t t0 = now_ns();
        if (tx_all(fd, &wire, sizeof(wire)) != 0 ||
            rx_exact(fd, &ack, sizeof(ack)) != 0) {
            rc = -10;
            break;
        }
        int64_t t1 = now_ns();
        if (ack.status_code == 0) {
            A->lat_us[A->done] = (double)(t1 - t0) / 1000.0;
            A->done++;
            atomic_fetch_add_explicit(&g_total_ok, 1, memory_order_relaxed);
            int64_t slot = (t1 - g_t_start) / 100000000ll; // 100 ms buckets
            if (slot >= 0 && slot < MAX_BUCKETS)
                atomic_fetch_add_explicit(&g_buckets[slot], 1, memory_order_relaxed);
        } else {
            A->rejected++;
            atomic_fetch_add_explicit(&g_total_reject, 1, memory_order_relaxed);
        }
    }

    uint64_t h = 0, cum = 0;
    csls_agent_get_channel_state(agent, w.vendor_pk, &h, &cum);
    A->final_height = h;
    A->final_cumulative = cum;
    A->rc = rc;
    OPENSSL_cleanse(sk, sizeof(sk));
    csls_agent_free(agent);
    close(fd);
    return NULL;
}

static double pct(double *v, long n, double p) {
    if (n == 0) return 0.0;
    long idx = (long)((p / 100.0) * (double)(n - 1));
    if (idx < 0) idx = 0;
    if (idx >= n) idx = n - 1;
    return v[idx];
}

int main(int argc, char **argv) {
    int port = 9444;
    int agents = 12;
    long cheques = 100000;
    long delta = 1000;
    const char *json_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--port") && i + 1 < argc) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--agents") && i + 1 < argc) agents = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--cheques") && i + 1 < argc) cheques = atol(argv[++i]);
        else if (!strcmp(argv[i], "--delta") && i + 1 < argc) delta = atol(argv[++i]);
        else if (!strcmp(argv[i], "--json") && i + 1 < argc) json_path = argv[++i];
        else { fprintf(stderr, "unknown arg %s\n", argv[i]); return 1; }
    }
    if (agents < 1 || agents > 64 || cheques < 1) {
        fprintf(stderr, "bad parameters\n");
        return 1;
    }

    if (csls_crypto_global_init() != 0) {
        fprintf(stderr, "crypto init failed\n");
        return 1;
    }
    memset((void *)g_buckets, 0, sizeof(g_buckets));
    g_t_start = now_ns();

    agent_arg_t *args = (agent_arg_t *)calloc((size_t)agents, sizeof(agent_arg_t));
    pthread_t *tids = (pthread_t *)calloc((size_t)agents, sizeof(pthread_t));
    for (int i = 0; i < agents; i++) {
        args[i].idx = i;
        args[i].port = port;
        args[i].cheques = cheques;
        args[i].delta_micro = delta;
        if (pthread_create(&tids[i], NULL, agent_worker, &args[i]) != 0) {
            fprintf(stderr, "pthread_create failed\n");
            return 1;
        }
    }
    for (int i = 0; i < agents; i++) pthread_join(tids[i], NULL);
    int64_t t_end = now_ns();

    // Aggregate latency + peak TPS.
    long total_done = 0;
    for (int i = 0; i < agents; i++) total_done += args[i].done;
    double *all = NULL;
    if (total_done > 0) {
        all = (double *)malloc((size_t)total_done * sizeof(double));
        long off = 0;
        for (int i = 0; i < agents; i++) {
            memcpy(all + off, args[i].lat_us, (size_t)args[i].done * sizeof(double));
            off += args[i].done;
        }
        qsort(all, (size_t)total_done, sizeof(double), cmp_double);
    }
    uint64_t peak_bucket = 0;
    for (int b = 0; b < MAX_BUCKETS; b++) {
        uint64_t v = atomic_load_explicit(&g_buckets[b], memory_order_relaxed);
        if (v > peak_bucket) peak_bucket = v;
    }

    double wall = (double)(t_end - g_t_start) / 1e9;
    double tps = (double)total_done / wall;
    double peak_tps = (double)peak_bucket * 10.0;
    double total_micro = 0;
    for (int i = 0; i < agents; i++) total_micro += (double)args[i].final_cumulative;

    printf("======================================================================\n");
    printf("[STRESS] CSLS TCP Swarm Streaming — %d agents x %ld cheques (delta=%ld micro)\n",
           agents, cheques, delta);
    printf("======================================================================\n");
    printf("  Cheques ACKed (status 0) : %ld\n", total_done);
    printf("  Cheques rejected         : %ld\n", (long)atomic_load(&g_total_reject));
    printf("  Wall time                : %.3f s\n", wall);
    printf("  Aggregate throughput     : %.0f cheques/s\n", tps);
    printf("  Peak throughput (100 ms) : %.0f cheques/s\n", peak_tps);
    printf("  Total volume streamed    : %.0f micro-USDC ($%.2f)\n", total_micro, total_micro / 1e6);
    if (total_done > 0) {
        double sum = 0;
        for (long i = 0; i < total_done; i++) sum += all[i];
        printf("  RTT avg                  : %.2f us\n", sum / (double)total_done);
        printf("  RTT p50 / p99 / p99.9    : %.2f / %.2f / %.2f us\n",
               pct(all, total_done, 50.0), pct(all, total_done, 99.0), pct(all, total_done, 99.9));
        printf("  RTT max                  : %.2f us\n", all[total_done - 1]);
    }
    for (int i = 0; i < agents; i++) {
        if (args[i].rc != 0) printf("  agent[%d] rc=%d done=%ld\n", i, args[i].rc, args[i].done);
    }

    if (json_path) {
        FILE *f = fopen(json_path, "w");
        if (f) {
            fprintf(f, "{\n  \"port\": %d,\n  \"agents\": %d,\n  \"cheques_requested\": %ld,\n", port, agents, cheques);
            fprintf(f, "  \"cheques_acked\": %ld,\n  \"cheques_rejected\": %ld,\n", total_done, (long)atomic_load(&g_total_reject));
            fprintf(f, "  \"wall_seconds\": %.4f,\n  \"tps_avg\": %.1f,\n  \"tps_peak_100ms\": %.1f,\n", wall, tps, peak_tps);
            if (total_done > 0) {
                double sum = 0;
                for (long i = 0; i < total_done; i++) sum += all[i];
                fprintf(f, "  \"rtt_us\": {\"avg\": %.3f, \"p50\": %.3f, \"p99\": %.3f, \"p999\": %.3f, \"max\": %.3f},\n",
                        sum / (double)total_done,
                        pct(all, total_done, 50.0), pct(all, total_done, 99.0),
                        pct(all, total_done, 99.9), all[total_done - 1]);
            }
            fprintf(f, "  \"total_volume_micro_usdc\": %.0f,\n", total_micro);
            fprintf(f, "  \"ledger\": [\n");
            for (int i = 0; i < agents; i++) {
                fprintf(f, "    {\"agent_idx\": %d, \"pk\": \"", i);
                for (int b = 0; b < 33; b++) fprintf(f, "%02x", args[i].pk[b]);
                fprintf(f, "\", \"final_height\": %llu, \"final_cumulative_micro\": %llu, \"acked\": %ld, \"rejected\": %d, \"rc\": %d}%s\n",
                        (unsigned long long)args[i].final_height,
                        (unsigned long long)args[i].final_cumulative,
                        args[i].done, args[i].rejected, args[i].rc,
                        (i + 1 < agents) ? "," : "");
            }
            fprintf(f, "  ]\n}\n");
            fclose(f);
            printf("  Ledger JSON              : %s\n", json_path);
        }
    }

    free(all);
    for (int i = 0; i < agents; i++) free(args[i].lat_us);
    free(args);
    free(tids);
    csls_crypto_global_cleanup();
    return (atomic_load(&g_total_reject) == 0) ? 0 : 2;
}
