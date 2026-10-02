// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers
//
// CSLS Network Daemon (Terminal 1 / causal_term1_core)
//
// A production TCP frontend over the frozen C11 clearing core
// (src/causal_daemon.c). Architecture:
//   * one csls_vendor_ctx_t per process, shared by all connection threads —
//     the vendor mutex inside the core makes equivocation detection global,
//     so a double-sign from two different sockets is still caught;
//   * thread per connection (detached), bounded by max_conns slots;
//   * hot path performs exactly one vendor->lock acquisition per cheque;
//   * the hot path is log-free: only accept/close/fraud/error events print;
//   * shutdown is drain-based (self-pipe wake + SHUT_RDWR + cond wait), so
//     ASan/TSan runs see a quiescent process with zero leaks and zero races.
//
// This file deliberately contains NO cryptographic or clearing logic — it is
// a transport shell around csls_vendor_process_cheque_mac() and friends.

#define _DEFAULT_SOURCE

#include "csls_daemon.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/crypto.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

_Static_assert(sizeof(csls_cheque_pkt_t) == 151, "cheque packet size drift");
_Static_assert(sizeof(csls_cheque_wire_t) == 167, "wire cheque size drift");
_Static_assert(sizeof(csls_ack_pkt_t) == 22, "ack packet size drift");
_Static_assert(sizeof(csls_session_init_pkt_t) == 95, "session init size drift");
_Static_assert(sizeof(csls_welcome_pkt_t) == 38, "welcome packet size drift");

#define DLOG(...) do { fprintf(stderr, "[CSLS-DAEMON] " __VA_ARGS__); fputc('\n', stderr); } while (0)

#define DRAIN_TIMEOUT_SEC 10

typedef struct {
    int fd; // -1 = free slot
} conn_slot_t;

static struct {
    conn_slot_t       *slots;
    int                n_slots;
    csls_vendor_ctx_t *vendor;
    csls_daemon_cfg_t  cfg;
    int                listen_fd;
    int                stop_pipe[2];
} d = { .listen_fd = -1, .stop_pipe = { -1, -1 } };

static _Atomic int      g_stop_flag = 0;
static _Atomic int      g_active_conns = 0;
static _Atomic int      g_running = 0;
static pthread_mutex_t  d_mu = PTHREAD_MUTEX_INITIALIZER; // slots + drain cv
static pthread_cond_t   d_idle_cv = PTHREAD_COND_INITIALIZER;

static int64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000ll + (int64_t)ts.tv_nsec;
}

static void hex_log(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) fprintf(stderr, "%02x", b[i]);
    fputc('\n', stderr);
}

// ACK status mapping (see csls_daemon.h for the wire contract).
static uint8_t map_status(int rc) {
    switch (rc) {
        case 0:   return 0;  // OK
        case -12: return 1;  // EXPOSURE_CAP_REACHED
        case -21:
        case -22: return 2;  // REPLAY / OUT_OF_ORDER
        case -20: return 3;  // FRAUD_EQUIVOCATION_DETECTED
        case -24:
        case -25: return 4;  // SESSION MAC rejected / no session
        default:  return 5;  // INVALID_PACKET / protocol violation
    }
}

// Only a clean accept (0) and a harmless exposure-cap halt (-12) keep the
// connection alive; every replay, forgery and MAC failure severs immediately.
static int sever_on(int rc) {
    return !(rc == 0 || rc == -12);
}

static int send_all(int fd, const void *buf, size_t n) {
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

static int send_ack(int fd, uint64_t h, uint64_t cum, uint8_t status) {
    csls_ack_pkt_t a;
    a.magic = CSLS_MAGIC;
    a.type = CSLS_PKT_ACK;
    a.acknowledged_h = h;
    a.cumulative_amt = cum;
    a.status_code = status;
    return send_all(fd, &a, sizeof(a));
}

// Read exactly n bytes with an absolute per-frame deadline (anti-Slowloris:
// a client may not trickle a frame forever). Returns 0 = complete,
// 1 = deadline hit (partial in *got), -1 = error / orderly EOF.
static int rd_exact(int fd, void *dst, size_t n, size_t *got, int64_t deadline) {
    uint8_t *p = (uint8_t *)dst;
    size_t off = 0;
    *got = 0;
    while (off < n) {
        int64_t rem = deadline - now_ns();
        if (rem <= 0) return 1;
        struct pollfd pf = { .fd = fd, .events = POLLIN };
        int wait_ms = (int)(rem / 1000000);
        if (wait_ms > 100) wait_ms = 100;
        int pr = poll(&pf, 1, wait_ms);
        if (pr < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (pr == 0) continue; // deadline re-checked at loop top
        ssize_t r = recv(fd, p + off, n - off, 0);
        if (r == 0) return -1;
        if (r < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return -1;
        }
        off += (size_t)r;
        *got = off;
    }
    return 0;
}

static int tune_client_socket(int fd) {
    int flag = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
#ifdef TCP_QUICKACK
    setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &flag, sizeof(flag));
#endif
    struct timeval tv;
    tv.tv_sec = CSLS_DAEMON_SOCK_TIMEOUT_SEC;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
    return 0;
}

static void serve_connection(int fd) {
    // Welcome frame: announce the live vendor identity.
    csls_welcome_pkt_t w;
    w.magic = CSLS_MAGIC;
    w.type = CSLS_PKT_WELCOME;
    memcpy(w.vendor_pk, d.vendor->pk, 33);
    if (send_all(fd, &w, sizeof(w)) != 0) return;

    uint8_t buf[sizeof(csls_cheque_wire_t)];
    int legacy = 0; // 151-byte framing adopted after first legacy cheque (--no-mac)

    for (;;) {
        if (atomic_load_explicit(&g_stop_flag, memory_order_relaxed)) return;
        int64_t deadline = now_ns() + (int64_t)CSLS_DAEMON_SOCK_TIMEOUT_SEC * 1000000000ll;

        uint8_t hdr[5];
        size_t got = 0;
        if (rd_exact(fd, hdr, sizeof(hdr), &got, deadline) != 0) {
            if (got > 0)
                DLOG("conn fd=%d: partial frame header (%zu/%zu B), dropping", fd, got, sizeof(hdr));
            return;
        }
        uint32_t magic;
        memcpy(&magic, hdr, 4);
        if (magic != CSLS_MAGIC) {
            DLOG("conn fd=%d: bad magic 0x%08x, dropping", fd, (unsigned)magic);
            return;
        }
        uint8_t type = hdr[4];

        if (type == CSLS_PKT_SESSION_INIT) {
            uint8_t ibuf[sizeof(csls_session_init_pkt_t)];
            memcpy(ibuf, hdr, 5);
            if (rd_exact(fd, ibuf + 5, sizeof(ibuf) - 5, &got, deadline) != 0) {
                DLOG("conn fd=%d: short SESSION_INIT frame, dropping", fd);
                return;
            }
            int rc = csls_vendor_session_init(d.vendor, (const csls_session_init_pkt_t *)ibuf);
            if (send_ack(fd, 0, 0, map_status(rc)) != 0) return;
            if (rc != 0) {
                DLOG("conn fd=%d: SESSION_INIT rejected rc=%d (spoofed or malformed), severing", fd, rc);
                return;
            }
            continue;
        }

        if (type != CSLS_PKT_CHEQUE) {
            DLOG("conn fd=%d: unexpected pkt type 0x%02x, severing", fd, (unsigned)type);
            return;
        }

        // Cheque frame: 167 B wire (151 B payload + 16 B MAC), or a legacy
        // 151 B frame when MAC enforcement is disabled.
        size_t want = legacy ? (sizeof(csls_cheque_pkt_t) - 5)
                             : (sizeof(csls_cheque_wire_t) - 5);
        memcpy(buf, hdr, 5);
        int rrc = rd_exact(fd, buf + 5, want, &got, deadline);
        size_t total = 5 + got;

        if (rrc != 0 && !legacy && total == sizeof(csls_cheque_pkt_t) && !d.cfg.enforce_mac) {
            legacy = 1; // old 151-byte client: adopt its framing for this connection
            rrc = 0;
        } else if (rrc != 0) {
            DLOG("conn fd=%d: short cheque frame (%zu/%zu B), severing", fd,
                 total, (size_t)(legacy ? 151 : 167));
            return;
        }

        csls_fraud_pkt_t fraud;
        memset(&fraud, 0, sizeof(fraud));
        csls_cheque_pkt_t *pkt = (csls_cheque_pkt_t *)buf;
        int rc;
        if (total == sizeof(csls_cheque_wire_t)) {
            rc = csls_vendor_process_cheque_mac(d.vendor, pkt,
                                                buf + sizeof(csls_cheque_pkt_t), &fraud);
        } else {
            rc = csls_vendor_process_cheque(d.vendor, pkt, &fraud);
        }

        uint64_t ack_cum = pkt->cumulative_amt; // on accept the channel equals the packet
        if (rc != 0) {
            uint64_t h_state = 0, accum = 0, cleared = 0;
            csls_vendor_get_channel_state(d.vendor, pkt->agent_pk, &h_state, &accum, &cleared);
            ack_cum = accum;
        }
        if (send_ack(fd, pkt->height, ack_cum, map_status(rc)) != 0) return;

        if (rc == -20) {
            // AXIOM 6: algebraic key extraction done by the core in O(1).
            // Log the proof, hand it to the watcher callback, cut the fraudster.
            DLOG("conn fd=%d: EQUIVOCATION (double-sign) at h=%llu, offender_pk=", fd,
                 (unsigned long long)pkt->height);
            hex_log(pkt->agent_pk, 33);
            DLOG("conn fd=%d: extracted_sk=", fd);
            hex_log(fraud.extracted_sk, 32);
            DLOG("conn fd=%d: fraud proof emitted, connection severed", fd);
            if (d.cfg.fraud_cb) d.cfg.fraud_cb(&fraud, d.cfg.fraud_user);
            return;
        }
        if (sever_on(rc)) {
            DLOG("conn fd=%d: cheque rejected rc=%d (status=%u), severing", fd, rc,
                 (unsigned)map_status(rc));
            return;
        }
        // rc == 0 or -12 (exposure cap reached): keep the stream alive.
    }
}

static void *conn_thread(void *arg) {
    conn_slot_t *slot = (conn_slot_t *)arg;
    int fd = slot->fd;

    atomic_fetch_add_explicit(&g_active_conns, 1, memory_order_acq_rel);
    serve_connection(fd);
    close(fd);

    atomic_fetch_sub_explicit(&g_active_conns, 1, memory_order_acq_rel);
    pthread_mutex_lock(&d_mu);
    slot->fd = -1;
    pthread_cond_broadcast(&d_idle_cv);
    pthread_mutex_unlock(&d_mu);
    return NULL;
}

int csls_daemon_run(const csls_daemon_cfg_t *cfg) {
    if (!cfg) return -1;
    if (atomic_exchange(&g_running, 1) != 0) return -2; // one daemon per process

    d.cfg = *cfg;
    d.n_slots = (cfg->max_conns > 0) ? cfg->max_conns : CSLS_DAEMON_DEFAULT_CONNS;
    int rc = -1;
    int listen_fd = -1;

    if (csls_crypto_global_init() != 0) {
        DLOG("Fatal: OpenSSL secp256k1 initialization failed.");
        goto out;
    }

    d.slots = (conn_slot_t *)calloc((size_t)d.n_slots, sizeof(conn_slot_t));
    if (!d.slots) { DLOG("calloc(slots) failed"); goto out; }
    for (int i = 0; i < d.n_slots; i++) d.slots[i].fd = -1;

    if (pipe(d.stop_pipe) != 0) {
        d.stop_pipe[0] = d.stop_pipe[1] = -1;
        DLOG("pipe() failed: %s", strerror(errno));
        goto out;
    }

    d.vendor = csls_vendor_new(cfg->vendor_sk, cfg->delta_v);
    if (!d.vendor) { DLOG("vendor context initialization failed"); goto out; }
    csls_vendor_enable_mac(d.vendor, cfg->enforce_mac ? 1 : 0);

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { DLOG("socket() failed: %s", strerror(errno)); goto out; }
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(cfg->port);
    if (cfg->bind_addr && cfg->bind_addr[0]) {
        if (inet_pton(AF_INET, cfg->bind_addr, &addr.sin_addr) != 1) {
            DLOG("invalid bind address '%s'", cfg->bind_addr);
            goto out;
        }
    } else {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        DLOG("bind(%u) failed: %s", (unsigned)cfg->port, strerror(errno));
        goto out;
    }
    if (listen(listen_fd, SOMAXCONN) != 0) {
        DLOG("listen() failed: %s", strerror(errno));
        goto out;
    }
    d.listen_fd = listen_fd;

    printf("[CSLS-DAEMON] READY port=%u delta_v=%llu mac=%s vendor_pk=",
           (unsigned)cfg->port, (unsigned long long)cfg->delta_v,
           cfg->enforce_mac ? "ON" : "OFF");
    for (int i = 0; i < 33; i++) printf("%02x", d.vendor->pk[i]);
    printf("\n");
    fflush(stdout);
    DLOG("listening on %s:%u (max_conns=%d, frame timeout %ds)",
         (cfg->bind_addr && cfg->bind_addr[0]) ? cfg->bind_addr : "0.0.0.0",
         (unsigned)cfg->port, d.n_slots, CSLS_DAEMON_SOCK_TIMEOUT_SEC);

    // ---- accept loop (self-pipe wake-up, no lost-shutdown window) ----
    while (!atomic_load_explicit(&g_stop_flag, memory_order_relaxed)) {
        struct pollfd pf[2] = {
            { .fd = d.listen_fd,   .events = POLLIN },
            { .fd = d.stop_pipe[0], .events = POLLIN },
        };
        int pr = poll(pf, 2, -1);
        if (pr < 0) {
            if (errno == EINTR) continue;
            DLOG("poll() failed: %s", strerror(errno));
            break;
        }
        if (pf[1].revents & POLLIN) break; // stop requested
        if (!(pf[0].revents & POLLIN)) continue;

        int cfd = accept(d.listen_fd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            DLOG("accept() failed: %s", strerror(errno));
            continue;
        }
        if (atomic_load_explicit(&g_stop_flag, memory_order_relaxed)) {
            close(cfd);
            break;
        }
        tune_client_socket(cfd);

        conn_slot_t *slot = NULL;
        pthread_mutex_lock(&d_mu);
        for (int i = 0; i < d.n_slots; i++) {
            if (d.slots[i].fd < 0) { slot = &d.slots[i]; slot->fd = cfd; break; }
        }
        pthread_mutex_unlock(&d_mu);
        if (!slot) {
            DLOG("connection limit %d reached, refusing", d.n_slots);
            close(cfd);
            continue;
        }

        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_t tid;
        if (pthread_create(&tid, &attr, conn_thread, slot) != 0) {
            DLOG("pthread_create failed: %s", strerror(errno));
            pthread_mutex_lock(&d_mu);
            slot->fd = -1;
            pthread_mutex_unlock(&d_mu);
            close(cfd);
        }
        pthread_attr_destroy(&attr);
    }
    rc = 0;

    // ---- drain: close listener, wake readers, wait for quiescence ----
    if (d.listen_fd >= 0) { close(d.listen_fd); d.listen_fd = -1; }
    pthread_mutex_lock(&d_mu);
    for (int i = 0; i < d.n_slots; i++) {
        if (d.slots[i].fd >= 0) shutdown(d.slots[i].fd, SHUT_RDWR);
    }
    int64_t drain_deadline = now_ns() + (int64_t)DRAIN_TIMEOUT_SEC * 1000000000ll;
    while (atomic_load_explicit(&g_active_conns, memory_order_acquire) > 0 &&
           now_ns() < drain_deadline) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 100 * 1000000; // 100 ms slices
        if (ts.tv_nsec >= 1000000000l) { ts.tv_sec++; ts.tv_nsec -= 1000000000l; }
        pthread_cond_timedwait(&d_idle_cv, &d_mu, &ts);
    }
    pthread_mutex_unlock(&d_mu);
    if (atomic_load_explicit(&g_active_conns, memory_order_acquire) > 0)
        DLOG("WARNING: %d connection threads still active at drain timeout",
             (int)atomic_load(&g_active_conns));

out:
    if (listen_fd >= 0 && d.listen_fd < 0) close(listen_fd);
    if (d.listen_fd >= 0) { close(d.listen_fd); d.listen_fd = -1; }
    // NOTE: the stop pipe is intentionally never closed. csls_daemon_stop()
    // is async-signal-safe precisely because it only performs an atomic store
    // and a write() to this process-lifetime fd; closing it here would race
    // with a concurrent stop() (TSan-verified). One pipe pair per process.
    if (d.vendor) { csls_vendor_free(d.vendor); d.vendor = NULL; }
    free(d.slots);
    d.slots = NULL;
    atomic_store_explicit(&g_running, 0, memory_order_release);
    return rc;
}

void csls_daemon_stop(void) {
    atomic_store_explicit(&g_stop_flag, 1, memory_order_seq_cst);
    int wfd = d.stop_pipe[1];
    if (wfd >= 0) {
        ssize_t r = write(wfd, "S", 1);
        (void)r;
    }
}

// -----------------------------------------------------------------------------
// STANDALONE BINARY ENTRY POINT
// -----------------------------------------------------------------------------

#ifndef CSLS_DAEMON_NO_MAIN
static void usage(const char *argv0) {
    fprintf(stderr,
            "Causal-Slash Protocol — C11 Network Daemon (vendor node)\n"
            "\n"
            "Usage: %s --port <PORT> --vendor-sk <64 HEX CHARS> [options]\n"
            "\n"
            "Required:\n"
            "  --vendor-sk <HEX>   Vendor secp256k1 secret key, exactly 64 hex chars (32 bytes)\n"
            "Options:\n"
            "  --port <PORT>       TCP listen port (default %d)\n"
            "  --buffer <MICRO>    Per-channel exposure cap in micro-USDC (default %llu = $1.00)\n"
            "  --no-mac            Disable Session MAC enforcement (legacy 151 B clients)\n"
            "  --max-conns <N>     Concurrent connection cap (default %d)\n"
            "  --bind <IP>         Bind address (default 0.0.0.0)\n"
            "  -h, --help          This help\n",
            argv0, CSLS_DEFAULT_PORT,
            (unsigned long long)CSLS_DEFAULT_DELTA_V, CSLS_DAEMON_DEFAULT_CONNS);
}

static int hex_nibble(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_sk_hex(const char *s, uint8_t out[32]) {
    if (!s || strlen(s) != 64) return -1;
    for (int i = 0; i < 32; i++) {
        int hi = hex_nibble((unsigned char)s[2 * i]);
        int lo = hex_nibble((unsigned char)s[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static void on_signal(int sig) {
    (void)sig;
    csls_daemon_stop();
}

int main(int argc, char *argv[]) {
    csls_daemon_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.port = CSLS_DEFAULT_PORT;
    cfg.delta_v = CSLS_DEFAULT_DELTA_V;
    cfg.enforce_mac = 1;
    cfg.max_conns = CSLS_DAEMON_DEFAULT_CONNS;

    const char *sk_hex = NULL;
    const char *bind_addr = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            char *end = NULL;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (!end || *end != '\0' || v < 1 || v > 65535) {
                fprintf(stderr, "invalid --port value\n");
                return 1;
            }
            cfg.port = (uint16_t)v;
        } else if (strcmp(argv[i], "--vendor-sk") == 0 && i + 1 < argc) {
            sk_hex = argv[++i];
        } else if (strcmp(argv[i], "--buffer") == 0 && i + 1 < argc) {
            char *end = NULL;
            unsigned long long v = strtoull(argv[++i], &end, 10);
            if (!end || *end != '\0' || v == 0) {
                fprintf(stderr, "invalid --buffer value (must be > 0 micro-USDC)\n");
                return 1;
            }
            cfg.delta_v = (uint64_t)v;
        } else if (strcmp(argv[i], "--no-mac") == 0) {
            cfg.enforce_mac = 0;
        } else if (strcmp(argv[i], "--max-conns") == 0 && i + 1 < argc) {
            char *end = NULL;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (!end || *end != '\0' || v < 1 || v > 4096) {
                fprintf(stderr, "invalid --max-conns value\n");
                return 1;
            }
            cfg.max_conns = (int)v;
        } else if (strcmp(argv[i], "--bind") == 0 && i + 1 < argc) {
            bind_addr = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 1;
        }
    }
    cfg.bind_addr = bind_addr;

    if (!sk_hex) {
        fprintf(stderr, "error: --vendor-sk is required\n\n");
        usage(argv[0]);
        return 1;
    }
    if (parse_sk_hex(sk_hex, cfg.vendor_sk) != 0) {
        fprintf(stderr, "error: --vendor-sk must be exactly 64 hex chars (32 bytes)\n");
        return 1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // no SA_RESTART: accept()/read() must observe the stop signal
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    int rc = csls_daemon_run(&cfg);

    OPENSSL_cleanse(cfg.vendor_sk, sizeof(cfg.vendor_sk));
    OPENSSL_cleanse((void *)sk_hex, strlen(sk_hex));
    csls_crypto_global_cleanup();
    fprintf(stderr, "[CSLS-DAEMON] shutdown complete (rc=%d)\n", rc);
    return rc == 0 ? 0 : 1;
}
#endif // CSLS_DAEMON_NO_MAIN
