// SPDX-License-Identifier: Apache-2.0
//
// CSLS SWARM SIMULATION — 4,300 agents, 3 tiers of hunters, bounded resources.
//
// PURPOSE (owner-directed): measure at swarm scale whether the fraud detector
// ever emits the private key of an HONEST agent (false positive -> bounty
// farming by framing/restart attacks) and whether real equivocators are
// missed under evidence-eviction pressure (false negatives).
//
// RESOURCE SAFETY (anti-freeze contract):
//   - ONE process, <= 12 threads total (agents are state machines, NOT threads)
//   - bounded memory (~550 MB), RSS watchdog aborts above 3 GB
//   - bounded wall time (default 100 s) + external `timeout` kill switch
//   - bounded queues with drop counters (no unbounded growth)
//   - deterministic metrics derived from per-agent atomic tick counters
//
// HONESTY: every signature/verification/extraction goes through the real
// src/causal_daemon.c + src/schnorr_bloodhound.c API. Zero mocks. The only
// modeled adversaries are wire-level: they produce/consume 151-byte packets
// exactly like a network observer would.
//
// Hunters under test:
//   T1 live Bloodhound ring (65,536 slots, seeded)   — src/schnorr_bloodhound.c
//   T2 vendor history ring (65,536 slots, keyless)   — src/causal_daemon.c
//   T3 archiving hunter (realistic MEV professional: archives victims' and
//      equivocators' traffic, unbounded memory model, capped in harness)
//
// Populations:
//   4,000 honest agents, 6 company profiles (rates, amounts, vendor fan-out)
//   60 restart victims (WAL crash/restart every ~0.8 s — the C1 false-
//     positive vector: post-restart height regression reuses nonces)
//   300 attackers:
//     150 EQUIV — real double-signs, delayed 0..3000 ticks (laundering window)
//      60 FRAME — forged cheques in VICTIMS' names (framing for 15% bounty)
//      40 PROBE — forged cumulative_amt inflation up to/over delta_v
//      50 EVICT — height-flood to flush evidence slots (C3 laundering aid)

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "causal_daemon.h"
#include "schnorr_bloodhound.h"

// ---- scale knobs -----------------------------------------------------------
#define N_HONEST        4000
#define N_VICTIMS       60      // subset of honest, with WAL + chaos restarts
#define N_EQUIV         150
#define N_FRAME         60
#define N_PROBE         40
#define N_EVICT         50
#define N_ATTACK        (N_EQUIV + N_FRAME + N_PROBE + N_EVICT)
#define N_AGENTS        (N_HONEST + N_ATTACK)
#define N_VENDORS       16
#define N_HOUNDS        2
#define N_SIGN_TH       4
#define N_VENDOR_TH     4
#define QCAP            8192
#define WIRE_QCAP       32768
#define ARCH_N          512
#define DEFAULT_TARGET  3000000ULL
#define DEFAULT_WALL_S  100
#define RSS_LIMIT_KB    (3ULL * 1024 * 1024)

#define ST_EQUIV 0
#define ST_FRAME 1
#define ST_PROBE 2
#define ST_EVICT 3

// ---- primitives ------------------------------------------------------------
static inline uint64_t sm64(uint64_t x) {
    x += 0x9E3779B97F4A7C15ULL;
    x ^= x >> 30; x *= 0xBF58476D1CE4E5B9ULL;
    x ^= x >> 27; x *= 0x94D049BB133111EBULL;
    x ^= x >> 31; return x;
}

static uint64_t g_seed;
static inline uint64_t rnd(void) { g_seed = sm64(g_seed); return g_seed; }
// init-time only (single-threaded phase)
// worker-phase RNG: thread-local (global rnd() would be a harness data race)
static _Thread_local uint64_t tls_rng;
static inline uint64_t trnd(void) { tls_rng = sm64(tls_rng); return tls_rng; }

static void make_challenge_e(const uint8_t *agent_pk, const uint8_t *vendor_pk,
                             uint64_t h, uint64_t amt, uint8_t out[32]) {
    uint8_t pre[33 + 33 + 8 + 8];
    memcpy(pre, agent_pk, 33);
    memcpy(pre + 33, vendor_pk, 33);
    for (int i = 0; i < 8; i++) pre[66 + i] = (uint8_t)(h >> (56 - i * 8));
    for (int i = 0; i < 8; i++) pre[74 + i] = (uint8_t)(amt >> (56 - i * 8));
    SHA256(pre, sizeof(pre), out);
}

// ---- archived hunter (T3) --------------------------------------------------
typedef struct {
    uint64_t h, cum;
    uint8_t e[32], s[32];
    bool used, consumed;
} arch_ent_t;
typedef struct { arch_ent_t ent[ARCH_N]; } arch_ring_t;
typedef struct { int n; arch_ring_t ring[8]; } sw_arch_t;

// ---- agent -----------------------------------------------------------------
typedef struct {
    int id, strat;
    uint8_t sk[32], pk[33];
    csls_agent_ctx_t *ctx;
    int n_vendors;
    int vendor_idx[8];
    uint64_t amt_min, amt_max;
    _Atomic uint64_t tick;
    _Atomic uint64_t last_h[8];   // wire-observable last height per vendor ring
    _Atomic int live;
    bool is_victim;
    bool has_session;
    uint64_t last_cum;
    uint64_t evict_h;
    pthread_spinlock_t iolock;
    char wal_path[160];
    // equiv pending state (single owner worker)
    uint64_t pend_until;   // global tick deadline (0 = idle)
    int pend_v;
    uint64_t pend_h;
    _Atomic uint64_t attempts;
    sw_arch_t *arch;
} sw_agent_t;

static sw_agent_t agents[N_AGENTS];
static csls_vendor_ctx_t *vendors[N_VENDORS];
static bloodhound_ctx_t *hounds[N_HOUNDS];

// ---- bounded queues --------------------------------------------------------
typedef struct { csls_cheque_pkt_t pkt; uint8_t mac[16]; int32_t src; } qe_t;
typedef struct {
    pthread_mutex_t mu;
    qe_t buf[QCAP];
    uint32_t head, tail;
    _Atomic uint32_t cnt;
} pktq_t;

static pktq_t vq[N_VENDORS];

static void q_init(pktq_t *q) {
    pthread_mutex_init(&q->mu, NULL);
    q->head = q->tail = 0;
    atomic_init(&q->cnt, 0);
}
static bool q_push(pktq_t *q, const csls_cheque_pkt_t *p, const uint8_t *mac, int32_t src) {
    pthread_mutex_lock(&q->mu);
    if (atomic_load_explicit(&q->cnt, memory_order_relaxed) >= QCAP) {
        pthread_mutex_unlock(&q->mu);
        return false;
    }
    qe_t *e = &q->buf[q->tail & (QCAP - 1)];
    e->pkt = *p;
    if (mac) memcpy(e->mac, mac, 16); else memset(e->mac, 0, 16);
    e->src = src;
    q->tail++;
    atomic_fetch_add_explicit(&q->cnt, 1, memory_order_release);
    pthread_mutex_unlock(&q->mu);
    return true;
}
static bool q_pop(pktq_t *q, qe_t *out) {
    pthread_mutex_lock(&q->mu);
    if (atomic_load_explicit(&q->cnt, memory_order_relaxed) == 0) {
        pthread_mutex_unlock(&q->mu);
        return false;
    }
    *out = q->buf[q->head & (QCAP - 1)];
    q->head++;
    atomic_fetch_sub_explicit(&q->cnt, 1, memory_order_acquire);
    pthread_mutex_unlock(&q->mu);
    return true;
}

// wire queue reuses pktq_t but needs bigger capacity -> separate type
typedef struct {
    pthread_mutex_t mu;
    qe_t buf[WIRE_QCAP];
    uint32_t head, tail;
    _Atomic uint32_t cnt;
} wq_t;
static wq_t g_wire;
static void wq_init(wq_t *q) { pthread_mutex_init(&q->mu, NULL); q->head = q->tail = 0; atomic_init(&q->cnt, 0); }
static bool wq_push(wq_t *q, const csls_cheque_pkt_t *p, const uint8_t *mac, int32_t src) {
    pthread_mutex_lock(&q->mu);
    if (atomic_load_explicit(&q->cnt, memory_order_relaxed) >= WIRE_QCAP) { pthread_mutex_unlock(&q->mu); return false; }
    qe_t *e = &q->buf[q->tail & (WIRE_QCAP - 1)];
    e->pkt = *p;
    if (mac) memcpy(e->mac, mac, 16); else memset(e->mac, 0, 16);
    e->src = src;
    q->tail++;
    atomic_fetch_add_explicit(&q->cnt, 1, memory_order_release);
    pthread_mutex_unlock(&q->mu);
    return true;
}
static bool wq_pop(wq_t *q, qe_t *out) {
    pthread_mutex_lock(&q->mu);
    if (atomic_load_explicit(&q->cnt, memory_order_relaxed) == 0) { pthread_mutex_unlock(&q->mu); return false; }
    *out = q->buf[q->head & (WIRE_QCAP - 1)];
    q->head++;
    atomic_fetch_sub_explicit(&q->cnt, 1, memory_order_acquire);
    pthread_mutex_unlock(&q->mu);
    return true;
}

// ---- sk registry (whose key was extracted?) --------------------------------
#define REG_N 16384
typedef struct { uint8_t sk[32]; int32_t id; bool used; } reg_ent_t;
static reg_ent_t g_reg[REG_N];
static int reg_slot(const uint8_t *sk) {
    uint64_t h = 14695981039346656037ULL;
    for (int i = 0; i < 8; i++) { h ^= sk[i]; h *= 1099511628211ULL; }
    return (int)(h & (REG_N - 1));
}
static void reg_insert(const uint8_t *sk, int32_t id) {
    int i = reg_slot(sk);
    while (g_reg[i].used) i = (i + 1) & (REG_N - 1);
    memcpy(g_reg[i].sk, sk, 32); g_reg[i].id = id; g_reg[i].used = true;
}
static int32_t reg_lookup(const uint8_t *sk) {
    int i = reg_slot(sk);
    while (g_reg[i].used) {
        if (memcmp(g_reg[i].sk, sk, 32) == 0) return g_reg[i].id;
        i = (i + 1) & (REG_N - 1);
    }
    return -1;
}

// ---- metrics ---------------------------------------------------------------
static _Atomic uint64_t g_next_agent;
static _Atomic int g_stop;
static _Atomic uint64_t m_total, m_honest_sent, m_qdrops;
static _Atomic uint64_t m_acc_honest, m_acc_forged, m_forged_rej;
static _Atomic uint64_t m_fraud_true_v, m_fraud_false_v, m_phantom_v;
static _Atomic uint64_t m_hound_true, m_hound_false, m_phantom_h;
static _Atomic uint64_t m_arch_true, m_arch_false, m_phantom_a;
static _Atomic uint64_t m_restarts, m_brick, m_equiv_fired, m_insider_acc, m_forged_rej_mac, m_rc[26];
static _Atomic uint64_t strat_rc[4][27]; // per-strategy vendor rc attribution
static _Atomic uint64_t m_sign_ns, m_sign_n, m_sign_s_n, m_sign_max, m_ver_ns, m_ver_n, m_ver_s_n, m_ver_max;

// ---- helpers ---------------------------------------------------------------
static inline void send_pkt(const csls_cheque_pkt_t *p, const uint8_t *mac, int vendor, int32_t src) {
    if (!q_push(&vq[vendor], p, mac, src)) atomic_fetch_add(&m_qdrops, 1);
    if (!wq_push(&g_wire, p, mac, src)) atomic_fetch_add(&m_qdrops, 1);
}

static void arch_record(sw_agent_t *a, int ring_i, const csls_cheque_pkt_t *pkt) {
    arch_ent_t *e = &a->arch->ring[ring_i].ent[pkt->height & (ARCH_N - 1)];
    e->h = pkt->height; e->cum = pkt->cumulative_amt;
    memcpy(e->e, pkt->challenge_e, 32); memcpy(e->s, pkt->sig_s, 32);
    e->used = true; e->consumed = false;
}
// returns 1 if a capture decision was made
static int arch_check(sw_agent_t *a, int ring_i, const csls_cheque_pkt_t *pkt, bool attacker) {
    arch_ent_t *e = &a->arch->ring[ring_i].ent[pkt->height & (ARCH_N - 1)];
    if (!e->used || e->consumed || e->h != pkt->height) return 0;
    if (memcmp(e->e, pkt->challenge_e, 32) == 0) return 0;
    csls_cheque_pkt_t c1;
    memset(&c1, 0, sizeof(c1));
    c1.magic = CSLS_MAGIC; c1.type = CSLS_PKT_CHEQUE;
    memcpy(c1.agent_pk, a->pk, 33);
    memcpy(c1.vendor_pk, vendors[a->vendor_idx[ring_i]]->pk, 33);
    c1.height = e->h; c1.cumulative_amt = e->cum;
    memcpy(c1.challenge_e, e->e, 32); memcpy(c1.sig_s, e->s, 32);
    uint8_t sk[32];
    if (csls_extract_private_key(&c1, pkt, sk) == 0) {
        e->consumed = true;
        if (memcmp(sk, a->sk, 32) == 0) {
            if (attacker) atomic_fetch_add(&m_arch_true, 1);
            else atomic_fetch_add(&m_arch_false, 1);
            return 1;
        }
        atomic_fetch_add(&m_phantom_a, 1);
        return 1;
    }
    return 0;
}

// ---- honest agent tick -----------------------------------------------------
static void honest_tick(sw_agent_t *a) {
    bool victim = a->is_victim;
    if (victim) {
        pthread_spin_lock(&a->iolock);
        if (!atomic_load_explicit(&a->live, memory_order_acquire)) {
            pthread_spin_unlock(&a->iolock);
            return;
        }
    }
    uint64_t t = atomic_fetch_add(&a->tick, 1) ;
    int vi = (int)(t % (uint64_t)a->n_vendors);
    int v = a->vendor_idx[vi];
    uint64_t span = a->amt_max - a->amt_min + 1;
    uint64_t amt = a->amt_min + sm64(t * 0x9E3779B97F4A7C15ULL ^ (uint64_t)a->id * 0xFF51AFD7ED558CCDULL) % span;

    csls_cheque_pkt_t pkt;
    bool sample = (atomic_fetch_add(&m_sign_n, 1) & 255) == 0;
    struct timespec ts0, ts1;
    if (sample) clock_gettime(CLOCK_MONOTONIC, &ts0);
    uint8_t mac[16];
    int rc = csls_agent_sign_cheque_mac(a->ctx, vendors[v]->pk, amt, &pkt, mac);
    if (sample) {
        clock_gettime(CLOCK_MONOTONIC, &ts1);
        uint64_t ns = (uint64_t)(ts1.tv_sec - ts0.tv_sec) * 1000000000ULL + (uint64_t)(ts1.tv_nsec - ts0.tv_nsec);
        atomic_fetch_add(&m_sign_ns, ns);
        atomic_fetch_add(&m_sign_s_n, 1);
        uint64_t prev = atomic_load(&m_sign_max);
        while (ns > prev && !atomic_compare_exchange_weak(&m_sign_max, &prev, ns)) {}
    }
    if (rc == 0) {
        atomic_fetch_add(&m_honest_sent, 1);
        if (a->arch) {
            arch_check(a, vi, &pkt, false);  // T3: pre-crash evidence comparison
            arch_record(a, vi, &pkt);
        }
        atomic_store_explicit(&a->last_h[vi], pkt.height, memory_order_relaxed);
        send_pkt(&pkt, mac, v, a->id);
    }
    if (victim) pthread_spin_unlock(&a->iolock);
}

// ---- attacker ticks --------------------------------------------------------
static void forge_base(csls_cheque_pkt_t *f, const uint8_t *agent_pk, int v, uint64_t h, uint64_t cum) {
    memset(f, 0, sizeof(*f));
    f->magic = CSLS_MAGIC; f->type = CSLS_PKT_CHEQUE;
    memcpy(f->agent_pk, agent_pk, 33);
    memcpy(f->vendor_pk, vendors[v]->pk, 33);
    f->height = h; f->cumulative_amt = cum;
    make_challenge_e(f->agent_pk, f->vendor_pk, h, cum, f->challenge_e);
}

static void attack_tick(sw_agent_t *a) {
    uint64_t t = atomic_fetch_add(&a->tick, 1);

    if (a->strat == ST_EQUIV) {
        // delayed double-sign: c1 now, c2 after a GLOBAL-tick laundering window
        uint64_t now = atomic_load_explicit(&m_total, memory_order_relaxed);
        if (a->pend_until != 0 && now >= a->pend_until) {
            // malicious client regresses its GLOBAL in-memory height to re-sign h
            atomic_store(&a->ctx->height, a->pend_h);
            csls_cheque_pkt_t c2;
            uint8_t mac2[16];
            uint64_t amt2 = 10000 + trnd() % 40000; // delta; cumulative grows by delta
            if (csls_agent_sign_cheque_mac(a->ctx, vendors[a->pend_v]->pk, amt2, &c2, mac2) == 0) {
                a->last_cum = c2.cumulative_amt; // track the WIRE cumulative, not the delta
                arch_check(a, 0, &c2, true);
                send_pkt(&c2, mac2, a->pend_v, a->id);
            }
            a->pend_until = 0;
            atomic_fetch_add(&m_equiv_fired, 1);
        } else if (a->pend_until == 0 && (sm64(t ^ 0xABCD) % 16) == 0) {
            csls_cheque_pkt_t c1;
            uint8_t mac1[16];
            uint64_t amt1 = 10000 + trnd() % 40000; // delta
            if (csls_agent_sign_cheque_mac(a->ctx, vendors[a->vendor_idx[0]]->pk, amt1, &c1, mac1) == 0) {
                a->last_cum = c1.cumulative_amt;
                if (a->arch) arch_record(a, 0, &c1);
                send_pkt(&c1, mac1, a->vendor_idx[0], a->id);
                a->pend_v = a->vendor_idx[0];
                a->pend_h = c1.height;
                a->pend_until = now + 50 + trnd() % 4000; // laundering window
                atomic_fetch_add(&a->attempts, 1);
            }
        }
        return;
    }

    int v = (int)(trnd() % N_VENDORS);
    csls_cheque_pkt_t f;
    uint8_t mac[16];
    if (a->strat == ST_FRAME || a->strat == ST_PROBE) {
        int victim = (int)(trnd() % N_HONEST);
        sw_agent_t *va = &agents[victim];
        int vi = (int)(trnd() % (uint64_t)va->n_vendors);
        v = va->vendor_idx[vi];
        uint64_t last = atomic_load_explicit(&va->last_h[vi], memory_order_relaxed);
        uint64_t h;
        uint32_t m = (uint32_t)(trnd() % 10);
        if (m < 4 && last > 0) h = last;                               // direct collision frame
        else if (m < 7 && last > 0) h = last + 65536ULL * (1 + trnd() % 3); // slot-shift frame
        else h = 1 + trnd() % 300000;                                  // blind forgery
        uint64_t cum = (a->strat == ST_PROBE)
            ? (5000000 + trnd() % 50000000)
            : (100 + trnd() % 200000);
        forge_base(&f, va->pk, v, h, cum);
        memset(f.sig_s, 0x01, 32);
        f.sig_s[0] ^= (uint8_t)trnd(); f.sig_s[31] ^= (uint8_t)trnd();
        memset(mac, 0x5A, 16); // attacker has no session key -> stale garbage tag
    } else { // ST_EVICT: registered insider with a REAL session (keyed noise)
        v = a->vendor_idx[0]; // insider floods the vendor it holds a session with
        uint64_t h = ++a->evict_h; // monotonic flood: packets ACCEPTED, slots overwritten
        forge_base(&f, a->pk, v, h, 1000);
        memset(f.sig_s, 0x02, 32);
        f.sig_s[0] ^= (uint8_t)trnd();
        if (csls_agent_mac_packet(a->ctx, vendors[v]->pk, &f, mac) != 0)
            memset(mac, 0, 16);
    }
    atomic_fetch_add(&a->attempts, 1);
    send_pkt(&f, mac, v, a->id);
}

// ---- worker threads --------------------------------------------------------
static void *sign_worker(void *arg) {
    int wid = (int)(intptr_t)arg;
    tls_rng = sm64(g_seed ^ (0x9E3779B97F4A7C15ULL * (uint64_t)(wid + 1)));
    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        uint32_t i = atomic_fetch_add(&g_next_agent, 1) % N_AGENTS;
        sw_agent_t *a = &agents[i];
        if (i >= N_HONEST && (i % (uint32_t)N_SIGN_TH) != (uint32_t)wid) continue;
        if (i < N_HONEST) honest_tick(a);
        else attack_tick(a);
        atomic_fetch_add(&m_total, 1);
    }
    return NULL;
}

static void *vendor_worker(void *arg) {
    int wid = (int)(intptr_t)arg;
    qe_t qe;
    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        bool did = false;
        for (int vi = 0; vi < N_VENDORS / N_VENDOR_TH; vi++) {
            int v = wid * (N_VENDORS / N_VENDOR_TH) + vi;
            while (q_pop(&vq[v], &qe)) {
                did = true;
                csls_fraud_pkt_t fraud;
                struct timespec ts0, ts1;
                bool sample = (atomic_fetch_add(&m_ver_n, 1) & 255) == 0;
                if (sample) clock_gettime(CLOCK_MONOTONIC, &ts0);
                int rc = csls_vendor_process_cheque_mac(vendors[v], &qe.pkt, qe.mac, &fraud);
                if (sample) {
                    clock_gettime(CLOCK_MONOTONIC, &ts1);
                    uint64_t ns = (uint64_t)(ts1.tv_sec - ts0.tv_sec) * 1000000000ULL + (uint64_t)(ts1.tv_nsec - ts0.tv_nsec);
                    atomic_fetch_add(&m_ver_ns, ns);
                    atomic_fetch_add(&m_ver_s_n, 1);
                    uint64_t prev = atomic_load(&m_ver_max);
                    while (ns > prev && !atomic_compare_exchange_weak(&m_ver_max, &prev, ns)) {}
                }
                if (rc == 0) {
                    if (qe.src >= N_HONEST && agents[qe.src].has_session)
                        atomic_fetch_add(&m_insider_acc, 1);       // legit insider noise (EVICT)
                    else if (qe.src >= N_HONEST)
                        atomic_fetch_add(&m_acc_forged, 1);        // MUST stay 0 post-C2
                    else
                        atomic_fetch_add(&m_acc_honest, 1);
                    // settlement cadence applies to every channel alike
                    if ((atomic_fetch_add(&m_rc[0], 1) & 3) == 0)
                        csls_vendor_advance_cleared(vendors[v], qe.pkt.agent_pk, qe.pkt.cumulative_amt);
                } else if (rc == -20) {
                    int32_t id = reg_lookup(fraud.extracted_sk);
                    if (id < 0) atomic_fetch_add(&m_phantom_v, 1);
                    else if (id < N_HONEST) atomic_fetch_add(&m_fraud_false_v, 1);
                    else atomic_fetch_add(&m_fraud_true_v, 1);
                } else {
                    int b = -rc; if (b > 25) b = 25;
                    atomic_fetch_add(&m_rc[b], 1);
                    if (qe.src >= N_HONEST) {
                        int st = agents[qe.src].strat;
                        if (st < 0 || st > 3) st = 3;
                        atomic_fetch_add(&strat_rc[st][b], 1);
                    }
                    if (rc == -23 && qe.src >= N_HONEST) atomic_fetch_add(&m_forged_rej, 1);
                    if (rc == -22 && qe.src < N_VICTIMS) atomic_fetch_add(&m_brick, 1);
                }
            }
        }
        if (!did) usleep(200);
    }
    return NULL;
}

static void *hound_worker(void *arg) {
    int hid = (int)(intptr_t)arg;
    qe_t qe;
    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        if (!wq_pop(&g_wire, &qe)) { usleep(200); continue; }
        bloodhound_exploit_payload_t payload;
        int rc = bloodhound_inspect_packet(hounds[hid], &qe.pkt, &payload);
        if (rc == 1) {
            int32_t id = reg_lookup(payload.extracted_sk);
            if (id < 0) atomic_fetch_add(&m_phantom_h, 1);
            else if (id < N_HONEST) atomic_fetch_add(&m_hound_false, 1);
            else atomic_fetch_add(&m_hound_true, 1);
        }
    }
    return NULL;
}

static void *chaos_worker(void *arg) {
    (void)arg;
    int i = 0;
    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        usleep(800000);
        sw_agent_t *a = &agents[i % N_VICTIMS];
        pthread_spin_lock(&a->iolock);
        atomic_store_explicit(&a->live, 0, memory_order_release);
        csls_agent_free(a->ctx);
        a->ctx = csls_agent_new(a->sk, a->wal_path);
        if (a->ctx) {
            // re-establish MAC sessions with the new process-lifetime keys
            for (int vi = 0; vi < a->n_vendors; vi++) {
                csls_session_init_pkt_t init;
                if (csls_agent_session_begin(a->ctx, vendors[a->vendor_idx[vi]]->pk, &init) == 0)
                    csls_vendor_session_init(vendors[a->vendor_idx[vi]], &init);
            }
            // Proof-Carrying Restart Handshake: adopt the vendor's provable head
            for (int vi = 0; vi < a->n_vendors; vi++) {
                csls_cheque_pkt_t head;
                if (csls_vendor_get_head_cheque(vendors[a->vendor_idx[vi]], a->pk, &head) == 0)
                    csls_agent_restore_session(a->ctx, vendors[a->vendor_idx[vi]]->pk, &head);
            }
        }
        atomic_store_explicit(&a->live, 1, memory_order_release);
        pthread_spin_unlock(&a->iolock);
        atomic_fetch_add(&m_restarts, 1);
        i++;
    }
    return NULL;
}

static size_t rss_kb(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[256]; size_t kb = 0;
    while (fgets(line, sizeof(line), f))
        if (sscanf(line, "VmRSS: %zu kB", &kb) == 1) break;
    fclose(f);
    return kb;
}

int main(int argc, char **argv) {
    uint64_t target = DEFAULT_TARGET;
    int wall_s = DEFAULT_WALL_S;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--cheques") && i + 1 < argc) target = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--seconds") && i + 1 < argc) wall_s = atoi(argv[++i]);
    }

    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("=== CSLS SWARM SIMULATION ===\n");
    printf("agents=%d honest (%d restart victims) + %d attackers | vendors=%d hounds=%d threads=%d\n",
           N_HONEST, N_VICTIMS, N_ATTACK, N_VENDORS, N_HOUNDS,
           N_SIGN_TH + N_VENDOR_TH + N_HOUNDS + 1 + 1);
    printf("resource caps: 1 process, bounded queues, RSS watchdog %llu MB, wall cap %d s\n",
           (unsigned long long)(RSS_LIMIT_KB / 1024), wall_s);

    // clean WAL dir
    if (system("rm -rf /tmp/csls_swarm_wal && mkdir -p /tmp/csls_swarm_wal") != 0) { fprintf(stderr, "wal dir prep failed\n"); return 1; }

    if (csls_crypto_global_init() != 0) { fprintf(stderr, "crypto init failed\n"); return 1; }

    RAND_bytes((unsigned char *)&g_seed, sizeof(g_seed));
    printf("master seed: 0x%016llx\n", (unsigned long long)g_seed);

    // vendors
    for (int v = 0; v < N_VENDORS; v++) {
        uint8_t vsk[32]; RAND_bytes(vsk, 32);
        vendors[v] = csls_vendor_new(vsk, 100000000ULL); // $100 delta_v
        if (!vendors[v]) { fprintf(stderr, "vendor_new failed\n"); return 1; }
        csls_vendor_enable_mac(vendors[v], 1); // C2 enforced fleet-wide
    }

    // honest agents
    static const struct { const char *name; int nv_min, nv_max; uint64_t amin, amax; } prof[6] = {
        { "LLM-API",      1, 2,      100,    1000 },
        { "GPU-Rent",     2, 3,    10000,  100000 },
        { "VectorDB",     3, 5,     1000,   10000 },
        { "Data-Broker",  1, 1,    50000, 1000000 },
        { "Infer-Router", 4, 8,      100,     500 },
        { "Sleepy-Corp",  1, 1,   500000, 1000000 },
    };
    size_t counts[6] = {0,0,0,0,0,0};
    for (int i = 0; i < N_HONEST; i++) {
        sw_agent_t *a = &agents[i];
        memset(a, 0, sizeof(*a));
        a->id = i;
        RAND_bytes(a->sk, 32);
        int p = i % 6;
        a->n_vendors = prof[p].nv_min + (int)(rnd() % (uint64_t)(prof[p].nv_max - prof[p].nv_min + 1));
        if (i < N_VICTIMS) a->n_vendors = 2;
        for (int k = 0; k < a->n_vendors; k++) {
            int v; bool dup;
            do {
                dup = false;
                v = (int)(rnd() % N_VENDORS);
                for (int j = 0; j < k; j++) if (a->vendor_idx[j] == v) dup = true;
            } while (dup);
            a->vendor_idx[k] = v;
        }
        a->amt_min = prof[p].amin; a->amt_max = prof[p].amax;
        atomic_init(&a->tick, 0); atomic_init(&a->live, 1);
        for (int k = 0; k < 8; k++) atomic_init(&a->last_h[k], 0);
        pthread_spin_init(&a->iolock, PTHREAD_PROCESS_PRIVATE);
        a->is_victim = i < N_VICTIMS;
        if (a->is_victim) {
            snprintf(a->wal_path, sizeof(a->wal_path), "/tmp/csls_swarm_wal/victim_%d.wal", i);
            unlink(a->wal_path);
        }
        a->ctx = csls_agent_new(a->sk, a->is_victim ? a->wal_path : NULL);
        if (!a->ctx) { fprintf(stderr, "agent_new failed at %d\n", i); return 1; }
        memcpy(a->pk, a->ctx->pk, 33);
        reg_insert(a->sk, i);
        for (int vi = 0; vi < a->n_vendors; vi++) {
            csls_session_init_pkt_t init;
            if (csls_agent_session_begin(a->ctx, vendors[a->vendor_idx[vi]]->pk, &init) != 0 ||
                csls_vendor_session_init(vendors[a->vendor_idx[vi]], &init) != 0) {
                fprintf(stderr, "session setup failed at %d\n", i);
                return 1;
            }
        }
        a->has_session = true;
        counts[p]++;
    }
    for (int p = 0; p < 6; p++) printf("  profile %-12s : %zu agents\n", prof[p].name, counts[p]);

    // attackers
    for (int k = 0; k < N_ATTACK; k++) {
        int i = N_HONEST + k;
        sw_agent_t *a = &agents[i];
        memset(a, 0, sizeof(*a));
        a->id = i;
        RAND_bytes(a->sk, 32);
        a->strat = (k < N_EQUIV) ? ST_EQUIV : (k < N_EQUIV + N_FRAME) ? ST_FRAME
                 : (k < N_EQUIV + N_FRAME + N_PROBE) ? ST_PROBE : ST_EVICT;
        a->n_vendors = 1;
        a->vendor_idx[0] = (int)(rnd() % N_VENDORS);
        a->amt_min = 100; a->amt_max = 1000000;
        atomic_init(&a->tick, 0); atomic_init(&a->live, 1);
        pthread_spin_init(&a->iolock, PTHREAD_PROCESS_PRIVATE);
        a->ctx = csls_agent_new(a->sk, NULL);
        if (!a->ctx) { fprintf(stderr, "agent_new failed at %d\n", i); return 1; }
        memcpy(a->pk, a->ctx->pk, 33);
        reg_insert(a->sk, i);
        if (a->strat == ST_EQUIV) {
            a->arch = calloc(1, sizeof(sw_arch_t));
            a->arch->n = 1;
        }
        // EQUIV and EVICT operate as registered insiders (real sessions);
        // FRAME/PROBE stay sessionless outsiders (their packets must die on MAC)
        if (a->strat == ST_EQUIV || a->strat == ST_EVICT) {
            csls_session_init_pkt_t init;
            if (csls_agent_session_begin(a->ctx, vendors[a->vendor_idx[0]]->pk, &init) != 0 ||
                csls_vendor_session_init(vendors[a->vendor_idx[0]], &init) != 0) {
                fprintf(stderr, "attacker session setup failed at %d\n", i);
                return 1;
            }
            a->has_session = true;
        }
    }
    for (int i = 0; i < N_VICTIMS; i++) {
        agents[i].arch = calloc(1, sizeof(sw_arch_t));
        agents[i].arch->n = agents[i].n_vendors;
    }
    printf("attackers: %d EQUIV / %d FRAME / %d PROBE / %d EVICT\n", N_EQUIV, N_FRAME, N_PROBE, N_EVICT);

    // hounds + queues
    static const uint8_t hunter[20] = {0xDE,0xAD,0xBE,0xEF,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    for (int h = 0; h < N_HOUNDS; h++) hounds[h] = bloodhound_new(hunter);
    for (int v = 0; v < N_VENDORS; v++) q_init(&vq[v]);
    wq_init(&g_wire);

    printf("init done, RSS=%zu MB — starting swarm\n", rss_kb() / 1024);

    // threads
    pthread_t th[N_SIGN_TH + N_VENDOR_TH + N_HOUNDS + 1];
    for (int w = 0; w < N_SIGN_TH; w++) pthread_create(&th[w], NULL, sign_worker, (void *)(intptr_t)w);
    for (int w = 0; w < N_VENDOR_TH; w++) pthread_create(&th[N_SIGN_TH + w], NULL, vendor_worker, (void *)(intptr_t)w);
    for (int h = 0; h < N_HOUNDS; h++) pthread_create(&th[N_SIGN_TH + N_VENDOR_TH + h], NULL, hound_worker, (void *)(intptr_t)h);
    pthread_create(&th[N_SIGN_TH + N_VENDOR_TH + N_HOUNDS], NULL, chaos_worker, NULL);

    // supervisor
    struct timespec t_start, t_now;
    clock_gettime(CLOCK_MONOTONIC, &t_start);
    bool rss_breach = false;
    while (true) {
        usleep(5000000);
        clock_gettime(CLOCK_MONOTONIC, &t_now);
        double el = (double)(t_now.tv_sec - t_start.tv_sec);
        size_t kb = rss_kb();
        printf("[t=%5.1fs] ticks=%llu honest_sent=%llu acc_honest=%llu acc_forged=%llu fraud(T/F)=%llu/%llu hound(T/F)=%llu/%llu arch(T/F)=%llu/%llu restarts=%llu RSS=%zuMB\n",
               el,
               (unsigned long long)atomic_load(&m_total),
               (unsigned long long)atomic_load(&m_honest_sent),
               (unsigned long long)atomic_load(&m_acc_honest),
               (unsigned long long)atomic_load(&m_acc_forged),
               (unsigned long long)atomic_load(&m_fraud_true_v),
               (unsigned long long)atomic_load(&m_fraud_false_v),
               (unsigned long long)atomic_load(&m_hound_true),
               (unsigned long long)atomic_load(&m_hound_false),
               (unsigned long long)atomic_load(&m_arch_true),
               (unsigned long long)atomic_load(&m_arch_false),
               (unsigned long long)atomic_load(&m_restarts),
               kb / 1024);
        if (kb > RSS_LIMIT_KB) { rss_breach = true; printf("!!! RSS WATCHDOG BREACH — aborting\n"); break; }
        if (atomic_load(&m_total) >= target) { printf("cheque budget reached\n"); break; }
        if (el >= wall_s) { printf("wall clock cap reached\n"); break; }
    }
    atomic_store(&g_stop, 1);
    for (size_t i = 0; i < sizeof(th) / sizeof(th[0]); i++) pthread_join(th[i], NULL);

    // ---- final report ----
    clock_gettime(CLOCK_MONOTONIC, &t_now);
    double el = (double)(t_now.tv_sec - t_start.tv_sec);
    uint64_t equiv_attempts = 0, frame_attempts = 0, probe_attempts = 0, evict_attempts = 0;
    for (int i = N_HONEST; i < N_AGENTS; i++) {
        uint64_t at = atomic_load(&agents[i].attempts);
        if (agents[i].strat == ST_EQUIV) equiv_attempts += at;
        else if (agents[i].strat == ST_FRAME) frame_attempts += at;
        else if (agents[i].strat == ST_PROBE) probe_attempts += at;
        else evict_attempts += at;
    }
    uint64_t ftrue = atomic_load(&m_fraud_true_v), ffalse = atomic_load(&m_fraud_false_v);
    uint64_t htrue = atomic_load(&m_hound_true), hfalse = atomic_load(&m_hound_false);
    uint64_t atrue = atomic_load(&m_arch_true), afalse = atomic_load(&m_arch_false);
    uint64_t restarts = atomic_load(&m_restarts);

    printf("\n=================== SWARM RESULTS ===================\n");
    printf("wall: %.1fs | ticks: %llu | RSS final: %zu MB | qdrops: %llu | rss_breach=%d\n",
           el, (unsigned long long)atomic_load(&m_total), rss_kb() / 1024,
           (unsigned long long)atomic_load(&m_qdrops), (int)rss_breach);
    printf("honest sent: %llu | honest accepted by vendor: %llu\n",
           (unsigned long long)atomic_load(&m_honest_sent), (unsigned long long)atomic_load(&m_acc_honest));
    for (int b = 1; b < 26; b++) {
        uint64_t c = atomic_load(&m_rc[b]);
        if (c) printf("  vendor rc=-%d : %llu\n", b, (unsigned long long)c);
    }
    if (atomic_load(&m_sign_s_n))
        printf("sign latency (sampled): avg %.0f ns, max %.0f ns over %llu samples\n",
               (double)atomic_load(&m_sign_ns) / (double)atomic_load(&m_sign_s_n),
               (double)atomic_load(&m_sign_max),
               (unsigned long long)atomic_load(&m_sign_s_n));
    if (atomic_load(&m_ver_s_n))
        printf("vendor verify (sampled): avg %.0f ns, max %.0f ns over %llu samples\n",
               (double)atomic_load(&m_ver_ns) / (double)atomic_load(&m_ver_s_n),
               (double)atomic_load(&m_ver_max),
               (unsigned long long)atomic_load(&m_ver_s_n));

    printf("\n--- REAL FRAUD (equivocators): %llu attempts, %llu completed double-signs ---\n",
           (unsigned long long)equiv_attempts, (unsigned long long)atomic_load(&m_equiv_fired));
    printf("  T2 vendor caught:   %llu\n", (unsigned long long)ftrue);
    printf("  T1 hound caught:    %llu\n", (unsigned long long)htrue);
    printf("  T3 archive caught:  %llu\n", (unsigned long long)atrue);
    printf("  => an archiving adversary catches what the 65k rings miss\n");

    printf("\n--- FALSE POSITIVES (keys of HONEST agents extracted) ---\n");
    printf("  T2 vendor:    %llu\n", (unsigned long long)ffalse);
    printf("  T1 hound:     %llu\n", (unsigned long long)hfalse);
    printf("  T3 archiver:  %llu\n", (unsigned long long)afalse);
    printf("  restarts: %llu -> false captures per restart: vendor %.3f hound %.3f archiver %.3f\n",
           (unsigned long long)restarts,
           restarts ? (double)ffalse / (double)restarts : 0.0,
           restarts ? (double)hfalse / (double)restarts : 0.0,
           restarts ? (double)afalse / (double)restarts : 0.0);
    printf("  honest-agent brick rejects (rc=-22 after restart): %llu\n",
           (unsigned long long)atomic_load(&m_brick));

    printf("\n--- PER-STRATEGY VENDOR RC ATTRIBUTION ---\n");
    for (int st = 0; st < 4; st++) {
        printf("  strat %d (0=EQUIV 1=FRAME 2=PROBE 3=EVICT): ", st);
        for (int b = 0; b <= 25; b++) {
            uint64_t c = atomic_load(&strat_rc[st][b]);
            if (c) printf("rc%s%d=%llu ", b == 0 ? "+" : "-", b, (unsigned long long)c);
        }
        printf("\n");
    }

    printf("\n--- INSIDER NOISE (EVICT, MAC-valid) ---\n");
    printf("  insider packets accepted (eviction pressure): %llu\n",
           (unsigned long long)atomic_load(&m_insider_acc));

    printf("\n--- FRAMING / FORGERY ---\n");
    printf("  forged packets rejected at the MAC gate (-24): %llu\n",
           (unsigned long long)atomic_load(&m_forged_rej_mac));
    printf("  FRAME attempts: %llu | PROBE attempts: %llu | EVICT packets: %llu\n",
           (unsigned long long)frame_attempts, (unsigned long long)probe_attempts,
           (unsigned long long)evict_attempts);
    printf("  forged cheques ACCEPTED by vendors (C2): %llu\n",
           (unsigned long long)atomic_load(&m_acc_forged));
    printf("  forged collisions rejected by derived_pk check (-23): %llu\n",
           (unsigned long long)atomic_load(&m_forged_rej));

    printf("\n--- EXTRACTION INTEGRITY ---\n");
    printf("  phantom keys (not matching ANY registered agent): vendor %llu, hound %llu, arch %llu\n",
           (unsigned long long)atomic_load(&m_phantom_v),
           (unsigned long long)atomic_load(&m_phantom_h),
           (unsigned long long)atomic_load(&m_phantom_a));
    printf("=====================================================\n");

    // ---- ZERO-TOLERANCE CI GATE (exit code is the verdict) ----
    // PASS requires ALL of: arch_false == 0 && forged_accepted == 0 &&
    // honest acceptance >= 99.9% (per-mille >= 999). Anything else => exit(1).
    uint64_t acc_h = atomic_load(&m_acc_honest);
    uint64_t sent_h = atomic_load(&m_honest_sent);
    uint64_t permille = sent_h ? (acc_h * 1000ULL) / sent_h : 0ULL;
    int gate_ok = (atomic_load(&m_arch_false) == 0) &&
                  (atomic_load(&m_acc_forged) == 0) &&
                  (permille >= 999);

    printf("\n=== CI GATE: arch_false=%llu | forged_accepted=%llu | honest=%llu.%llu%% (>=99.9%% required) -> %s ===\n",
           (unsigned long long)atomic_load(&m_arch_false),
           (unsigned long long)atomic_load(&m_acc_forged),
           (unsigned long long)(permille / 10), (unsigned long long)(permille % 10),
           gate_ok ? "PASS" : "FAIL");

    // cleanup
    for (int i = 0; i < N_AGENTS; i++) {
        if (agents[i].ctx) csls_agent_free(agents[i].ctx);
        pthread_spin_destroy(&agents[i].iolock);
        free(agents[i].arch);
    }
    for (int v = 0; v < N_VENDORS; v++) csls_vendor_free(vendors[v]);
    for (int h = 0; h < N_HOUNDS; h++) bloodhound_free(hounds[h]);
    csls_crypto_global_cleanup();
    return gate_ok ? 0 : 1;
}
