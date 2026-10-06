// SPDX-License-Identifier: Apache-2.0
//
// RED TEAM — P6/H1: Bloodhound watchtower under concurrent wire taps.
// The advertised deployment is a MEV watcher consuming packets from multiple
// feeds. bloodhound_ctx_t has ZERO atomics: ctx->packets_inspected /
// equivocations_captured are plain ++, and table[slot] fields are plain
// read-modify-write. Two concurrent feeds on one ctx = C11 data races (UB),
// torn evidence records, lost counters. This harness makes the race
// deterministic for TSan: both feeds hammer the SAME (agent, height) keys.
//
// Build (gate command, TSan flavor):
//   gcc -O1 -g -fsanitize=thread -DCSLS_NO_MAIN test/c/test_redteam_hound_race.c \
//       src/causal_daemon.c src/schnorr_bloodhound.c -lcrypto -lpthread -o /tmp/rt_tsan
//   setarch -R /tmp/rt_tsan     (TSan requires ASLR disabled)
// Expected: ThreadSanitizer data-race reports on bloodhound_ctx fields.
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "causal_daemon.h"
#include "schnorr_bloodhound.h"

#define ITERS 40000
static bloodhound_ctx_t *g_hound;
static const uint8_t *G_VPK;

static void make_pkt(csls_cheque_pkt_t *p, const uint8_t *apk, int thread_id, int i) {
    memset(p, 0, sizeof(*p));
    p->magic = CSLS_MAGIC; p->type = CSLS_PKT_CHEQUE;
    memcpy(p->agent_pk, apk, 33);
    memcpy(p->vendor_pk, G_VPK, 33);
    uint64_t h = 500 + (uint64_t)(i % 64);   // heavy (agent,height) overlap
    p->height = h;
    p->cumulative_amt = 1000 + (uint64_t)(thread_id * 7 + i % 5);
    for (int k = 0; k < 8; k++)
        p->challenge_e[k] = (uint8_t)(p->cumulative_amt >> (8 * (7 - k)));
    p->challenge_e[31] ^= (uint8_t)thread_id; // challenge differs -> trap path
    memset(p->sig_s, 0x3C + thread_id, 32);
}

static void *feeder(void *arg) {
    long id = (long)arg;
    uint8_t apk[33]; apk[0] = 0x02; apk[1] = (uint8_t)id;
    for (int i = 1; i < 33; i++) apk[i] = (uint8_t)(0x70 + id * 3 + i);
    for (int i = 0; i < ITERS; i++) {
        csls_cheque_pkt_t p;
        make_pkt(&p, apk, (int)id, i);
        bloodhound_exploit_payload_t pl;
        (void)bloodhound_inspect_packet(g_hound, &p, &pl);  // plain ++ and
        (void)g_hound->packets_inspected;                    // plain reads
    }
    return NULL;
}

int main(void) {
    csls_crypto_global_init();
    uint8_t vsk[32]; memset(vsk, 0x22, 32);
    csls_vendor_ctx_t *V = csls_vendor_new(vsk, 1000000ULL);
    csls_vendor_enable_mac(V, 0); // legacy wire harness: explicit opt-out (secure default mandates Session MAC)
    G_VPK = V->pk;
    g_hound = bloodhound_new((const uint8_t *)"\x11\x22\x33");

    pthread_t t1, t2, t3;
    pthread_create(&t1, NULL, feeder, (void *)1L);
    pthread_create(&t2, NULL, feeder, (void *)2L);
    pthread_create(&t3, NULL, feeder, (void *)3L);
    pthread_join(t1, NULL); pthread_join(t2, NULL); pthread_join(t3, NULL);

    printf("packets_inspected=%llu equivocations_captured=%llu (sum of 3 feeds = %d; "
           "lost updates = plain non-atomic RMW)\n",
           (unsigned long long)g_hound->packets_inspected,
           (unsigned long long)g_hound->equivocations_captured,
           3 * ITERS);

    bloodhound_free(g_hound);
    csls_vendor_free(V);
    csls_crypto_global_cleanup();
    return 0;
}
