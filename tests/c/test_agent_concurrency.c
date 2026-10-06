// SPDX-License-Identifier: Apache-2.0
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <assert.h>
#include <string.h>
#include "causal_daemon.h"

#define NUM_THREADS 16
#define CHEQUES_PER_THREAD 5000
#define DELTA_PER_CHEQUE 100ULL // 100 micro USDC

static csls_agent_ctx_t g_agent;
static uint8_t g_vendor_pk[33];

typedef struct {
    int thread_id;
    uint64_t cheques_signed;
} WorkerArg;

void* signing_worker(void* arg) {
    WorkerArg* w = (WorkerArg*)arg;
    for (int i = 0; i < CHEQUES_PER_THREAD; i++) {
        csls_cheque_pkt_t pkt;
        int res = csls_agent_sign_cheque(&g_agent, g_vendor_pk, DELTA_PER_CHEQUE, &pkt);
        assert(res == 0);
        assert(pkt.magic == CSLS_MAGIC);
        assert(pkt.type == CSLS_PKT_CHEQUE);
        w->cheques_signed++;
    }
    return NULL;
}

int main() {
    printf("--- CONCURRENT AGENT SIGNING STRESS TEST (%d Threads x %d Cheques) ---\n", 
           NUM_THREADS, CHEQUES_PER_THREAD);

    int cr = csls_crypto_global_init();
    assert(cr == 0);

    uint8_t agent_sk[32];
    memset(agent_sk, 0x42, 32);

    int ar = csls_agent_init(&g_agent, agent_sk, NULL);
    assert(ar == 0);

    // Dummy vendor pk
    memcpy(g_vendor_pk, g_agent.pk, 33);

    pthread_t threads[NUM_THREADS];
    WorkerArg args[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id = i;
        args[i].cheques_signed = 0;
        pthread_create(&threads[i], NULL, signing_worker, &args[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
        assert(args[i].cheques_signed == CHEQUES_PER_THREAD);
    }

    uint64_t expected_total_cheques = (uint64_t)NUM_THREADS * CHEQUES_PER_THREAD;
    uint64_t expected_cumulative = expected_total_cheques * DELTA_PER_CHEQUE;

    csls_channel_t *chan = csls_channel_get_or_create(&g_agent.channels, g_vendor_pk);
    assert(chan != NULL);

    printf("Final Channel Height: %lu (Expected: %lu)\n", 
           (unsigned long)chan->height, (unsigned long)expected_total_cheques);
    printf("Final Global Agent Height: %lu (Expected: %lu)\n", 
           (unsigned long)atomic_load(&g_agent.height), (unsigned long)(expected_total_cheques + 1));
    printf("Final Cumulative Sent: %lu micro-USDC (Expected: %lu)\n", 
           (unsigned long)chan->cumulative_sent, (unsigned long)expected_cumulative);

    assert(chan->height == expected_total_cheques);
    assert(atomic_load(&g_agent.height) == expected_total_cheques + 1);
    assert(chan->cumulative_sent == expected_cumulative);

    csls_agent_destroy(&g_agent);
    csls_crypto_global_cleanup();

    printf("[SUCCESS] All %lu cheques signed concurrently without race conditions or lost updates.\n", 
           (unsigned long)expected_total_cheques);
    return 0;
}
