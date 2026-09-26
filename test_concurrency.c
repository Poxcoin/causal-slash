#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <assert.h>
#include <string.h>

#define NUM_THREADS 32
#define OPS_PER_THREAD 100000
#define TOTAL_OPS (NUM_THREADS * OPS_PER_THREAD)

// Global atomic monotonic state height
static _Atomic uint64_t global_height = 0;

// Bitmap to verify ZERO duplicate heights ever generated
static uint8_t *height_bitmap;
static _Atomic uint64_t collision_counter = 0;

typedef struct {
    int thread_id;
    uint64_t success_count;
} ThreadArg;

void* agent_worker(void* arg) {
    ThreadArg* targ = (ThreadArg*)arg;
    for (int i = 0; i < OPS_PER_THREAD; i++) {
        // Atomic fetch and add guarantees strict serialization in hardware CPU cache line (LOCK XADD)
        uint64_t h = atomic_fetch_add_explicit(&global_height, 1, memory_order_seq_cst);
        
        // Check bitmap for duplicate
        uint64_t byte_idx = h / 8;
        uint8_t bit_mask = 1 << (h % 8);
        
        // If this bit was already set, we had a fatal duplicate nonce!
        uint8_t prev = __atomic_fetch_or(&height_bitmap[byte_idx], bit_mask, __ATOMIC_SEQ_CST);
        if (prev & bit_mask) {
            atomic_fetch_add(&collision_counter, 1);
        }
        targ->success_count++;
    }
    return NULL;
}

int main() {
    printf("--- STRESS TEST 1: Concurrency Race Condition (32 Threads, 3.2M Ops) ---\n");
    height_bitmap = (uint8_t*)calloc((TOTAL_OPS / 8) + 1, sizeof(uint8_t));
    assert(height_bitmap != NULL);

    pthread_t threads[NUM_THREADS];
    ThreadArg args[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id = i;
        args[i].success_count = 0;
        pthread_create(&threads[i], NULL, agent_worker, &args[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("Total Operations: %ld\n", (long)global_height);
    printf("Duplicate Nonce Collisions: %ld\n", (long)collision_counter);
    assert(collision_counter == 0);
    printf("RESULT: ZERO collisions! Hardware atomic fetch-and-add completely neutralizes accidental suicide.\n");

    free(height_bitmap);
    return 0;
}
