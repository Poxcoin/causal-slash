#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

// Sliding Window of 10,000 active slots per agent
// Using a dense bitset: 10,000 bits = 1,250 bytes per agent!
#define NUM_AGENTS 10000
#define WINDOW_SIZE 10000
#define BYTES_PER_AGENT (WINDOW_SIZE / 8)

typedef struct {
    uint64_t base_epoch;
    uint8_t bitset[BYTES_PER_AGENT];
} AgentWindow;

int main() {
    printf("--- STRESS TEST 2: History Buffer Memory Bloat Simulation ---\n");
    size_t total_memory_bytes = NUM_AGENTS * sizeof(AgentWindow);
    printf("Target Scale: %d concurrent agents with 10,000 tx sliding window each\n", NUM_AGENTS);
    printf("Total RAM allocated for all 10,000 agents: %.2f Megabytes\n", total_memory_bytes / (1024.0 * 1024.0));

    AgentWindow* windows = (AgentWindow*)malloc(total_memory_bytes);
    if (!windows) {
        printf("Memory allocation failed!\n");
        return 1;
    }
    memset(windows, 0, total_memory_bytes);

    // Benchmark 5,000,000 lookups and updates
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int operations = 5000000;
    int collisions_detected = 0;

    for (int i = 0; i < operations; i++) {
        uint32_t agent_id = (i * 37) % NUM_AGENTS;
        uint32_t offset = (i * 13) % WINDOW_SIZE;

        uint32_t byte_idx = offset / 8;
        uint8_t bit_mask = 1 << (offset % 8);

        if (windows[agent_id].bitset[byte_idx] & bit_mask) {
            collisions_detected++;
        } else {
            windows[agent_id].bitset[byte_idx] |= bit_mask;
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    double ns_per_lookup = (elapsed / operations) * 1e9;

    printf("5,000,000 History Lookups executed in %.4f seconds\n", elapsed);
    printf("Lookup Speed: %.2f nanoseconds per check\n", ns_per_lookup);
    printf("Throughput: %.2f million checks/sec on a single CPU core\n", (operations / elapsed) / 1e6);
    printf("Memory usage per agent: %zu bytes (1.25 KB)\n", sizeof(AgentWindow));

    free(windows);
    return 0;
}
