// SPDX-License-Identifier: Apache-2.0
//
// RED TEAM KILL-CHAIN GATE (Zero-Tolerance Gate, owner-mandated).
// Every demonstration MUST FAIL against the hardened core:
//  [1] Identity theft via crash/restart nonce reuse (C1) -> extraction rc != 0
//  [2] Forged cheque with garbage sig_s from the wire    -> REJECT (C2)
//  [3] Spoofed SESSION_INIT without the agent's key      -> REJECT (C2)
//  [4] Corrupted WAL (both sectors)                      -> fail-closed, no signing
//
// Build: gcc -O2 -Isrc -DCSLS_NO_MAIN test/c/poc_identity_theft.c \
//            src/causal_daemon.c src/schnorr_bloodhound.c -lcrypto -lpthread

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/sha.h>
#include "causal_daemon.h"

static void make_challenge_e(const uint8_t *agent_pk, const uint8_t *vendor_pk,
                             uint64_t h, uint64_t amt, uint8_t out[32]) {
    uint8_t pre[82];
    memcpy(pre, agent_pk, 33);
    memcpy(pre + 33, vendor_pk, 33);
    for (int i = 0; i < 8; i++) pre[66 + i] = (uint8_t)(h >> (56 - i * 8));
    for (int i = 0; i < 8; i++) pre[74 + i] = (uint8_t)(amt >> (56 - i * 8));
    SHA256(pre, sizeof(pre), out);
}

int main(void) {
    if (csls_crypto_global_init() != 0) return 1;
    int exploits_ok = 0; // count of exploits that SUCCEEDED (target: 0)
    const char *wal = "/tmp/poc_identity_wal.bin";
    unlink(wal);

    printf("=== RED TEAM KILL-CHAIN GATE (all exploits must FAIL) ===\n");

    // ---- [1] Identity theft: crash/restart nonce reuse (C1) ----
    printf("\n--- [1] Identity theft via crash/restart nonce reuse ---\n");
    uint8_t agent_sk[32], vendor_sk[32];
    memset(agent_sk, 0xAB, 32);
    memset(vendor_sk, 0x22, 32);
    csls_vendor_ctx_t *vendor = csls_vendor_new(vendor_sk, 100000000ULL);
    csls_vendor_enable_mac(vendor, 0); // legacy wire harness: explicit opt-out (secure default mandates Session MAC)
    csls_agent_ctx_t *agent = csls_agent_new(agent_sk, wal);
    if (!agent) { printf("  agent_new failed\n"); return 1; }
    csls_cheque_pkt_t pre[5];
    for (int i = 0; i < 5; i++) {
        csls_agent_sign_cheque(agent, vendor->pk, 10000 + i, &pre[i]);
        int vr = csls_vendor_process_cheque(vendor, &pre[i], NULL); // vendor accepts pre-crash traffic
        if (vr != 0) { printf("  unexpected vendor reject %d\n", vr); return 1; }
    }
    printf("  pre-crash heights: %llu..%llu (all vendor-accepted)\n",
           (unsigned long long)pre[0].height, (unsigned long long)pre[4].height);
    csls_agent_free(agent); // simulated crash

    agent = csls_agent_new(agent_sk, wal); // restart from watermark WAL
    if (!agent) { printf("  restart failed\n"); return 1; }
    csls_cheque_pkt_t post;
    int sr = csls_agent_sign_cheque(agent, vendor->pk, 99999, &post);
    printf("  post-restart sign rc=%d height=%llu (pre-crash max was %llu)\n",
           sr, (unsigned long long)post.height, (unsigned long long)pre[4].height);
    uint8_t leaked[32];
    int rc = csls_extract_private_key(&pre[0], &post, leaked);
    int stolen = (rc == 0 && memcmp(leaked, agent_sk, 32) == 0);
    printf("  extraction rc=%d -> %s\n", rc,
           stolen ? "*** IDENTITY THEFT SUCCESSFUL (GATE FAILED) ***" : "EXPLOIT FAILED (key match: NO)");
    if (stolen) exploits_ok++; else printf("  [PASS] watermark lease prevents nonce reuse\n");
    if (post.height <= pre[4].height) {
        printf("  [GATE FAILED] height regressed across restart\n");
        exploits_ok++;
    } else {
        printf("  [PASS] no height regression across restart\n");
    }
    // cumulative continuity via Proof-Carrying Restart Handshake
    csls_cheque_pkt_t head;
    int gh = csls_vendor_get_head_cheque(vendor, agent->pk, &head);
    if (gh == 0) {
        int rs = csls_agent_restore_session(agent, vendor->pk, &head);
        printf("  handshake: vendor head h=%llu cum=%llu -> agent restore rc=%d %s\n",
               (unsigned long long)head.height, (unsigned long long)head.cumulative_amt, rs,
               rs == 0 ? "(proof accepted)" : "(*** LYING VENDOR DETECTED ***)");
        if (rs != 0) exploits_ok++;
        csls_cheque_pkt_t cont;
        int cc = csls_agent_sign_cheque(agent, vendor->pk, 5000, &cont);
        int vr = csls_vendor_process_cheque(vendor, &cont, NULL);
        printf("  post-handshake cheque h=%llu cum=%llu -> vendor rc=%d %s\n",
               (unsigned long long)cont.height, (unsigned long long)cont.cumulative_amt, vr,
               vr == 0 ? "(channel alive, no brick)" : "(*** BRICKED ***)");
        if (cc != 0 || vr != 0) exploits_ok++;
    } else {
        printf("  vendor head unavailable (gh=%d)\n", gh);
        exploits_ok++;
    }
    csls_agent_free(agent);

    // ---- [2] Forged cheque with garbage sig_s (C2, MAC enforced) ----
    printf("\n--- [2] Forged cheque with garbage sig_s (MAC enforced) ---\n");
    csls_vendor_ctx_t *vendor2 = csls_vendor_new(vendor_sk, 100000000ULL); // fresh channel state
    csls_vendor_enable_mac(vendor2, 1);
    agent = csls_agent_new(agent_sk, NULL);
    csls_session_init_pkt_t init;
    if (csls_agent_session_begin(agent, vendor2->pk, &init) != 0) { printf("  session_begin failed\n"); return 1; }
    if (csls_vendor_session_init(vendor2, &init) != 0) { printf("  vendor session_init rejected the agent's own INIT\n"); return 1; }
    csls_cheque_pkt_t honest; uint8_t hmac_[16];
    csls_agent_sign_cheque_mac(agent, vendor2->pk, 10000, &honest, hmac_);
    int r_honest = csls_vendor_process_cheque_mac(vendor2, &honest, hmac_, NULL);
    printf("  honest MAC'd cheque -> rc=%d (%s)\n", r_honest, r_honest == 0 ? "accepted as expected" : "GATE BROKE");
    if (r_honest != 0) exploits_ok++;

    csls_cheque_pkt_t forged;
    memset(&forged, 0, sizeof(forged));
    forged.magic = CSLS_MAGIC;
    forged.type = CSLS_PKT_CHEQUE;
    memcpy(forged.agent_pk, agent->pk, 33);
    memcpy(forged.vendor_pk, vendor2->pk, 33);
    forged.height = 424242;
    forged.cumulative_amt = 60000;
    make_challenge_e(forged.agent_pk, forged.vendor_pk, forged.height, forged.cumulative_amt, forged.challenge_e);
    memset(forged.sig_s, 0x01, 32); // pure garbage, no key knowledge
    int r1 = csls_vendor_process_cheque_mac(vendor2, &forged, NULL, NULL);
    int r2 = csls_vendor_process_cheque_mac(vendor2, &forged, (const uint8_t *)"\xde\xad\xbe\xef\xde\xad\xbe\xef\xde\xad\xbe\xef\xde\xad\xbe\xef", NULL);
    printf("  forged without MAC -> rc=%d, with random MAC -> rc=%d (%s)\n", r1, r2,
           (r1 == CSLS_ERR_BAD_MAC && r2 == CSLS_ERR_BAD_MAC)
               ? "REJECTED (expected)"
               : "*** FORGERY ACCEPTED (GATE FAILED) ***");
    if (r1 != CSLS_ERR_BAD_MAC || r2 != CSLS_ERR_BAD_MAC) exploits_ok++;
    csls_agent_free(agent);

    // ---- [3] Spoofed SESSION_INIT (attacker lacks the agent's key) ----
    printf("\n--- [3] Spoofed SESSION_INIT impersonating a victim ---\n");
    csls_session_init_pkt_t spoof;
    memset(&spoof, 0, sizeof(spoof));
    spoof.magic = CSLS_MAGIC;
    spoof.type = CSLS_PKT_SESSION_INIT;
    memcpy(spoof.agent_pk, agent_sk, 0); // placeholder, replaced below
    csls_agent_ctx_t *victim = csls_agent_new(agent_sk, NULL);
    memcpy(spoof.agent_pk, victim->pk, 33);
    memcpy(spoof.vendor_pk, vendor2->pk, 33);
    spoof.session_nonce = 0xDEADBEEFCAFEBABEULL;
    memset(spoof.auth_mac, 0x77, 16);    // attacker cannot compute the auth tag
    int r3 = csls_vendor_session_init(vendor2, &spoof);
    printf("  spoofed INIT -> rc=%d (%s)\n", r3,
           r3 == CSLS_ERR_BAD_MAC ? "REJECTED (expected)" : "*** SPOOF ACCEPTED (GATE FAILED) ***");
    if (r3 != CSLS_ERR_BAD_MAC) exploits_ok++;
    csls_agent_free(victim);
    csls_vendor_free(vendor2);

    // ---- [4] WAL fail-closed: both sectors corrupt ----
    printf("\n--- [4] Corrupted WAL (both sectors) must refuse to sign ---\n");
    unlink(wal);
    agent = csls_agent_new(agent_sk, wal);
    csls_agent_free(agent);
    FILE *f = fopen(wal, "r+b");
    if (f) {
        fseek(f, 0, SEEK_SET);
        fputc(0xFF, f);                     // corrupt sector A magic
        fseek(f, CSLS_WAL_SECTOR + 8, SEEK_SET);
        fputc(0xFF, f);                     // corrupt sector B reserved_height
        fclose(f);
    }
    csls_agent_ctx_t *bad = csls_agent_new(agent_sk, wal);
    printf("  agent_new on corrupted WAL -> %s\n", bad ? "*** STARTED (GATE FAILED) ***" : "REFUSED (fail-closed, expected)");
    if (bad) { exploits_ok++; csls_agent_free(bad); }
    else printf("  [PASS] fail-closed on unrecoverable WAL\n");

    printf("\n=== RESULT: %d of 4 exploits SUCCEEDED (target: 0 = system hardened) ===\n", exploits_ok);
    csls_crypto_global_cleanup();
    unlink(wal);
    return (exploits_ok == 0) ? 0 : 1;
}
