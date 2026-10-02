// SPDX-License-Identifier: Apache-2.0
//
// RED TEAM — P1: the WAL file itself is an attack surface.
// Threat model: local attacker with WRITE access to the agent's WAL file
// (shared volume, compromised backup/copy job, container neighbor) but NOT
// to the agent's process memory. Goal: regress the boot height -> nonce
// k = HMAC(sk, PKv || h) repeats -> extract the HONEST agent's sk -> frame
// it for the 15% bounty + bond forfeiture.
//
// The Zero-Tolerance Gate covers CORRUPT sectors (CRC mismatch -> fail-closed).
// It does NOT cover:
//   ATTACK A: WAL wiped/deleted (rm / truncate) -> "fresh lease" path -> boot = 1
//   ATTACK B: forged sector with HIGHER sequence + LOWERED reserved_height and
//             a RECOMPUTED CRC64 (unkeyed, public polynomial) -> accepted lease
//
// Build (gate command):
//   gcc -O2 -Isrc -DCSLS_NO_MAIN test/c/test_redteam_wal_forge.c \
//       src/causal_daemon.c src/schnorr_bloodhound.c -lcrypto -lpthread -o /tmp/rt_wal
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "causal_daemon.h"

static const char *WAL = "/tmp/rt_wal_forge.bin";

// --- attacker-side re-implementation of the PUBLIC CRC-64/ECMA-182 ----------
static uint64_t tab[256];
static void build_tab(void) {
    for (uint64_t i = 0; i < 256; i++) {
        uint64_t c = i << 56;
        for (int k = 0; k < 8; k++)
            c = (c & 0x8000000000000000ULL) ? (c << 1) ^ 0x42F0E1EBA9EA3693ULL : (c << 1);
        tab[i] = c;
    }
}
static uint64_t crc64_of(const void *data, size_t len) {
    const uint8_t *p = data; uint64_t crc = 0;
    while (len--) crc = tab[(crc >> 56) ^ *p++] ^ (crc << 8);
    return crc;
}
// Forge a fully VALID WAL sector (attacker needs no secrets for this).
static int forge_sector(uint32_t seq, uint64_t reserved) {
    int fd = open(WAL, O_WRONLY);
    if (fd < 0) return -1;
    uint8_t buf[4096];
    memset(buf, 0, sizeof(buf));
    uint32_t magic = CSLS_WAL_MAGIC;
    memcpy(buf, &magic, 4);
    memcpy(buf + 4, &seq, 4);
    memcpy(buf + 8, &reserved, 8);
    uint64_t crc = crc64_of(buf, 16);
    memcpy(buf + 16, &crc, 8);
    off_t off = (seq & 1) ? CSLS_WAL_SECTOR : 0;
    int rc = pwrite(fd, buf, sizeof(buf), off) == sizeof(buf) ? 0 : -1;
    fsync(fd);
    close(fd);
    return rc;
}

int main(void) {
    build_tab();
    csls_crypto_global_init();
    uint8_t sk[32], vsk[32], vpk_buf[33];
    memset(sk, 0x71, 32); memset(vsk, 0x22, 32);
    unlink(WAL);
    csls_vendor_ctx_t *vendor = csls_vendor_new(vsk, 100000000ULL);
    memcpy(vpk_buf, vendor->pk, 33);
    const uint8_t *vpk = vendor->pk;

    csls_cheque_pkt_t pre[3], post;

    printf("======================================================================\n");
    printf(" P1: WAL-file tampering -> boot-height regression -> sk extraction\n");
    printf("======================================================================\n");

    // ---------------- honest life: signs h = 1..3, then crashes ----------------
    csls_agent_ctx_t *a = csls_agent_new(sk, WAL);
    for (int i = 0; i < 3; i++)
        csls_agent_sign_cheque(a, vpk, 10000 + i, &pre[i]);
    printf("[life]   signed heights 1..3 (amounts 10000..10002); next h would be %llu\n",
           (unsigned long long)atomic_load(&a->height));
    csls_agent_free(a);   // CRASH: process gone, WAL file remains on disk

    // ---------------- ATTACK A: wipe (rm / truncate equivalent) ----------------
    if (truncate(WAL, 0) != 0) { printf("[A] truncate failed\n"); return 1; }
    csls_agent_ctx_t *a2 = csls_agent_new(sk, WAL);   // existing 0-byte file => WAL_FATAL
    if (!a2) {
        printf("[A]      REPELLED: agent_new REFUSED (existing file != 8192B => WAL_FATAL)\n");
        printf("[A]      no signature exists => no nonce reuse => no extraction, no framing\n");
    }
    if (a2) csls_agent_sign_cheque(a2, vpk, 99999, &post);
    uint64_t h_a = post.height;
    uint8_t ska[32];
    int rc_a = csls_extract_private_key(&pre[0], &post, ska);
    int frame_a = 0;
    csls_fraud_pkt_t fr; memset(&fr, 0, sizeof(fr));
    csls_vendor_process_cheque(vendor, &pre[0], NULL);
    if (a2 && csls_vendor_process_cheque(vendor, &post, &fr) == -20)
        frame_a = (memcmp(fr.extracted_sk, sk, 32) == 0);
    printf("[A]      WIPE: post-restart height = %llu (regressed from 1,000,001+)\n"
           "[A]      nonce reuse -> extraction rc=%d, key match=%s, "
           "vendor fraud proof vs HONEST agent=%s\n",
           (unsigned long long)h_a, rc_a,
           rc_a == 0 && memcmp(ska, sk, 32) == 0 ? "YES" : "no",
           frame_a ? "YES (-20, bounty claimable)" : "no");
    if (a2) csls_agent_free(a2);

    // ---------------- ATTACK B: targeted CRC64 forgery -------------------------
    // Fresh deterministic life: unlink (legit fresh start), sign 1..3, crash.
    unlink(WAL);
    csls_agent_ctx_t *a3 = csls_agent_new(sk, WAL);
    if (!a3) { printf("[B]      setup failed: honest life could not start\n"); return 1; }
    for (int i = 0; i < 3; i++)
        csls_agent_sign_cheque(a3, vpk, 20000 + i, &pre[i]);
    csls_agent_free(a3);
    // Attacker forges a VALID sector: seq = current+1, reserved = 2 (was 1,000,000).
    // No secrets needed: CRC-64/ECMA-182 is an unkeyed public polynomial.
    int frc = forge_sector(2, 2);
    csls_agent_ctx_t *a4 = csls_agent_new(sk, WAL);
    if (!a4) {
        printf("[B]      REPELLED: forged sector failed sk-keyed HMAC => WAL_FATAL, no boot\n");
    }
    if (a4) csls_agent_sign_cheque(a4, vpk, 99999, &post);
    else post = pre[2];      // neutral placeholder: dead agent signs nothing
    uint64_t h_b = post.height;
    uint8_t skb[32];
    int rc_b = a4 ? csls_extract_private_key(&pre[2], &post, skb) : -2;
    // The attack's goal is boot-height REGRESSION (forged reserved=2 -> boot=3).
    // Repelled = agent refused OR booted from the surviving AUTHENTIC sector
    // (height far above the pre-crash maximum). Signing at the honest lease = fail.
    int forge_repelled = (!a4) || (post.height > pre[2].height && rc_b != 0);
    printf("[B]      FORGE rc=%d: boot height = %llu (attacker wanted 3) -> %s\n",
           frc, (unsigned long long)h_b,
           forge_repelled ? "LEASE HONORED / REPELLED" : "REGRESSED (GATE FAILED)");
    printf("[B]      height-3 nonce reuse -> extraction rc=%d, key match=%s\n",
           rc_b, rc_b == 0 && memcmp(skb, sk, 32) == 0 ? "YES" : "no");
    csls_agent_free(a4);

    // ---------------- CONTROL: honest restart without tampering ----------------
    unlink(WAL);
    csls_agent_ctx_t *a5h = csls_agent_new(sk, WAL);
    csls_cheque_pkt_t cpre[3];
    for (int i = 0; i < 3; i++) csls_agent_sign_cheque(a5h, vpk, 30000 + i, &cpre[i]);
    csls_agent_free(a5h);
    csls_agent_ctx_t *a5 = csls_agent_new(sk, WAL);
    csls_agent_sign_cheque(a5, vpk, 12345, &post);
    int rc_c = csls_extract_private_key(&pre[2], &post, skb);
    printf("[ctrl]   untampered restart: height = %llu (lease honored), "
           "extraction rc=%d (expect != 0)\n",
           (unsigned long long)post.height, rc_c);
    int verdict_ok = (!a2) && forge_repelled && (!frame_a) && (rc_c != 0);
    printf("GATE: %s (wipe=%s forge=%s framing=%s honest-restart=%s)\n",
           verdict_ok ? "REPELLED" : "FAILED",
           a2 ? "NOT-REPELLED" : "repelled",
           forge_repelled ? "repelled" : "NOT-REPELLED",
           frame_a ? "HAPPENED" : "none",
           rc_c != 0 ? "honored" : "REGRESSED");
    csls_agent_free(a5);

    printf("======================================================================\n");
    printf(" VERDICT: CRC64 is an integrity check, not authenticity. A local\n"
           " attacker with WAL write/delete access regresses the lease and\n"
           " harvests the honest agent's sk for framing. Fix direction:\n"
           " HMAC-SHA256(sk_kept_in_memory, sector) instead of CRC64 + treat\n"
           " 'fresh file' as WAL_FATAL when the agent has any signing history.\n");

    csls_vendor_free(vendor);
    csls_crypto_global_cleanup();
    unlink(WAL);
    return 0;
}
