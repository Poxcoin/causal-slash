# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Causal-Slash Protocol: Python High-Performance Native SDK Facade (sdk/causal_slash.py)
Provides a zero-latency Python interface to the sovereign C11 cryptographic engine.
All internal settlement is denominated strictly in USD / USDC (6 decimal places: micro-USDC).

This module serves as a lightweight backward-compatible facade re-exporting symbols from:
- sdk.ffi: Native C11 shared library loading (libcausal_slash.so, libbloodhound.so) and C ctypes structures.
- sdk.crypto: secp256k1 mathematics, SipHash-128 MAC, ECDH, and fallback cryptography.
- sdk.packet: Binary envelope packing/unpacking and protocol wire-level framing validation.
- sdk.wallet: CausalAgentWallet, CausalVendorNode, and DebtCycleMesh.
"""

from __future__ import annotations

try:
    from .ffi import (
        _BLOODHOUND_SO_PATHS,
        _IS_NATIVE,
        _LIB,
        _LIB_BLOODHOUND,
        _PROJECT_ROOT,
        _SDK_DIR,
        _SO_PATHS,
        AgentCtxHandle,
        BloodhoundPayload,
        CausalPacket,
        ChannelState,
        ChannelTable,
        CslsAgentCtx,
        CslsChequePkt,
        CslsFraudPkt,
        CslsSessionInitPkt,
        CslsVendorCtx,
        EOTSKey,
        SessionState,
        VendorCtxHandle,
        _AgentCtxHandle,
        _CslsAgentCtx,
        _CslsChequePkt,
        _CslsFraudPkt,
        _CslsHistoryEntry,
        _CslsSessionInitPkt,
        _CslsVendorCtx,
        _LibPurePythonStub,
        _VendorCtxHandle,
        _load_bloodhound_lib,
        _load_c_lib,
        csls_channel_state_t,
        csls_channel_table_t,
        load_bloodhound_lib,
        load_c_lib,
    )
    from .crypto import (
        SECP256K1_P,
        SECP256K1_Q,
        _PyAgentCtx,
        _PyVendorCtx,
        _derive_k,
        _ecdh_x,
        _mac128,
        _parse_bytes,
        _session_auth,
        _session_kdf,
        _siphash24,
        _sipround,
        compute_challenge,
        derive_k,
        derive_public_key,
        ecdh_x,
        extract_private_key_eots,
        mac128,
        parse_bytes,
        session_auth,
        session_kdf,
        sign_cheque_python,
        siphash24,
        sipround,
    )
    from .packet import (
        CHEQUE_MAC_PKT_LEN,
        CHEQUE_PKT_LEN,
        CHEQUE_STRUCT_FMT,
        CSLS_ERR_BAD_MAC,
        CSLS_ERR_EXPOSURE_CAP,
        CSLS_ERR_FORGED_HASH,
        CSLS_ERR_FRAUD,
        CSLS_ERR_NO_SESSION,
        CSLS_ERR_OUT_OF_ORDER,
        CSLS_ERR_REPLAY,
        CSLS_ERR_WAL_FATAL,
        CSLS_MAGIC,
        CSLS_OK,
        CSLS_PKT_ACK,
        CSLS_PKT_CHEQUE,
        CSLS_PKT_FRAUD,
        CSLS_PKT_HALT,
        CSLS_PKT_SESSION_INIT,
        FRAUD_PKT_LEN,
        FRAUD_STRUCT_FMT,
        SESSION_INIT_PKT_LEN,
        SESSION_INIT_STRUCT_FMT,
        Cheque,
        CslsCheque,
        FraudProof,
        ProcessResult,
        pack_cheque,
        pack_fraud_proof,
        pack_session_init,
        unpack_cheque,
        unpack_fraud_proof,
        unpack_session_init,
        validate_cheque_header,
        validate_session_init_header,
    )
    from .wallet import (
        CausalAgentWallet,
        CausalVendorNode,
        CycleEliminationRecord,
        DebtCycleMesh,
        NettingSummary,
    )
except (ImportError, ValueError):
    from ffi import (
        _BLOODHOUND_SO_PATHS,
        _IS_NATIVE,
        _LIB,
        _LIB_BLOODHOUND,
        _PROJECT_ROOT,
        _SDK_DIR,
        _SO_PATHS,
        AgentCtxHandle,
        BloodhoundPayload,
        CausalPacket,
        ChannelState,
        ChannelTable,
        CslsAgentCtx,
        CslsChequePkt,
        CslsFraudPkt,
        CslsSessionInitPkt,
        CslsVendorCtx,
        EOTSKey,
        SessionState,
        VendorCtxHandle,
        _AgentCtxHandle,
        _CslsAgentCtx,
        _CslsChequePkt,
        _CslsFraudPkt,
        _CslsHistoryEntry,
        _CslsSessionInitPkt,
        _CslsVendorCtx,
        _LibPurePythonStub,
        _VendorCtxHandle,
        _load_bloodhound_lib,
        _load_c_lib,
        csls_channel_state_t,
        csls_channel_table_t,
        load_bloodhound_lib,
        load_c_lib,
    )
    from crypto import (
        SECP256K1_P,
        SECP256K1_Q,
        _PyAgentCtx,
        _PyVendorCtx,
        _derive_k,
        _ecdh_x,
        _mac128,
        _parse_bytes,
        _session_auth,
        _session_kdf,
        _siphash24,
        _sipround,
        compute_challenge,
        derive_k,
        derive_public_key,
        ecdh_x,
        extract_private_key_eots,
        mac128,
        parse_bytes,
        session_auth,
        session_kdf,
        sign_cheque_python,
        siphash24,
        sipround,
    )
    from packet import (
        CHEQUE_MAC_PKT_LEN,
        CHEQUE_PKT_LEN,
        CHEQUE_STRUCT_FMT,
        CSLS_ERR_BAD_MAC,
        CSLS_ERR_EXPOSURE_CAP,
        CSLS_ERR_FORGED_HASH,
        CSLS_ERR_FRAUD,
        CSLS_ERR_NO_SESSION,
        CSLS_ERR_OUT_OF_ORDER,
        CSLS_ERR_REPLAY,
        CSLS_ERR_WAL_FATAL,
        CSLS_MAGIC,
        CSLS_OK,
        CSLS_PKT_ACK,
        CSLS_PKT_CHEQUE,
        CSLS_PKT_FRAUD,
        CSLS_PKT_HALT,
        CSLS_PKT_SESSION_INIT,
        FRAUD_PKT_LEN,
        FRAUD_STRUCT_FMT,
        SESSION_INIT_PKT_LEN,
        SESSION_INIT_STRUCT_FMT,
        Cheque,
        CslsCheque,
        FraudProof,
        ProcessResult,
        pack_cheque,
        pack_fraud_proof,
        pack_session_init,
        unpack_cheque,
        unpack_fraud_proof,
        unpack_session_init,
        validate_cheque_header,
        validate_session_init_header,
    )
    from wallet import (
        CausalAgentWallet,
        CausalVendorNode,
        CycleEliminationRecord,
        DebtCycleMesh,
        NettingSummary,
    )

__all__ = [
    # FFI symbols
    "_LIB",
    "_IS_NATIVE",
    "_LIB_BLOODHOUND",
    "_SDK_DIR",
    "_PROJECT_ROOT",
    "_SO_PATHS",
    "_BLOODHOUND_SO_PATHS",
    "_load_c_lib",
    "_load_bloodhound_lib",
    "load_c_lib",
    "load_bloodhound_lib",
    "_CslsChequePkt",
    "_CslsFraudPkt",
    "_CslsSessionInitPkt",
    "_CslsAgentCtx",
    "_CslsVendorCtx",
    "_CslsHistoryEntry",
    "csls_channel_state_t",
    "csls_channel_table_t",
    "BloodhoundPayload",
    "CausalPacket",
    "CslsChequePkt",
    "EOTSKey",
    "CslsFraudPkt",
    "SessionState",
    "CslsSessionInitPkt",
    "CslsAgentCtx",
    "CslsVendorCtx",
    "ChannelState",
    "ChannelTable",
    "_AgentCtxHandle",
    "_VendorCtxHandle",
    "AgentCtxHandle",
    "VendorCtxHandle",
    "_LibPurePythonStub",
    # Crypto symbols
    "SECP256K1_Q",
    "SECP256K1_P",
    "_sipround",
    "sipround",
    "_siphash24",
    "siphash24",
    "_mac128",
    "mac128",
    "_ecdh_x",
    "ecdh_x",
    "_session_kdf",
    "session_kdf",
    "_session_auth",
    "session_auth",
    "_derive_k",
    "derive_k",
    "_parse_bytes",
    "parse_bytes",
    "derive_public_key",
    "compute_challenge",
    "extract_private_key_eots",
    "sign_cheque_python",
    "_PyAgentCtx",
    "_PyVendorCtx",
    # Packet symbols
    "CSLS_MAGIC",
    "CSLS_PKT_CHEQUE",
    "CSLS_PKT_ACK",
    "CSLS_PKT_FRAUD",
    "CSLS_PKT_HALT",
    "CSLS_PKT_SESSION_INIT",
    "CSLS_OK",
    "CSLS_ERR_EXPOSURE_CAP",
    "CSLS_ERR_FRAUD",
    "CSLS_ERR_REPLAY",
    "CSLS_ERR_OUT_OF_ORDER",
    "CSLS_ERR_FORGED_HASH",
    "CSLS_ERR_BAD_MAC",
    "CSLS_ERR_NO_SESSION",
    "CSLS_ERR_WAL_FATAL",
    "CHEQUE_PKT_LEN",
    "CHEQUE_MAC_PKT_LEN",
    "SESSION_INIT_PKT_LEN",
    "FRAUD_PKT_LEN",
    "CHEQUE_STRUCT_FMT",
    "SESSION_INIT_STRUCT_FMT",
    "FRAUD_STRUCT_FMT",
    "pack_cheque",
    "unpack_cheque",
    "validate_cheque_header",
    "pack_session_init",
    "unpack_session_init",
    "validate_session_init_header",
    "pack_fraud_proof",
    "unpack_fraud_proof",
    "Cheque",
    "CslsCheque",
    "ProcessResult",
    "FraudProof",
    # Wallet & Mesh symbols
    "CausalAgentWallet",
    "CausalVendorNode",
    "CycleEliminationRecord",
    "NettingSummary",
    "DebtCycleMesh",
]


if __name__ == "__main__":
    import time
    print("=" * 70)
    print("CAUSAL-SLASH PYTHON SDK: BENCHMARK & VERIFICATION SUITE")
    print("=" * 70)

    # 1. Initialize
    agent = CausalAgentWallet()
    vendor = CausalVendorNode(delta_v_usdc=1000.0)  # High buffer for benchmark
    # Authenticated Session MAC channel (C2 gate): vendors mandate Session MAC
    # by default because wire cheques omit the Schnorr point R.
    assert vendor.init_session(agent.create_session(vendor.public_key))

    print(f"Agent PK:  {agent.public_key_hex[:18]}...")
    print(f"Vendor PK: {vendor.public_key_hex[:18]}...")

    # 2. Benchmark streaming 50,000 cheques
    n = 50000
    print(f"\n[1] Streaming {n:,} micro-cheques from Python through native C engine...")
    t0 = time.perf_counter()
    for _ in range(n):
        c = agent.sign_cheque(vendor.public_key, amount_usdc=0.0001, session_mac=True)
        r = vendor.process_cheque(c)
        assert r.accepted

    t1 = time.perf_counter()
    total_time = t1 - t0
    ops_per_sec = n / total_time
    us_per_op = (total_time / n) * 1e6

    print(f"  [OK] Completed {n:,} cheques in {total_time:.4f} seconds")
    print(f"  Latency: {us_per_op:.2f} microseconds per full cycle (Sign + Verify)")
    print(f"  Throughput: {ops_per_sec:,.0f} operations/second in Python!")
    print(f"  Settled Volume: ${vendor.accumulated_usdc:.4f} USDC")

    # 3. Equivocation Detection & Key Extraction Test
    print("\n[2] Testing Equivocation Trap from Python...")
    attacker_agent = CausalAgentWallet()
    v2 = CausalVendorNode(delta_v_usdc=1.0)
    assert v2.init_session(attacker_agent.create_session(v2.public_key))
    legit_cheque = attacker_agent.sign_cheque(v2.public_key, amount_usdc=0.05, session_mac=True)
    r1 = v2.process_cheque(legit_cheque)
    assert r1.accepted, f"Legitimate cheque failed: {r1.error_message}"
    print(f"  Legitimate cheque at height h={legit_cheque.height} accepted: True")

    # Tamper height back to duplicate for double-spending attack
    attacker_agent._ctx.height = legit_cheque.height
    fork_cheque = attacker_agent.sign_cheque(v2.public_key, amount_usdc=0.07, session_mac=True)

    r2 = v2.process_cheque(fork_cheque)
    assert not r2.accepted
    assert r2.fraud_proof is not None
    assert r2.fraud_proof.extracted_secret_key == bytes(attacker_agent._ctx.sk)
    print("  [ALERT] Equivocation detected and private key extracted successfully")
    print(f"  Offender PK:  {r2.fraud_proof.offender_pk.hex()[:18]}...")
    print(f"  Extracted SK: {r2.fraud_proof.extracted_secret_key.hex()[:18]}...")
    print(f"  True SK:      {bytes(attacker_agent._ctx.sk).hex()[:18]}...")
    print("  [PASS] Mathematical Invariant Verified: Extracted key matches agent secret key")

    # 4. DebtCycleMesh Kirchhoff Cycle Reduction & Invariant Test
    print("\n[3] Testing DebtCycleMesh & Kirchhoff Cycle Reduction...")
    mesh = DebtCycleMesh()
    pk_a = b"\x02" + b"A" * 32
    pk_b = b"\x02" + b"B" * 32
    pk_c = b"\x02" + b"C" * 32
    pk_d = b"\x02" + b"D" * 32

    mesh.add_obligation(pk_a, pk_b, 100_000)  # $0.10
    mesh.add_obligation(pk_b, pk_c, 100_000)  # $0.10
    mesh.add_obligation(pk_c, pk_d, 100_000)  # $0.10
    mesh.add_obligation(pk_d, pk_a, 100_000)  # $0.10
    mesh.add_obligation(pk_b, pk_d, 50_000)   # $0.05

    bal_before = mesh.get_all_net_balances()
    assert sum(bal_before.values()) == 0

    cycles, cleared = mesh.reduce_kirchhoff_cycles()
    bal_after = mesh.get_all_net_balances()

    assert bal_before == bal_after, "Kirchhoff Net Balance Invariant Violated!"
    assert mesh.is_dag, "Residual graph must be a DAG!"
    print(f"  Cycles Eliminated: {cycles}")
    print(f"  Cleared Volume: ${cleared / 1e6:.4f} USDC")
    print(f"  Remaining Net System Debt: ${mesh.total_system_debt / 1e6:.4f} USDC")
    print("  [PASS] Mathematical Invariant Verified: Net balances strictly preserved (Theorem 2)")
    print("=" * 70)
    print("ALL PYTHON SDK VERIFICATIONS COMPLETED SUCCESSFULLY!")
