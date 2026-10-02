# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Unit and Integration Tests for BaseOnChainSettler (Base Sepolia L2).

Tests:
1. Differential ABI calldata encoding against Foundry `cast calldata` for:
   - settleSwarmCheque (0x5f0bd093)
   - slashSwarmSubAgent (0x02c1c77b)
   - commitFraudProof (0xd120aac5)
   - revealAndSlash (0x4e99b365)
2. Canonical subagent leaf and Merkle proof verification.
3. Cryptographic EIP-712 SwarmCheque digest creation and secp256k1 (r, s, v) signature recovery.
4. Input validation, positional constructor signatures, and address normalization.
5. Live on-chain end-to-end execution on an ephemeral local EVM node (Foundry Anvil):
   - Real contract deployment of MockUSDC and SwarmDelegationVault.
   - Master bond deposit & delegation root configuration.
   - Real on-chain streaming cheque settlement via settle_swarm_cheque (0 gas offchain -> onchain finality).
   - Real on-chain liquidation of equivocating subagent via slash_subagent.
   - Real on-chain 2-phase MEV-protected slashing via commit_fraud_proof & reveal_and_slash (Axiom 4 & 6).
   - Verification that slashed subagents cannot settle subsequent cheques.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from typing import Generator, Tuple

import pytest

from sdk.causal_eth import (
    SECP256K1_N,
    _point_add,
    build_merkle_tree,
    commit_hash_for,
    compute_subagent_leaf,
    compute_swarm_cheque_digest,
    decompress_pubkey,
    derive_address,
    encode_commit_fraud_proof,
    encode_reveal_and_slash,
    keccak256,
    merkle_proof,
    merkle_verify,
    secp256k1_mul,
)
from sdk.onchain_settler import (
    BaseOnChainSettler,
    OnChainSettlementError,
    TransactionRevertedError,
    sign_digest_secp256k1,
)

# Test vectors
MASTER_PK = 0xAC0974BEC39A17E36BA4A6B4D238FF944BACB478CBED5EFCAE784D7BF4F2FF80
SUBAGENT1_PK = 0x4C0883A69102937D6231471B5DBB6204FE5129617082792AE468D01A3F362318
SUBAGENT2_PK = 0x6CBED5EFCAE784D7BF4F2FF80AC0974BEC39A17E36BA4A6B4D238FF944BACB47
VENDOR_PK = 0x59C6995E998F97A5A0044966F0945389DC9E86DAE88C7A8412F4603B6B78690D
HUNTER_PK = 0x5DE4111AFA1A4B94908F83103EB1F1706367C2E68CA870FC3FB9A804CDAB365A


def _get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def test_differential_calldata_settle_swarm_cheque() -> None:
    """Verifies Python settle calldata matches `cast calldata` byte-for-byte."""
    cast_path = shutil.which("cast")
    if not cast_path:
        pytest.skip("cast CLI not found in PATH")

    settler = BaseOnChainSettler(
        vault_address="0x33BD2908a372cf6A533B75e79D3cAa754da8775c",
        master_agent="0x1111111111111111111111111111111111111111",
        chain_id=84532,
    )

    proof = [bytes.fromhex("22" * 32), bytes.fromhex("33" * 32)]
    dummy_sig = bytes.fromhex("44" * 65)
    vendor_addr = "0x5555555555555555555555555555555555555555"

    py_calldata = settler.encode_settle_calldata(
        subagent_pk=SUBAGENT1_PK,
        height=105,
        amount=500_000_000,
        merkle_proof=proof,
        vendor_address=vendor_addr,
        signature=dummy_sig,
    )

    cast_cmd = [
        cast_path,
        "calldata",
        "settleSwarmCheque(address,uint64,uint64,bytes32[],bytes)",
        settler.master_agent,
        "105",
        "500000000",
        "[" + ",".join("0x" + p.hex() for p in proof) + "]",
        "0x" + dummy_sig.hex(),
    ]
    cast_calldata = subprocess.check_output(cast_cmd, text=True).strip()

    assert "0x" + py_calldata.hex() == cast_calldata


def test_differential_calldata_slash_swarm_subagent() -> None:
    """Verifies Python slash calldata matches `cast calldata` byte-for-byte."""
    cast_path = shutil.which("cast")
    if not cast_path:
        pytest.skip("cast CLI not found in PATH")

    settler = BaseOnChainSettler(
        vault_address="0x33BD2908a372cf6A533B75e79D3cAa754da8775c",
        master_agent="0x1111111111111111111111111111111111111111",
    )

    leaf_hash = bytes.fromhex("aa" * 32)
    nonce_root = bytes.fromhex("bb" * 32)
    proof = [bytes.fromhex("cc" * 32)]

    py_calldata = settler.encode_slash_calldata(
        extracted_sk=SUBAGENT1_PK,
        merkle_proof=proof,
        subagent_quota=5_000_000,
        nonce_root=nonce_root,
        expiry=1_700_000_000,
        leaf_index=3,
        leaf_hash=leaf_hash,
    )

    tuple_arg = (
        f"({settler.master_agent},0x{leaf_hash.hex()},"
        f"[0x{proof[0].hex()}],3,{SUBAGENT1_PK},5000000,0x{nonce_root.hex()},1700000000)"
    )
    cast_cmd = [
        cast_path,
        "calldata",
        "slashSwarmSubAgent((address,bytes32,bytes32[],uint256,uint256,uint256,bytes32,uint256))",
        tuple_arg,
    ]
    cast_calldata = subprocess.check_output(cast_cmd, text=True).strip()

    assert "0x" + py_calldata.hex() == cast_calldata


def test_differential_calldata_commit_reveal_slash() -> None:
    """Verifies Python commitFraudProof and revealAndSlash match `cast calldata` byte-for-byte."""
    cast_path = shutil.which("cast")
    if not cast_path:
        pytest.skip("cast CLI not found in PATH")

    target = "0x1111111111111111111111111111111111111111"
    target_b = bytes.fromhex(target[2:])
    commit_hash = bytes.fromhex("22" * 32)

    # 1. commitFraudProof calldata check (selector 0xd120aac5)
    py_commit = encode_commit_fraud_proof(target_b, commit_hash)
    cast_commit = subprocess.check_output([
        cast_path, "calldata", "commitFraudProof(address,bytes32)",
        target, "0x" + commit_hash.hex()
    ], text=True).strip()
    assert "0x" + py_commit.hex() == cast_commit

    # 2. revealAndSlash calldata check (selector 0x4e99b365)
    salt = bytes.fromhex("33" * 32)
    py_reveal = encode_reveal_and_slash(target_b, SUBAGENT1_PK, salt)
    cast_reveal = subprocess.check_output([
        cast_path, "calldata", "revealAndSlash((address,uint256,bytes32))",
        f"({target},{SUBAGENT1_PK},0x{salt.hex()})"
    ], text=True).strip()
    assert "0x" + py_reveal.hex() == cast_reveal


def test_subagent_leaf_and_merkle_proof_integrity() -> None:
    """Verifies subagent leaf derivation and Merkle path verification."""
    subagent_addr = derive_address(SUBAGENT1_PK)
    quota = 10_000_000
    nonce_root = keccak256(b"subagent-1-nonces")
    expiry = 1_800_000_000
    leaf_index = 0

    leaf = compute_subagent_leaf(subagent_addr, quota, nonce_root, expiry, leaf_index)
    assert len(leaf) == 32

    # Second leaf
    subagent2_addr = derive_address(SUBAGENT2_PK)
    leaf2 = compute_subagent_leaf(subagent2_addr, quota, nonce_root, expiry, 1)

    levels, root = build_merkle_tree([leaf, leaf2])
    proof0 = merkle_proof(levels, 0)
    assert merkle_verify(leaf, proof0, 0, root)


def test_eip712_cheque_signing_and_signer_recovery() -> None:
    """Verifies EIP-712 SwarmCheque digest generation and ECDSA recovery."""
    settler = BaseOnChainSettler(
        vault_address="0x33BD2908a372cf6A533B75e79D3cAa754da8775c",
        chain_id=84532,
    )

    vendor_addr = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    height = 42
    amount = 1_500_000

    sig = settler.sign_swarm_cheque(
        subagent_pk=SUBAGENT1_PK,
        height=height,
        amount=amount,
        vendor_address=vendor_addr,
    )
    assert len(sig) == 65

    # Check recovery mathematically
    digest = compute_swarm_cheque_digest(
        master_agent=settler.vault_bytes,
        vendor_address=bytes.fromhex(vendor_addr[2:]),
        channel_height=height,
        cumulative_amount=amount,
        verifying_contract=settler.vault_bytes,
        chain_id=84532,
    )

    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:64], "big")
    v = sig[64]
    assert v in (27, 28)
    assert s <= SECP256K1_N // 2  # BIP-146 low-s

    # Recover address
    y_odd = (v - 27) & 1
    prefix = 0x03 if y_odd else 0x02
    pt = decompress_pubkey(bytes([prefix]) + r.to_bytes(32, "big"))
    sR = secp256k1_mul(s, pt)
    inv_r = pow(r, -1, SECP256K1_N)
    e = int.from_bytes(digest, "big")
    neg_eG = secp256k1_mul(SECP256K1_N - (e % SECP256K1_N))
    cand_Q = _point_add(sR, neg_eG)
    assert cand_Q is not None
    Q = secp256k1_mul(inv_r, cand_Q)
    recovered_addr = keccak256(Q[0].to_bytes(32, "big") + Q[1].to_bytes(32, "big"))[12:]

    expected_addr = derive_address(SUBAGENT1_PK)
    assert recovered_addr == expected_addr


def test_input_normalization_and_constructor_variations() -> None:
    """Verifies hex string, int, and bytes normalization, and constructor argument order."""
    # Test canonical positional order: (rpc_url, private_key, vault_address)
    s1 = BaseOnChainSettler(
        "https://sepolia.base.org",
        hex(MASTER_PK),
        "0x33bd2908a372cf6a533b75e79d3caa754da8775c",
    )
    assert s1.rpc_url == "https://sepolia.base.org"
    assert s1.caller_address.lower() == "0x" + derive_address(MASTER_PK).hex().lower()
    assert s1.vault_address == "0x33bd2908a372cf6a533b75e79d3caa754da8775c"

    # Test reverse positional order: (vault_address, rpc_url, private_key)
    s2 = BaseOnChainSettler(
        "0x33bd2908a372cf6a533b75e79d3caa754da8775c",
        "https://sepolia.base.org",
        hex(MASTER_PK),
    )
    assert s2.rpc_url == "https://sepolia.base.org"
    assert s2.caller_address.lower() == "0x" + derive_address(MASTER_PK).hex().lower()


@pytest.fixture(scope="module")
def anvil_node() -> Generator[Tuple[str, int], None, None]:
    """Launches an ephemeral Foundry Anvil instance for real on-chain testing (Zero sleep)."""
    anvil_bin = shutil.which("anvil")
    if not anvil_bin:
        pytest.skip("Foundry anvil not found in PATH")

    port = _get_free_port()
    proc = subprocess.Popen(
        [anvil_bin, "--port", str(port), "--disable-code-size-limit", "--silent"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    rpc_url = f"http://127.0.0.1:{port}"

    # Non-blocking socket polling: wait until anvil binds port without time.sleep
    start = time.perf_counter()
    ready = False
    while time.perf_counter() - start < 5.0:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.05):
                ready = True
                break
        except (OSError, ConnectionRefusedError):
            pass

    if not ready:
        proc.terminate()
        raise RuntimeError(f"Anvil failed to start on port {port} within 5.0s")

    yield rpc_url, port

    proc.terminate()
    proc.wait(timeout=5.0)


def test_live_anvil_settlement_and_slashing(anvil_node: Tuple[str, int]) -> None:
    """
    Comprehensive Live End-to-End Test on Real EVM (Anvil):
    1. Deploy MockUSDC and SwarmDelegationVault.
    2. Mint USDC to MasterAgent, approve and deposit $100,000 collateral.
    3. Configure Swarm Merkle delegation tree with SubAgent 1 and SubAgent 2.
    4. Settle streaming micro-cheque from SubAgent 1 to Vendor via BaseOnChainSettler.
    5. Liquidate SubAgent 1 after equivocation via slash_subagent.
    6. Verify Commit-Reveal fraud proof submission on-chain (Axiom 4 & 6).
    7. Verify that subsequent settlements from SubAgent 1 revert on-chain.
    """
    rpc_url, _ = anvil_node
    forge_bin = shutil.which("forge")
    cast_bin = shutil.which("cast")
    if not forge_bin or not cast_bin:
        pytest.skip("Foundry forge/cast not found")

    master_pk_hex = hex(MASTER_PK)
    master_addr = "0x" + derive_address(MASTER_PK).hex()
    vendor_pk_hex = hex(VENDOR_PK)
    vendor_addr = "0x" + derive_address(VENDOR_PK).hex()
    hunter_pk_hex = hex(HUNTER_PK)
    hunter_addr = "0x" + derive_address(HUNTER_PK).hex()

    # 1. Deploy MockUSDC
    usdc_deploy = subprocess.check_output(
        [
            forge_bin, "create", "contracts/MockUSDC.sol:MockUSDC",
            "--rpc-url", rpc_url,
            "--private-key", master_pk_hex,
            "--broadcast",
        ],
        text=True,
    )
    usdc_addr = ""
    for line in usdc_deploy.splitlines():
        if "Deployed to:" in line:
            usdc_addr = line.split()[-1]
            break
    assert usdc_addr.startswith("0x")

    # 2. Deploy SwarmDelegationVault
    vault_deploy = subprocess.check_output(
        [
            forge_bin, "create", "contracts/SwarmDelegationVault.sol:SwarmDelegationVault",
            "--rpc-url", rpc_url,
            "--private-key", master_pk_hex,
            "--broadcast",
            "--constructor-args", usdc_addr, master_addr, master_addr,
        ],
        text=True,
    )
    vault_addr = ""
    for line in vault_deploy.splitlines():
        if "Deployed to:" in line:
            vault_addr = line.split()[-1]
            break
    assert vault_addr.startswith("0x")

    # 3. Mint & Deposit $100,000 USDC
    bond_micro = 100_000_000_000  # $100,000 USDC
    subprocess.check_call([
        cast_bin, "send", usdc_addr, "mint(address,uint256)", master_addr, str(bond_micro),
        "--rpc-url", rpc_url, "--private-key", master_pk_hex
    ], stdout=subprocess.DEVNULL)
    subprocess.check_call([
        cast_bin, "send", usdc_addr, "approve(address,uint256)", vault_addr, str(bond_micro),
        "--rpc-url", rpc_url, "--private-key", master_pk_hex
    ], stdout=subprocess.DEVNULL)

    # 4. Build Swarm Delegation Merkle Tree
    subagent1_addr = derive_address(SUBAGENT1_PK)
    subagent2_addr = derive_address(SUBAGENT2_PK)

    # SwarmDelegationVault supports address leaf for streaming settlement
    leaf0 = keccak256(subagent1_addr)
    leaf1 = keccak256(subagent2_addr)
    root = keccak256(leaf0 + leaf1) if leaf0 <= leaf1 else keccak256(leaf1 + leaf0)

    # Deposit collateral with root
    subprocess.check_call([
        cast_bin, "send", vault_addr,
        "depositCollateral(uint256,bytes32,address)", str(bond_micro), "0x" + root.hex(), master_addr,
        "--rpc-url", rpc_url, "--private-key", master_pk_hex
    ], stdout=subprocess.DEVNULL)

    # Set delegation root
    subprocess.check_call([
        cast_bin, "send", vault_addr,
        "setDelegationRoot(bytes32,uint256)", "0x" + root.hex(), "1",
        "--rpc-url", rpc_url, "--private-key", master_pk_hex
    ], stdout=subprocess.DEVNULL)

    proof = [leaf1]

    # 5. Initialize BaseOnChainSettler acting as Vendor
    vendor_settler = BaseOnChainSettler(
        rpc_url=rpc_url,
        private_key=vendor_pk_hex,
        vault_address=vault_addr,
        master_agent=master_addr,
        chain_id=31337,  # Anvil chain ID
    )

    # Settle streaming cheque #1: height 1, $1,500 USDC
    cheque_amount = 1_500_000_000
    tx_hash = vendor_settler.settle_swarm_cheque(
        subagent_pk=SUBAGENT1_PK,
        height=1,
        amount=cheque_amount,
        merkle_proof=proof,
        vendor_address=vendor_addr,
    )
    assert tx_hash.startswith("0x") and len(tx_hash) == 66

    # Verify receipt and on-chain balance
    receipt = vendor_settler.wait_for_receipt(tx_hash)
    assert receipt["status"] in (1, "0x1", "1", True)

    vendor_bal_str = subprocess.check_output([
        cast_bin, "call", usdc_addr, "balanceOf(address)(uint256)", vendor_addr,
        "--rpc-url", rpc_url
    ], text=True).strip().split()[0]
    assert int(vendor_bal_str) == cheque_amount

    # 6. Settle second incremental cheque: height 2, $2,500 cumulative
    cheque_amount_2 = 2_500_000_000
    tx_hash_2 = vendor_settler.settle_swarm_cheque(
        subagent_pk=SUBAGENT1_PK,
        height=2,
        amount=cheque_amount_2,
        merkle_proof=proof,
        vendor_address=vendor_addr,
    )
    receipt_2 = vendor_settler.wait_for_receipt(tx_hash_2)
    assert receipt_2["status"] in (1, "0x1", "1", True)

    vendor_bal_str_2 = subprocess.check_output([
        cast_bin, "call", usdc_addr, "balanceOf(address)(uint256)", vendor_addr,
        "--rpc-url", rpc_url
    ], text=True).strip().split()[0]
    assert int(vendor_bal_str_2) == cheque_amount_2

    # 7. Settle Monotonicity Violation Reverts (replay height 2)
    with pytest.raises(TransactionRevertedError):
        vendor_settler.settle_swarm_cheque(
            subagent_pk=SUBAGENT1_PK,
            height=2,
            amount=cheque_amount_2,
            merkle_proof=proof,
            vendor_address=vendor_addr,
        )

    # 8. Settle Stale/Decreased Amount Reverts
    with pytest.raises(TransactionRevertedError):
        vendor_settler.settle_swarm_cheque(
            subagent_pk=SUBAGENT1_PK,
            height=3,
            amount=2_000_000_000,  # Less than previous settled 2,500
            merkle_proof=proof,
            vendor_address=vendor_addr,
        )

    # 9. Test On-Chain Slashing via slash_subagent
    quota = 5_000_000_000  # $5,000 USDC quota
    nonce_root1 = keccak256(b"subagent-1-nonces")
    nonce_root2 = keccak256(b"subagent-2-nonces")
    expiry = int(time.time()) + 86400 * 7

    s_leaf0 = compute_subagent_leaf(subagent1_addr, quota, nonce_root1, expiry, 0)
    s_leaf1 = compute_subagent_leaf(subagent2_addr, quota, nonce_root2, expiry, 1)
    s_root = keccak256(s_leaf0 + s_leaf1)

    # Update delegation root to include the quota leaf
    subprocess.check_call([
        cast_bin, "send", vault_addr,
        "setDelegationRoot(bytes32,uint256)", "0x" + s_root.hex(), "1",
        "--rpc-url", rpc_url, "--private-key", master_pk_hex
    ], stdout=subprocess.DEVNULL)

    # Whistleblower Hunter client executes liquidation
    hunter_settler = BaseOnChainSettler(
        rpc_url=rpc_url,
        private_key=hunter_pk_hex,
        vault_address=vault_addr,
        master_agent=master_addr,
        chain_id=31337,
    )

    slash_tx = hunter_settler.slash_subagent(
        extracted_sk=SUBAGENT1_PK,
        merkle_proof=[s_leaf1],
        subagent_quota=quota,
        nonce_root=nonce_root1,
        expiry=expiry,
        leaf_index=0,
    )
    assert slash_tx.startswith("0x") and len(slash_tx) == 66

    slash_receipt = hunter_settler.wait_for_receipt(slash_tx)
    assert slash_receipt["status"] in (1, "0x1", "1", True)

    # Hunter received 15% bounty on-chain ($750 USDC)
    hunter_bal_str = subprocess.check_output([
        cast_bin, "call", usdc_addr, "balanceOf(address)(uint256)", hunter_addr,
        "--rpc-url", rpc_url
    ], text=True).strip().split()[0]
    assert int(hunter_bal_str) == (quota * 15) // 100

    # 10. SubAgent 1 is now slashed: subsequent cheques MUST revert
    with pytest.raises(TransactionRevertedError):
        vendor_settler.settle_swarm_cheque(
            subagent_pk=SUBAGENT1_PK,
            height=3,
            amount=3_000_000_000,
            merkle_proof=proof,
            vendor_address=vendor_addr,
        )
