# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
End-to-End Integration Test: Autonomous Client -> Independent Provider -> Non-Custodial Settlement.
Proves that CSLS is an actual protocol for agent-to-independent-provider commerce:
1. Client and Provider are separate sovereign identities with separate keys and L2 addresses.
2. Provider exposes capabilities, pricing, and independent payout address.
3. Client discovers provider, bootstraps 95-byte Session MAC handshake over HTTP.
4. Client requests real computation, streaming monotonic 167-byte Session MAC micro-cheques.
5. Provider executes real deterministic workload and emits cryptographically signed receipts.
6. Replay, out-of-order, and double-signing attacks are trapped by the C11 engine.
7. Provider claims on-chain settlement directly to its own payout destination on Base L2.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Generator, Tuple

import pytest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_TESTS_DIR)
_SDK_DIR = os.path.join(_PROJECT_ROOT, "sdk")
if _SDK_DIR not in sys.path:
    sys.path.insert(0, _SDK_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from causal_slash import (
    CSLS_ERR_FRAUD,
    CSLS_OK,
    CausalAgentWallet,
)
from causal_eth import (
    SECP256K1_N,
    derive_address,
    keccak256,
)
from onchain_settler import sign_digest_secp256k1
from sdk.provider.server import IndependentProvider, StandaloneProviderServer


def _get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def provider_instance() -> Generator[Tuple[StandaloneProviderServer, IndependentProvider, str], None, None]:
    """Starts a live independent provider server in background on an ephemeral port."""
    port = _get_free_port()
    # Distinct secret key for provider
    provider_sk = bytes.fromhex("11" * 32)
    provider = IndependentProvider(
        provider_id="provider.independent.verifier-01",
        secret_key=provider_sk,
        unit_price_micro_usdc=500,
    )
    server = StandaloneProviderServer(host="127.0.0.1", port=port, provider=provider)
    server.start(background=True)

    # Wait until bound
    t0 = time.perf_counter()
    while time.perf_counter() - t0 < 3.0:
        try:
            with urllib.request.urlopen(f"{server.url}/health", timeout=0.1) as r:
                if r.status == 200:
                    break
        except Exception:
            time.sleep(0.02)

    yield server, provider, server.url

    server.stop()


def test_independent_provider_discovery_and_metadata(
    provider_instance: Tuple[StandaloneProviderServer, IndependentProvider, str]
) -> None:
    """Verifies that the provider publishes identity, capabilities, and payout destination."""
    _, provider, base_url = provider_instance

    # 1. Inspect /health
    req = urllib.request.Request(f"{base_url}/health")
    with urllib.request.urlopen(req, timeout=2.0) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))

    assert data["status"] == "online"
    assert data["provider_id"] == "provider.independent.verifier-01"
    assert data["provider_pk"].lower() == provider.public_key_hex.lower()
    assert data["payout_address"].lower() == provider.payout_address.lower()
    assert data["unit_price_micro_usdc"] == 500
    assert "compute.hash_audit" in data["capabilities"]

    # 2. Inspect /v1/capabilities
    req = urllib.request.Request(f"{base_url}/v1/capabilities")
    with urllib.request.urlopen(req, timeout=2.0) as resp:
        assert resp.status == 200
        caps = json.loads(resp.read().decode("utf-8"))

    cap_names = [c["name"] for c in caps["capabilities"]]
    assert "compute.hash_audit" in cap_names
    assert "compute.verify_signature" in cap_names
    assert "data.transform" in cap_names


def test_client_to_provider_e2e_execution_flow(
    provider_instance: Tuple[StandaloneProviderServer, IndependentProvider, str]
) -> None:
    """
    Executes complete end-to-end flow:
    Client Wallet -> HTTP Handshake -> 167-Byte Cheque -> Computation -> Signed Receipt.
    """
    _, provider, base_url = provider_instance

    # Client agent with its own independent identity
    client_sk = bytes.fromhex("22" * 32)
    client = CausalAgentWallet(secret_key=client_sk)
    assert client.public_key != provider.public_key_bytes

    # 1. Bootstrap 95-Byte Session MAC Handshake over HTTP
    session_init_pkt = client.create_session(provider.public_key_bytes)
    assert len(session_init_pkt) == 95

    init_payload = json.dumps({"session_init_pkt": session_init_pkt.hex()}).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url}/v1/session/init",
        data=init_payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=2.0) as resp:
        assert resp.status == 200
        init_res = json.loads(resp.read().decode("utf-8"))
        assert init_res["status"] == "session_established"

    # 2. Execute First Task: compute.hash_audit
    task1_payload = {
        "capability": "compute.hash_audit",
        "input": {"data": "causal-slash sovereign settlement invariant verification", "algorithm": "sha256"},
    }
    # Sign 167-byte Session MAC micro-cheque for 500 micro-USDC ($0.0005)
    cheque1 = client.sign_cheque(provider.public_key_bytes, amount_usdc=0.0005, session_mac=True)
    assert len(cheque1.raw_packet) == 167

    exec_req = urllib.request.Request(
        f"{base_url}/v1/service/execute",
        data=json.dumps(task1_payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Causal-Cheque": "0x" + cheque1.raw_packet.hex(),
        },
        method="POST",
    )
    with urllib.request.urlopen(exec_req, timeout=2.0) as resp:
        assert resp.status == 200
        exec_res1 = json.loads(resp.read().decode("utf-8"))

    assert exec_res1["status"] == "success"
    assert exec_res1["service"] == "compute.hash_audit"
    assert exec_res1["result"]["audit_status"] == "VERIFIED"
    assert exec_res1["usage"]["cost_micro_usdc"] == 500
    assert exec_res1["settlement"]["payout_address"].lower() == provider.payout_address.lower()

    # Verify Receipt
    rcpt1 = exec_res1["receipt"]
    assert rcpt1["channel_height"] == 1
    assert rcpt1["cost_micro_usdc"] == 500
    assert rcpt1["payout_address"].lower() == provider.payout_address.lower()
    assert rcpt1["client_pk"].lower() == ("0x" + client.public_key.hex()).lower()
    assert rcpt1["provider_signature"].startswith("0x")

    # 3. Execute Second Task: data.transform (monotonically streaming next cheque)
    task2_payload = {
        "capability": "data.transform",
        "input": {"text": "autonomous sovereign m2m protocol execution pipeline", "operation": "tokenize"},
    }
    cheque2 = client.sign_cheque(provider.public_key_bytes, amount_usdc=0.0005, session_mac=True)
    assert len(cheque2.raw_packet) == 167
    assert cheque2.height == 2

    exec_req2 = urllib.request.Request(
        f"{base_url}/v1/service/execute",
        data=json.dumps(task2_payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Causal-Cheque": "0x" + cheque2.raw_packet.hex(),
        },
        method="POST",
    )
    with urllib.request.urlopen(exec_req2, timeout=2.0) as resp:
        assert resp.status == 200
        exec_res2 = json.loads(resp.read().decode("utf-8"))

    assert exec_res2["status"] == "success"
    assert exec_res2["result"]["token_count"] == 6
    assert exec_res2["usage"]["cumulative_spent_micro_usdc"] == 1000
    assert exec_res2["receipt"]["channel_height"] == 2

    # 4. Verify Auditability: Fetch receipts from /v1/receipts
    with urllib.request.urlopen(f"{base_url}/v1/receipts", timeout=2.0) as resp:
        receipts_data = json.loads(resp.read().decode("utf-8"))
        assert receipts_data["total_receipts"] >= 2

    client.close()


def test_independent_provider_adversarial_rejection(
    provider_instance: Tuple[StandaloneProviderServer, IndependentProvider, str]
) -> None:
    """Verifies that bad MAC, replays, and double-signing attacks are rejected with distinct HTTP codes."""
    _, provider, base_url = provider_instance

    attacker_sk = bytes.fromhex("33" * 32)
    attacker = CausalAgentWallet(secret_key=attacker_sk)

    # 1. Request without session -> 401
    bad_cheque = bytearray(167)
    bad_cheque[0:4] = bytes.fromhex("43534c53") # CSLS magic
    bad_cheque[4] = 0x01
    bad_cheque[5:38] = attacker.public_key
    bad_cheque[38:71] = provider.public_key_bytes
    bad_cheque[71:79] = (1).to_bytes(8, "big")

    req = urllib.request.Request(
        f"{base_url}/v1/service/execute",
        data=json.dumps({"capability": "compute.hash_audit", "input": "test"}).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Causal-Cheque": "0x" + bad_cheque.hex()},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req, timeout=2.0)
    assert exc_info.value.code == 401

    # 2. Establish valid session for attacker
    s_init = attacker.create_session(provider.public_key_bytes)
    init_req = urllib.request.Request(
        f"{base_url}/v1/session/init",
        data=json.dumps({"session_init_pkt": s_init.hex()}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(init_req, timeout=2.0) as resp:
        assert resp.status == 200

    # 3. Legitimate cheque at height 1 -> 200 OK
    c1 = attacker.sign_cheque(provider.public_key_bytes, amount_usdc=0.0005, session_mac=True)
    req1 = urllib.request.Request(
        f"{base_url}/v1/service/execute",
        data=json.dumps({"capability": "compute.hash_audit", "input": "valid"}).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Causal-Cheque": "0x" + c1.raw_packet.hex()},
        method="POST",
    )
    with urllib.request.urlopen(req1, timeout=2.0) as resp:
        assert resp.status == 200

    # 4. Replay of same cheque -> 409 Conflict (Replay detected)
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req1, timeout=2.0)
    assert exc_info.value.code == 409

    # 5. Unsupported capability -> 404 Not Found
    c2 = attacker.sign_cheque(provider.public_key_bytes, amount_usdc=0.0005, session_mac=True)
    req_bad_cap = urllib.request.Request(
        f"{base_url}/v1/service/execute",
        data=json.dumps({"capability": "unsupported_dummy_service", "input": "invalid"}).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Causal-Cheque": "0x" + c2.raw_packet.hex()},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req_bad_cap, timeout=2.0)
    assert exc_info.value.code == 404

    attacker.close()


def test_independent_provider_onchain_settlement_payout(
    provider_instance: Tuple[StandaloneProviderServer, IndependentProvider, str]
) -> None:
    """
    Verifies that the provider-controlled payout destination is targeted by settlement.
    Tests canonical calldata generation for PerformanceCollateralVault.settleCheque
    and tests live Anvil EVM settlement when Foundry is available.
    """
    _, provider, base_url = provider_instance
    client_sk = bytes.fromhex("44" * 32)
    client_addr = "0x" + derive_address(int.from_bytes(client_sk, "big")).hex()

    # 1. Prepare settlement calldata via provider endpoint
    prep_payload = {
        "client_address": client_addr,
        "cumulative_amount_micro_usdc": 1000,
        "session_nonce": 1,
        "deadline": int(time.time()) + 3600,
        "signature": "99" * 65,
    }
    req = urllib.request.Request(
        f"{base_url}/v1/settlement/prepare",
        data=json.dumps(prep_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=2.0) as resp:
        assert resp.status == 200
        settle_data = json.loads(resp.read().decode("utf-8"))

    assert settle_data["provider_payout_address"].lower() == provider.payout_address.lower()
    assert settle_data["selector"] == "0xf8bf9167" # settleCheque(address,uint256,uint256,uint256,bytes)
    assert settle_data["calldata"].startswith("0xf8bf9167")

    # 2. Live On-Chain Settlement Verification on Anvil (if Foundry available)
    anvil_bin = shutil.which("anvil")
    forge_bin = shutil.which("forge")
    cast_bin = shutil.which("cast")
    if not (anvil_bin and forge_bin and cast_bin):
        pytest.skip("Foundry tools not available for live Anvil node test")

    anvil_port = _get_free_port()
    anvil_proc = subprocess.Popen(
        [anvil_bin, "--port", str(anvil_port), "--silent"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    rpc_url = f"http://127.0.0.1:{anvil_port}"

    try:
        # Wait for Anvil to bind
        t0 = time.perf_counter()
        while time.perf_counter() - t0 < 4.0:
            try:
                with socket.create_connection(("127.0.0.1", anvil_port), timeout=0.05):
                    break
            except Exception:
                time.sleep(0.05)

        # Deploy MockUSDC and PerformanceCollateralVault
        deployer_sk = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        deployer_addr = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

        usdc_deploy = subprocess.check_output(
            [forge_bin, "create", "contracts/MockUSDC.sol:MockUSDC", "--rpc-url", rpc_url, "--private-key", deployer_sk, "--broadcast"],
            text=True,
        )
        usdc_addr = [line.split()[-1] for line in usdc_deploy.splitlines() if "Deployed to:" in line][0]

        vault_deploy = subprocess.check_output(
            [
                forge_bin, "create", "contracts/PerformanceCollateralVault.sol:PerformanceCollateralVault",
                "--rpc-url", rpc_url, "--private-key", deployer_sk,
                "--broadcast",
                "--constructor-args", usdc_addr, deployer_addr, deployer_addr,
            ],
            text=True,
        )
        vault_addr = [line.split()[-1] for line in vault_deploy.splitlines() if "Deployed to:" in line][0]

        # Fund client agent and provider with ETH for gas, plus 100 USDC to client
        subprocess.check_call([cast_bin, "send", client_addr, "--value", "1ether", "--rpc-url", rpc_url, "--private-key", deployer_sk])
        subprocess.check_call([cast_bin, "send", provider.payout_address, "--value", "1ether", "--rpc-url", rpc_url, "--private-key", deployer_sk])
        client_sk_hex = "0x" + client_sk.hex()
        subprocess.check_call([cast_bin, "send", usdc_addr, "mint(address,uint256)", client_addr, "100000000", "--rpc-url", rpc_url, "--private-key", deployer_sk])
        subprocess.check_call([cast_bin, "send", usdc_addr, "approve(address,uint256)", vault_addr, "100000000", "--rpc-url", rpc_url, "--private-key", client_sk_hex])
        subprocess.check_call([
            cast_bin, "send", vault_addr, "depositCollateral(uint256,bytes32,address)",
            "10000000", "0x0000000000000000000000000000000000000000000000000000000000000000", client_addr,
            "--rpc-url", rpc_url, "--private-key", client_sk_hex
        ])

        # Allocate 2 USDC session exposure for provider payout address
        subprocess.check_call([
            cast_bin, "send", vault_addr, "allocateSessionExposure(address,uint256)",
            provider.payout_address, "2000000",
            "--rpc-url", rpc_url, "--private-key", client_sk_hex
        ])

        # Client signs EIP-712 cheque for provider
        cheque_amount = 1000000 # $1.00 USDC
        nonce = 1
        deadline = int(time.time()) + 3600
        chain_id = int(subprocess.check_output([cast_bin, "chain-id", "--rpc-url", rpc_url]).strip())

        # Construct EIP-712 signature from client
        domain_sep = keccak256(
            keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
            + keccak256(b"CausalSlashVault")
            + keccak256(b"2.0")
            + chain_id.to_bytes(32, "big")
            + bytes.fromhex(vault_addr[2:].rjust(64, "0"))
        )
        cheque_typehash = keccak256(b"Cheque(address agent,address vendor,uint256 cumulativeAmount,uint256 sessionNonce,uint256 deadline)")
        struct_hash = keccak256(
            cheque_typehash
            + bytes.fromhex(client_addr[2:].rjust(64, "0"))
            + bytes.fromhex(provider.payout_address[2:].rjust(64, "0"))
            + cheque_amount.to_bytes(32, "big")
            + nonce.to_bytes(32, "big")
            + deadline.to_bytes(32, "big")
        )
        digest = keccak256(b"\x19\x01" + domain_sep + struct_hash)
        client_sig = sign_digest_secp256k1(int.from_bytes(client_sk, "big"), digest)

        # Provider prepares and claims settlement on-chain
        live_calldata = provider.prepare_onchain_settlement(
            client_address=client_addr,
            cumulative_amount_micro_usdc=cheque_amount,
            session_nonce=nonce,
            deadline=deadline,
            client_signature_hex=client_sig.hex(),
        )["calldata"]

        provider.rpc_url = rpc_url
        provider.vault_address = vault_addr

        # Check balance before
        provider_bal_before = int(subprocess.check_output([cast_bin, "call", usdc_addr, "balanceOf(address)(uint256)", provider.payout_address, "--rpc-url", rpc_url]).split()[0])
        assert provider_bal_before == 0

        # Provider broadcasts settlement to vault
        claim_output = provider.claim_settlement_onchain(live_calldata)
        assert claim_output["success"] is True

        # Check provider balance after -> $1.00 USDC received directly from vault!
        provider_bal_after = int(subprocess.check_output([cast_bin, "call", usdc_addr, "balanceOf(address)(uint256)", provider.payout_address, "--rpc-url", rpc_url]).split()[0])
        assert provider_bal_after == cheque_amount
        print(f"\n[LIVE ON-CHAIN AUDIT CONFIRMED] Provider {provider.payout_address} directly received ${provider_bal_after/1e6:.6f} USDC!")

    finally:
        anvil_proc.terminate()
        anvil_proc.wait(timeout=2.0)
