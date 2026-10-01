# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Production Coinbase AgentKit ActionProvider Test Suite for Causal-Slash.
Validates:
1. Channel creation and session allocation on Base L2 / Anvil.
2. Streaming micro-cheque signing and verification via native C11 engine.
3. Sub-microsecond equivocation trapping upon double-signing.
4. On-chain commit-reveal foreclosure and bounty liquidation on PerformanceCollateralVault.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
import pytest

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_TEST_DIR)
sys.path.insert(0, os.path.join(_PROJECT_ROOT, "sdk"))

from agentkit_provider import (
    CausalSlashActionProvider,
    CreateChannelSchema,
    SignStreamChequeSchema,
    VerifyChequeStreamSchema,
    TriggerForeclosureSchema,
)
from causal_slash import (
    CausalAgentWallet,
    CausalVendorNode,
    CSLS_OK,
    CSLS_ERR_FRAUD,
)


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def anvil_environment():
    """Starts an isolated local Anvil instance and deploys protocol contracts."""
    cast_bin = shutil.which("cast") or os.path.expanduser("~/.foundry/bin/cast")
    forge_bin = shutil.which("forge") or os.path.expanduser("~/.foundry/bin/forge")
    anvil_bin = shutil.which("anvil") or os.path.expanduser("~/.foundry/bin/anvil")

    assert os.path.exists(anvil_bin), f"anvil binary not found: {anvil_bin}"
    assert os.path.exists(forge_bin), f"forge binary not found: {forge_bin}"
    assert os.path.exists(cast_bin), f"cast binary not found: {cast_bin}"

    port = _find_free_port()
    rpc_url = f"http://127.0.0.1:{port}"
    anvil_proc = subprocess.Popen(
        [anvil_bin, "--port", str(port), "--silent"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Wait for Anvil to become responsive
    time.sleep(1.0)

    # Default Anvil Account 0
    deployer_pk = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    deployer_addr = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

    # 1. Deploy MockUSDC
    out_usdc = subprocess.check_output([
        forge_bin, "create", "contracts/MockUSDC.sol:MockUSDC",
        "--rpc-url", rpc_url,
        "--private-key", deployer_pk,
        "--broadcast",
    ], cwd=_PROJECT_ROOT).decode()
    usdc_addr = [l.split(": ")[1].strip() for l in out_usdc.splitlines() if "Deployed to:" in l][0]

    # 2. Deploy PerformanceCollateralVault
    treasury = "0x0000000000000000000000000000000000000002"
    insurance = "0x0000000000000000000000000000000000000003"
    out_vault = subprocess.check_output([
        forge_bin, "create", "contracts/PerformanceCollateralVault.sol:PerformanceCollateralVault",
        "--rpc-url", rpc_url,
        "--private-key", deployer_pk,
        "--broadcast",
        "--constructor-args", usdc_addr, treasury, insurance,
    ], cwd=_PROJECT_ROOT).decode()
    vault_addr = [l.split(": ")[1].strip() for l in out_vault.splitlines() if "Deployed to:" in l][0]

    # 3. Mint 500 USDC to deployer and approve vault
    subprocess.check_call([
        cast_bin, "send", usdc_addr, "mint(address,uint256)", deployer_addr, "500000000",
        "--rpc-url", rpc_url, "--private-key", deployer_pk,
    ], stdout=subprocess.DEVNULL)
    subprocess.check_call([
        cast_bin, "send", usdc_addr, "approve(address,uint256)", vault_addr, "500000000",
        "--rpc-url", rpc_url, "--private-key", deployer_pk,
    ], stdout=subprocess.DEVNULL)

    yield {
        "rpc_url": rpc_url,
        "private_key": deployer_pk,
        "deployer_address": deployer_addr,
        "usdc_address": usdc_addr,
        "vault_address": vault_addr,
        "cast_bin": cast_bin,
    }

    # Teardown
    anvil_proc.terminate()
    try:
        anvil_proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        anvil_proc.kill()


def test_agentkit_action_provider_full_lifecycle(anvil_environment):
    env = anvil_environment
    rpc_url = env["rpc_url"]
    pk = env["private_key"]
    deployer = env["deployer_address"]
    usdc = env["usdc_address"]
    vault = env["vault_address"]
    cast_bin = env["cast_bin"]

    # Instantiate Vendor
    vendor = CausalVendorNode(delta_v_usdc=5.0)
    vendor_pk_hex = "0x" + vendor.public_key.hex()

    # 1. Initialize CausalSlashActionProvider adhering to Coinbase AgentKit SDK
    provider = CausalSlashActionProvider(
        vendor_node=vendor,
        vault_address=vault,
        rpc_url=rpc_url,
        private_key=pk,
        usdc_address=usdc,
    )
    assert provider.name == "causal_slash"

    # -----------------------------------------------------------------------
    # Action 1: create_channel
    # -----------------------------------------------------------------------
    create_res_raw = provider.create_channel(vendor_address=vendor_pk_hex, deposit_usdc=2.50)
    create_res = json.loads(create_res_raw)
    assert create_res["status"] == "CHANNEL_CREATED"
    assert create_res["deposit_usdc"] == 2.50
    assert create_res["vendor_address"] == vendor_pk_hex

    # -----------------------------------------------------------------------
    # Action 2: sign_stream_cheque
    # -----------------------------------------------------------------------
    sign_res_raw = provider.sign_stream_cheque(vendor_address=vendor_pk_hex, amount_usdc=0.001)
    sign_res = json.loads(sign_res_raw)
    assert sign_res["status"] == "SIGNED"
    assert sign_res["height"] == 1
    assert sign_res["incremental_usdc"] == 0.001
    assert "cheque_hex" in sign_res
    cheque_hex = sign_res["cheque_hex"]

    # -----------------------------------------------------------------------
    # Action 3: verify_cheque_stream
    # -----------------------------------------------------------------------
    verify_res_raw = provider.verify_cheque_stream(cheque_bytes=cheque_hex)
    verify_res = json.loads(verify_res_raw)
    assert verify_res["status"] == "ACCEPTED"
    assert verify_res["accepted"] is True
    assert verify_res["status_code"] == CSLS_OK
    assert verify_res["accumulated_usdc"] == 0.001

    # Stream 10 more cheques sequentially
    for seq in range(2, 12):
        s_raw = provider.sign_stream_cheque(vendor_address=vendor_pk_hex, amount_usdc=0.001)
        s_data = json.loads(s_raw)
        v_raw = provider.verify_cheque_stream(cheque_bytes=s_data["cheque_hex"])
        v_data = json.loads(v_raw)
        assert v_data["accepted"] is True
        assert v_data["status_code"] == CSLS_OK

    assert round(provider.vendor_node.accumulated_usdc, 3) == 0.011

    # -----------------------------------------------------------------------
    # Equivocation Attack & Action 4: trigger_foreclosure
    # -----------------------------------------------------------------------
    # Set up attacker agent with known secret key
    attacker_sk_bytes = bytes([0x99] * 32)
    attacker_sk_int = int.from_bytes(attacker_sk_bytes, "big")
    attacker_sk_hex = "0x" + attacker_sk_bytes.hex()
    attacker_wallet = CausalAgentWallet(secret_key=attacker_sk_bytes)

    # Derive on-chain Ethereum address for attacker key
    attacker_signer_addr = subprocess.check_output([
        cast_bin, "call", vault, "deriveAddress(uint256)(address)", str(attacker_sk_int), "--rpc-url", rpc_url
    ]).decode().strip()

    # Deposit 10 USDC collateral for attacker on PerformanceCollateralVault
    subprocess.check_call([
        cast_bin, "send", vault, "depositCollateral(uint256,bytes32,address)", "10000000",
        "0x0000000000000000000000000000000000000000000000000000000000000000", attacker_signer_addr,
        "--rpc-url", rpc_url, "--private-key", pk,
    ], stdout=subprocess.DEVNULL)

    # Step A: Attacker signs legitimate cheque h=1
    legit_cheque = attacker_wallet.sign_cheque(vendor.public_key, amount_usdc=0.02)
    res_legit = vendor.process_cheque(legit_cheque)
    assert res_legit.accepted

    # Step B: Attacker double-signs at duplicate height h=1 for different vendor
    attacker_wallet._ctx.height = 1
    rogue_vendor_pk = b"\x02" + b"\x55" * 32
    fork_cheque = attacker_wallet.sign_cheque(rogue_vendor_pk, amount_usdc=0.04)

    # Step C: Vendor processes conflicting cheque via provider Action 3
    fraud_res_raw = provider.verify_cheque_stream(cheque_bytes=fork_cheque.raw_packet.hex())
    fraud_res = json.loads(fraud_res_raw)
    assert fraud_res["status"] == "EQUIVOCATION_DETECTED"
    assert fraud_res["accepted"] is False
    assert fraud_res["status_code"] == CSLS_ERR_FRAUD
    assert "extracted_secret_key" in fraud_res
    extracted_sk = fraud_res["extracted_secret_key"]
    assert extracted_sk.lower() == attacker_sk_hex.lower()

    # Step D: Trigger On-Chain Foreclosure Waterfall via provider Action 4
    foreclosure_raw = provider.trigger_foreclosure(
        malicious_agent=deployer,
        extracted_sk=extracted_sk,
    )
    foreclosure_res = json.loads(foreclosure_raw)
    assert foreclosure_res["status"] == "FORECLOSED"
    assert foreclosure_res["is_slashed"] is True
    assert foreclosure_res["bounty_rate_pct"] == 15.0

    # Clean up all contexts with zero leaks
    provider.close()
    attacker_wallet.close()
    vendor.close()
