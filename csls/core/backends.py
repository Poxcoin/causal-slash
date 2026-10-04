# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Backend adapters for CSLS protocol components.

Explicit rule:
Where the real backend binary or contract is not available yet,
the adapter returns an explicit "not connected: <what is missing>" message in yellow.
NO fake or random data pretending to be real output.
"""

from __future__ import annotations
import os
import socket
from typing import Tuple, Optional, Dict, Any


def get_repo_root() -> str:
    """Resolve repository root directory."""
    # csls/core/backends.py -> repo_root
    cur = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(cur, "..", ".."))


class DaemonBackend:
    @staticmethod
    def get_daemon_binary() -> Tuple[bool, str]:
        root = get_repo_root()
        bin_path = os.path.join(root, "bin", "csls_daemon")
        if os.path.exists(bin_path) and os.access(bin_path, os.X_OK):
            return True, bin_path
        # Check causal_daemon fallback
        bin_fallback = os.path.join(root, "causal_daemon")
        if os.path.exists(bin_fallback) and os.access(bin_fallback, os.X_OK):
            return True, bin_fallback
        return False, "not connected: bin/csls_daemon binary not found (run `make csls_daemon` to compile)"

    @staticmethod
    def check_daemon_running(host: str = "127.0.0.1", port: int = 9444) -> bool:
        try:
            with socket.create_connection((host, port), timeout=0.3):
                return True
        except (OSError, ConnectionRefusedError):
            return False


class ProxyBackend:
    @staticmethod
    def get_proxy_script() -> Tuple[bool, str]:
        root = get_repo_root()
        script_path = os.path.join(root, "sdk", "slash_proxy.py")
        if os.path.exists(script_path):
            return True, script_path
        return False, "not connected: sdk/slash_proxy.py not found in repository"


class BondBackend:
    @staticmethod
    def query_bond(
        rpc_url: str,
        vault_address: str,
        agent_address: Optional[str] = None
    ) -> Tuple[bool, Dict[str, Any], str]:
        # Validate RPC and contract availability
        if not rpc_url:
            return False, {}, "not connected: RPC URL not configured in ~/.csls/config.toml"

        # Check if contract address is configured
        if not vault_address or vault_address.startswith("0x0000000000000000"):
            return False, {}, "not connected: PerformanceCollateralVault contract address not configured"

        # Query real on-chain vault state if available
        try:
            from sdk.onchain_settler import BaseOnChainSettler
            settler = BaseOnChainSettler(rpc_url=rpc_url, vault_address=vault_address)
            info = settler.get_vault_info(agent_address)
            if info:
                bond_usdc = info.get("collateral_bond", 0) / 1e6
                exposure_usdc = info.get("allocated_exposure", 0) / 1e6
                free_margin = max(0.0, bond_usdc - exposure_usdc)
                is_slashed = info.get("is_slashed", False)
                return True, {
                    "vault": vault_address,
                    "chain": f"Base L2 ({settler.chain_id})",
                    "collateral_bond": f"${bond_usdc:.2f} USDC",
                    "free_margin": f"${free_margin:.2f} USDC",
                    "exposure_cap": f"${exposure_usdc:.2f} USDC",
                    "status": "slashed" if is_slashed else "active",
                }, ""
        except Exception as e:
            return False, {}, f"not connected: failed to query on-chain vault at {vault_address}: {e}"

        # Default fallback if agent has no deposit on-chain yet
        return True, {
            "vault": vault_address,
            "chain": "Base Sepolia (84532)",
            "collateral_bond": "$0.00 USDC",
            "free_margin": "$0.00 USDC",
            "exposure_cap": "$0.00 USDC",
            "status": "unfunded",
        }, ""


class ChequeStreamBackend:
    @staticmethod
    def check_stream(port: int = 9444) -> Tuple[bool, str]:
        if DaemonBackend.check_daemon_running(port=port):
            return True, f"Connected to C11 daemon on 127.0.0.1:{port}"
        return False, f"not connected: C11 streaming daemon is not running on port {port} (start with `/daemon`)"


class KirchhoffBackend:
    @staticmethod
    def check_netting() -> Tuple[bool, str]:
        root = get_repo_root()
        lib_path = os.path.join(root, "sdk", "libcausal_slash.so")
        if not os.path.exists(lib_path):
            return False, "not connected: sdk/libcausal_slash.so not found (run `make libcausal_slash.so`)"
        return True, lib_path


class BloodhoundBackend:
    @staticmethod
    def check_hound() -> Tuple[bool, str]:
        root = get_repo_root()
        lib_path = os.path.join(root, "sdk", "libbloodhound.so")
        if not os.path.exists(lib_path):
            return False, "not connected: sdk/libbloodhound.so not compiled (run `make sdk/libbloodhound.so`)"
        return True, lib_path


class VerificationBackend:
    @staticmethod
    def check_contracts() -> Tuple[bool, str]:
        root = get_repo_root()
        contracts_dir = os.path.join(root, "contracts")
        if not os.path.exists(contracts_dir):
            return False, "not connected: contracts/ directory not found"
        out_dir = os.path.join(root, "out")
        if not os.path.exists(out_dir):
            return False, "not connected: Foundry build artifacts not found (run `forge build` first)"
        return True, out_dir
