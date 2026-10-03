#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
On-chain swarm anchoring + settlement stress (Zero-Mock), Arbitrum Sepolia.

Phases:
  keys    derive the hierarchical swarm: depth-10 Merkle tree over 1024
          secp256k1 sub-agents (leaf = keccak256(abi.encodePacked(address)),
          OZ sorted-pair hashing), plus K vendor keys. The first 12 sub-agent
          identities are byte-identical to the C11 TCP stress swarm
          (sk[i] = 0x50+i pattern), so on-chain settlement settles the exact
          cumulative amounts streamed over TCP by the same cryptographic keys.
  anchor  mint MockUSDC -> approve -> depositCollateral(master bond) ->
          setDelegationRoot(root1, depth=10) -> rotation to root2 ->
          assert isRootValid(root1) stays TRUE (7-day ROOT_GRACE_PERIOD).
  settle  fund vendors with gas, then settleSwarmCheque from each vendor with
          EIP-712 SwarmCheque signatures by the sub-agents (heights and
          cumulative amounts taken from the live TCP stress ledger). Verifies:
          delta = cumulativeAmount - lastSettled, master bond debit,
          MockUSDC credit to vendor, on-chain monotonic heights.

Uses sdk/onchain_settler.py (read-only import) for calldata, RFC-6979 ECDSA
signing and cast-send broadcast. No mocks; every action is a real RPC tx.
"""
import argparse
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, ".")
from sdk.causal_eth import keccak256
from sdk.onchain_settler import BaseOnChainSettler

RPC = "https://arbitrum-sepolia-rpc.publicnode.com"
CHAIN_ID = 421614
VAULT = "0x7ff2D6B943e23d5A31772482417FB67c2ED0b8b6"
USDC = "0x8faAD06ef5937Ad1019CD49f5Dcab36181e266A5"
WALLET = "scripts/.deployer_wallet.json"
STATE_DIR = "/tmp/csls_onchain"

DEPTH = 10
N_LEAVES = 2 ** DEPTH  # 1024 sub-agents
N_VENDORS = 6
MINT_AMOUNT = 20_000_000_000  # 20,000 USDC
BOND_AMOUNT = 5_000_000_000   # 5,000 USDC master bond
VENDOR_FUND_ETH = "0.005ether"


def sh(cmd, timeout=120):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        raise RuntimeError(f"cmd failed: {' '.join(cmd[:6])}...\n{p.stderr.strip()[:400]}")
    return p.stdout.strip()


def cast_call(sig, *args):
    cmd = ["cast", "call", VAULT if "vaults(" in sig or "Root" in sig or "Valid" in sig or "Settled" in sig or "Heights" in sig or "Fee" in sig else USDC,
           sig, *map(str, args), "--rpc-url", RPC]
    return sh(cmd)


def usdc_call(sig, *args):
    return sh(["cast", "call", USDC, sig, *map(str, args), "--rpc-url", RPC])


def vault_call(sig, *args):
    return sh(["cast", "call", VAULT, sig, *map(str, args), "--rpc-url", RPC])


def sel(signature: str) -> bytes:
    return keccak256(signature.encode())[:4]


def enc_addr(addr: str) -> bytes:
    return bytes(12) + bytes.fromhex(addr.replace("0x", ""))


def enc_uint(v: int) -> bytes:
    return v.to_bytes(32, "big")


def enc_bytes32(b: bytes) -> bytes:
    return b.rjust(32, b"\x00")


# ---------------------------------------------------------------- merkle

def build_tree(leaves):
    levels = [list(leaves)]
    cur = list(leaves)
    while len(cur) > 1:
        nxt = []
        for i in range(0, len(cur), 2):
            l, r = cur[i], cur[i + 1]
            a, b = (l, r) if l <= r else (r, l)
            nxt.append(keccak256(a + b))
        levels.append(nxt)
        cur = nxt
    return levels[0][0], levels


def merkle_proof(levels, index):
    proof = []
    idx = index
    for level in levels[:-1]:
        sibling = idx ^ 1
        proof.append((level[sibling], idx % 2 == 1))  # (hash, is_right)
        idx //= 2
    return proof  # ordered bottom-up; contract consumes [current, proof[i]] order


# Merkle proof for the contract: at level i, if leaf is LEFT (idx%2==0),
# computed = H(current || proof[i]) else H(proof[i] || current) (sorted-pair).
def contract_proof(levels, index):
    out = []
    idx = index
    for level in levels[:-1]:
        out.append(level[idx ^ 1])
        idx //= 2
    return out


# ---------------------------------------------------------------- phases

def phase_keys(args, master):
    os.makedirs(STATE_DIR, exist_ok=True)
    state_path = os.path.join(STATE_DIR, "swarm_state.json")
    if os.path.exists(state_path) and not args.regenerate:
        with open(state_path) as f:
            state = json.load(f)
        if state.get("depth") == DEPTH:
            print(f"[keys] loaded existing swarm state ({N_LEAVES} leaves) from {state_path}")
            return state

    # Generation 1: 1024 sub-agents. First 12 = the C11 TCP stress identities.
    from sdk.causal_eth import derive_address
    subs = []
    for i in range(N_LEAVES):
        if i < 12:
            sk_bytes = bytes([0x50 + i]) * 32
        else:
            sk_bytes = keccak256(b"csls-swarm-subagent-" + i.to_bytes(4, "big"))
        sk_int = int.from_bytes(sk_bytes, "big")
        addr = "0x" + derive_address(sk_int).hex()
        subs.append({"idx": i, "sk": sk_int, "addr": addr,
                     "leaf": keccak256(bytes.fromhex(addr[2:])).hex()})

    vendors = []
    for j in range(N_VENDORS):
        sk_bytes = keccak256(b"csls-swarm-vendor-" + j.to_bytes(4, "big"))
        sk_int = int.from_bytes(sk_bytes, "big")
        vendors.append({"idx": j, "sk": sk_int, "addr": "0x" + derive_address(sk_int).hex()})

    # Generation 1 tree over sorted leaves.
    leaves = [bytes.fromhex(s["leaf"]) for s in subs]
    order = sorted(range(N_LEAVES), key=lambda i: leaves[i])
    sorted_leaves = [leaves[i] for i in order]
    root1, levels1 = build_tree(sorted_leaves)
    pos = {orig: pos_i for pos_i, orig in enumerate(order)}  # original idx -> position

    # Generation 2 tree: rotate 16 leaves (new sub-agent generation).
    leaves2 = list(leaves)
    rot_positions = list(range(N_LEAVES - 16, N_LEAVES))
    for k, p in enumerate(rot_positions):
        sk2 = int.from_bytes(keccak256(b"csls-swarm-gen2-" + k.to_bytes(4, "big")), "big")
        leaves2[p] = keccak256(derive_address(sk2))
    root2, levels2 = build_tree(leaves2)

    state = {
        "depth": DEPTH,
        "master": master,
        "root1": root1.hex(),
        "root2": root2.hex(),
        "gen2_sk": subs2_sk,
        "sorted_order": order,
        "leaf_position": {str(i): pos[i] for i in range(N_LEAVES)},
        "levels1": [[h.hex() for h in lv] for lv in levels1],
        "subs": subs,
        "vendors": vendors,
    }
    with open(state_path, "w") as f:
        json.dump(state, f)
    print(f"[keys] {N_LEAVES} sub-agents (D={DEPTH}), {N_VENDORS} vendors, "
          f"root1={root1.hex()[:18]}.. root2={root2.hex()[:18]}..  -> {state_path}")
    return state


def phase_anchor(args, state, master_pk):
    master = state["master"]
    root1 = bytes.fromhex(state["root1"])
    root2 = bytes.fromhex(state["root2"])

    m = BaseOnChainSettler(rpc_url=RPC, private_key=master_pk, vault_address=VAULT,
                           chain_id=CHAIN_ID, master_agent=master)
    assert m.caller_address.lower() == master.lower(), "deployer wallet mismatch"

    def tx(label, calldata, to_addr=VAULT):
        t0 = time.time()
        h = m.send_transaction(calldata=calldata, to_address=to_addr)
        print(f"  [tx] {label:<28} {h}  ({time.time()-t0:.1f}s)")
        print(f"       https://sepolia.arbiscan.io/tx/{h}")
        return h

    print("[anchor] pre-state:")
    print("  bond   :", vault_call("vaults(address)(uint256,bytes32,address,address,uint256,uint256,bool)", master))
    print("  usdc   :", usdc_call("balanceOf(address)(uint256)", master))

    # 1. Mint MockUSDC to master (unlimited faucet token of the testnet).
    cd = sel("mint(address,uint256)") + enc_addr(master) + enc_uint(MINT_AMOUNT)
    tx("MockUSDC.mint", cd, to_addr=USDC)

    # 2. Approve vault spend.
    cd = sel("approve(address,uint256)") + enc_addr(VAULT) + enc_uint(BOND_AMOUNT)
    tx("MockUSDC.approve", cd, to_addr=USDC)

    # 3. Deposit master performance bond.
    cd = (sel("depositCollateral(uint256,bytes32,address)")
          + enc_uint(BOND_AMOUNT) + enc_bytes32(b"\x00" * 32) + enc_addr(master))
    tx("depositCollateral", cd)

    # 4. Anchor swarm generation 1.
    cd = sel("setDelegationRoot(bytes32,uint256)") + enc_bytes32(root1) + enc_uint(DEPTH)
    tx("setDelegationRoot(root1,10)", cd)
    got = vault_call("swarmMerkleRoots(address)(bytes32)", master)
    assert got == "0x" + root1.hex(), f"root1 mismatch: {got}"
    ok1 = vault_call("isRootValid(address,bytes32)(bool)", master, "0x" + root1.hex())
    print(f"  [check] swarmMerkleRoots == root1, isRootValid(root1) = {ok1}")
    assert ok1 == "true"

    # 5. Rotate to generation 2 (2-epoch ring buffer + grace registry).
    cd = sel("setDelegationRoot(bytes32,uint256)") + enc_bytes32(root2) + enc_uint(DEPTH)
    tx("setDelegationRoot(root2,10) ROTATION", cd)
    got = vault_call("swarmMerkleRoots(address)(bytes32)", master)
    assert got == "0x" + root2.hex(), f"root2 mismatch: {got}"
    ok1 = vault_call("isRootValid(address,bytes32)(bool)", master, "0x" + root1.hex())
    ok2 = vault_call("isRootValid(address,bytes32)(bool)", master, "0x" + root2.hex())
    print(f"  [check] after rotation: isRootValid(root1) = {ok1} (7-day grace), isRootValid(root2) = {ok2}")
    assert ok1 == "true" and ok2 == "true", "grace-period ring buffer violated"
    print("[anchor] GATE PASS: root rotation preserved generation-1 payments (grace active)")


def phase_settle(args, state, master_pk, ledger_path):
    master = state["master"]
    subs = state["subs"]
    vendors = state["vendors"]
    order = state["sorted_order"]
    pos = state["leaf_position"]

    with open(ledger_path) as f:
        ledger = json.load(f)

    master_settler = BaseOnChainSettler(rpc_url=RPC, private_key=master_pk,
                                        vault_address=VAULT, chain_id=CHAIN_ID,
                                        master_agent=master)

    print(f"[settle] funding {N_VENDORS} vendors with {VENDOR_FUND_ETH} gas each...")
    for v in vendors:
        h = sh(["cast", "send", v["addr"], "--value", VENDOR_FUND_ETH,
                "--private-key", master_pk, "--rpc-url", RPC, "--json"])
        h = json.loads(h)["transactionHash"]
        print(f"  [tx] fund vendor{v['idx']} {v['addr']}: https://sepolia.arbiscan.io/tx/{h}")

    # settle the 12 TCP swarm identities; agents rotate across the vendors
    results = []
    bond_before = int(vault_call("vaults(address)(uint256,bytes32,address,address,uint256,uint256,bool)",
                                 master).split(",")[0], 16)

    for entry in ledger["ledger"]:
        i = entry["agent_idx"]
        sub = subs[i]
        vendor = vendors[i % N_VENDORS]
        height = int(entry["final_height"])
        cumulative = int(entry["final_cumulative_micro"])

        # Merkle proof under generation-1 root (now in grace after rotation!)
        p = pos[str(i)]
        proof = contract_proof([bytes.fromhex(x) for x in state["levels1"]], p)

        vendor_settler = BaseOnChainSettler(rpc_url=RPC, private_key=vendor["sk"].to_bytes(32, "big").hex(),
                                            vault_address=VAULT, chain_id=CHAIN_ID,
                                            master_agent=master)
        assert vendor_settler.caller_address.lower() == vendor["addr"].lower()

        usdc_before = int(usdc_call("balanceOf(address)(uint256)", vendor["addr"]), 16)
        settled_before = int(vault_call("swarmSettledAmounts(address,address)(uint256)",
                                        "0x" + sub["addr"], vendor["addr"]) or "0", 16)
        bond_before_agent = bond_before

        t0 = time.time()
        tx_hash = vendor_settler.settle_swarm_cheque(
            subagent_pk=sub["sk"], height=height, amount=cumulative,
            merkle_proof=proof, master_agent=master, vendor_address=vendor["addr"])
        dt = time.time() - t0

        receipt = json.loads(sh(["cast", "receipt", tx_hash, "--rpc-url", RPC, "--json"], timeout=120))
        gas_used = int(receipt["gasUsed"], 16)
        block = int(receipt["blockNumber"], 16)

        usdc_after = int(usdc_call("balanceOf(address)(uint256)", vendor["addr"]), 16)
        settled_after = int(vault_call("swarmSettledAmounts(address,address)(uint256)",
                                       "0x" + sub["addr"], vendor["addr"]), 16)
        height_onchain = int(vault_call("swarmChannelHeights(address,address)(uint64)",
                                        "0x" + sub["addr"], vendor["addr"]), 16)
        bond_after = int(vault_call("vaults(address)(uint256,bytes32,address,address,uint256,uint256,bool)",
                                    master).split(",")[0], 16)
        bond_before = bond_after

        delta = cumulative - settled_before
        vendor_delta = usdc_after - usdc_before
        bond_delta = bond_before_agent - bond_after

        ok_delta = (settled_after == cumulative)
        ok_funds = (vendor_delta == delta)          # protocolFeeBps = 0
        ok_bond = (bond_delta == delta)
        ok_height = (height_onchain == height)

        print(f"  [settle] agent[{i}] -> vendor{vendor['idx']}: h={height} cum={cumulative} micro "
              f"(${cumulative/1e6:.2f}) delta={delta} vendor_credit={vendor_delta} bond_debit={bond_delta} "
              f"gas={gas_used} block={block} {'OK' if (ok_delta and ok_funds and ok_bond and ok_height) else 'INVARIANT FAIL'}")
        print(f"       https://sepolia.arbiscan.io/tx/{tx_hash}")

        results.append({
            "agent_idx": i, "subagent": sub["addr"], "vendor": vendor["addr"],
            "vendor_idx": vendor["idx"], "channel_height": height,
            "cumulative_micro": cumulative, "delta_micro": delta,
            "vendor_credit_micro": vendor_delta, "bond_debit_micro": bond_delta,
            "gas_used": gas_used, "tx": tx_hash, "block": block,
            "settle_seconds": dt,
            "invariants": {"delta_recorded": ok_delta, "vendor_credited": ok_funds,
                           "bond_debited": ok_bond, "height_monotonic": ok_height},
            "arbiscan": f"https://sepolia.arbiscan.io/tx/{tx_hash}",
        })
        if not (ok_delta and ok_funds and ok_bond and ok_height):
            print("[settle] GATE FAIL")
            return 1

    total_delta = sum(r["delta_micro"] for r in results)
    total_gas = sum(r["gas_used"] for r in results)
    print("-" * 70)
    print(f"[settle] settled {len(results)} final cumulative cheques, "
          f"total delta {total_delta} micro (${total_delta/1e6:,.2f})")
    print(f"[settle] total gas {total_gas} (avg {total_gas//len(results)} per settlement)")
    with open(os.path.join(STATE_DIR, "settlement_report.json"), "w") as f:
        json.dump({"chain_id": CHAIN_ID, "vault": VAULT, "usdc": USDC,
                   "master": master, "settlements": results,
                   "total_delta_micro": total_delta, "total_gas": total_gas}, f, indent=2)
    print("[settle] GATE PASS")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--phase", choices=["keys", "anchor", "settle", "all"], default="all")
    ap.add_argument("--ledger", default="/tmp/stress_ledger.json")
    ap.add_argument("--regenerate", action="store_true")
    args = ap.parse_args()

    with open(WALLET) as f:
        wallet = json.load(f)
    master_pk = wallet["privateKey"]
    master = wallet["address"]

    rc = 0
    state = phase_keys(args, master)
    if args.phase in ("anchor", "all"):
        phase_anchor(args, state, master_pk)
    if args.phase in ("settle", "all"):
        rc = phase_settle(args, state, master_pk, args.ledger)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
