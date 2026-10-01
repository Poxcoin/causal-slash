# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Causal-Slash Protocol: Host-side Ethereum toolkit (pure Python, zero dependencies).

Everything needed to speak to PerformanceCollateralVault on Base L2 from the
settlement layer, without pulling web3:

  * keccak-256 (original Keccak padding 0x01, NOT NIST SHA3) - pure Python
    keccak-f[1600], differential-tested against hashlib's SHA3-256 using the
    same permutation (see test/test_causal_eth.py).
  * secp256k1 scalar multiplication / pubkey derivation / address derivation -
    used to replicate the vault's O(1) `deriveAddress(extractedSk)` identity
    check entirely off-chain.
  * Minimal ABI encoder for static types (address, uint256, bytes32 and
    statically-sized tuples) - enough to assemble real calldata for
    depositCollateral / commitFraudProof / revealAndSlash.
  * Binary keccak Merkle tree used to anchor the swarm of subagents into the
    master bond's `nonceMerkleRoot`.

All integers are micro-USDC (6 decimals) unless explicitly stated otherwise.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Iterable, List, Sequence, Tuple

# ---------------------------------------------------------------------------
# keccak-f[1600]
# ---------------------------------------------------------------------------

_M64 = (1 << 64) - 1
_RATE_256 = 136  # bytes per absorb block for 256-bit output (1088-bit rate)

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

# rho offsets, indexed by lane index i = x + 5*y
_RHO = [
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
]


def _rotl(v: int, n: int) -> int:
    n %= 64
    if n == 0:
        return v & _M64
    return ((v << n) | (v >> (64 - n))) & _M64


def _keccak_f1600(state: List[int]) -> None:
    """24-round keccak-f[1600] permutation, in place. `state` is 25 lanes."""
    for rc in _RC:
        # theta
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
             for x in range(5)]
        for x in range(5):
            t = c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1)
            for y in range(5):
                state[x + 5 * y] ^= t
        # rho + pi (B[x'=y, y'=(2x+3y)%5] = rot(A[x,y], r[x,y]))
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(state[x + 5 * y], _RHO[x + 5 * y])
        # chi
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
        # iota
        state[0] ^= rc


def _keccak(data: bytes, rate: int, pad_byte: int, out_len: int) -> bytes:
    state = [0] * 25
    # pad10*1 domain separation: 0x01 = original Keccak, 0x06 = NIST SHA-3
    padded = bytearray(data)
    pad_len = rate - (len(padded) % rate)
    padded += bytes([pad_byte]) + bytes(pad_len - 1)
    padded[-1] |= 0x80

    for block_start in range(0, len(padded), rate):
        block = padded[block_start:block_start + rate]
        for i in range(rate // 8):
            lane = struct.unpack_from("<Q", block, i * 8)[0]
            state[i] ^= lane
        _keccak_f1600(state)

    out = bytearray()
    while len(out) < out_len:
        for i in range(rate // 8):
            out += struct.pack("<Q", state[i])
            if len(out) >= out_len:
                break
        if len(out) < out_len:
            _keccak_f1600(state)
    return bytes(out[:out_len])


def keccak256(data: bytes) -> bytes:
    """Ethereum keccak-256 (Keccak padding 0x01)."""
    return _keccak(bytes(data), _RATE_256, 0x01, 32)


def sha3_256_mode(data: bytes) -> bytes:
    """Same permutation with NIST SHA-3 padding - test oracle interop only."""
    return _keccak(bytes(data), _RATE_256, 0x06, 32)


# ---------------------------------------------------------------------------
# secp256k1 (pure Python; verified against the OpenSSL-backed C engine in tests)
# ---------------------------------------------------------------------------

SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_SECP_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

Point = Tuple[int, int]


def _point_add(p1: Point, p2: Point) -> Point:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % SECP256K1_P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * pow(2 * y1, -1, SECP256K1_P) % SECP256K1_P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, SECP256K1_P) % SECP256K1_P
    x3 = (lam * lam - x1 - x2) % SECP256K1_P
    y3 = (lam * (x1 - x3) - y1) % SECP256K1_P
    return (x3, y3)


def secp256k1_mul(sk: int, point: Point = (_SECP_GX, _SECP_GY)) -> Point:
    """Double-and-add scalar multiplication on secp256k1."""
    if not 0 < sk < SECP256K1_N:
        raise ValueError("scalar out of secp256k1 range")
    result = None
    addend = point
    while sk:
        if sk & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        sk >>= 1
    return result


def pubkey_from_sk(sk: int) -> bytes:
    """33-byte compressed secp256k1 public key (0x02/0x03 prefix)."""
    x, y = secp256k1_mul(sk)
    prefix = 0x02 if y % 2 == 0 else 0x03
    return bytes([prefix]) + x.to_bytes(32, "big")


def decompress_pubkey(pk33: bytes) -> Point:
    """Recover (x, y) from a 33-byte compressed secp256k1 point."""
    if len(pk33) != 33 or pk33[0] not in (0x02, 0x03):
        raise ValueError("expected 33-byte compressed secp256k1 point")
    x = int.from_bytes(pk33[1:], "big")
    y_sq = (pow(x, 3, SECP256K1_P) + 7) % SECP256K1_P
    y = pow(y_sq, (SECP256K1_P + 1) // 4, SECP256K1_P)
    if pow(y, 2, SECP256K1_P) != y_sq:
        raise ValueError("point is not on secp256k1 curve")
    if (y % 2 == 0) != (pk33[0] == 0x02):
        y = SECP256K1_P - y
    return (x, y)


def derive_address(sk: int) -> bytes:
    """
    Replicates PerformanceCollateralVault.deriveAddress(uint256 sk):
    address = last 20 bytes of keccak256(<x:32><y:32>) of sk * G.
    """
    x, y = secp256k1_mul(sk)
    return keccak256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[12:]


def derive_address_from_pk(pk33: bytes) -> bytes:
    x, y = decompress_pubkey(pk33)
    return keccak256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[12:]


def derive_subagent_sk(swarm_seed: bytes, index: int) -> int:
    """Deterministic subagent key material: sk = HMAC-SHA256(seed, domain||index)."""
    if len(swarm_seed) != 32:
        raise ValueError("swarm_seed must be 32 bytes")
    digest = hmac.new(swarm_seed, b"causal-slash/subagent/" + index.to_bytes(4, "big"),
                      hashlib.sha256).digest()
    sk = int.from_bytes(digest, "big") % SECP256K1_N
    if sk == 0:
        raise ValueError("HMAC-derived scalar reduced to zero; regenerate swarm seed")
    return sk


# ---------------------------------------------------------------------------
# Minimal ABI encoding (static types only: address, uint256, bytes32, static tuples)
# ---------------------------------------------------------------------------

def _word(value: bytes) -> bytes:
    if len(value) > 32:
        raise ValueError("ABI word overflow")
    return value.rjust(32, b"\x00")


def abi_encode_uint256(value: int) -> bytes:
    if not 0 <= value < 2 ** 256:
        raise ValueError("uint256 out of range")
    return value.to_bytes(32, "big")


def abi_encode_address(address20: bytes) -> bytes:
    if len(address20) != 20:
        raise ValueError("address must be 20 bytes")
    return _word(address20)


def abi_encode_bytes32(value: bytes) -> bytes:
    if len(value) != 32:
        raise ValueError("bytes32 must be exactly 32 bytes")
    return value


def function_selector(signature: str) -> bytes:
    return keccak256(signature.encode("ascii"))[:4]


def encode_call(signature: str, *static_args: bytes) -> bytes:
    """
    Calldata = selector ++ head sequence of already-word-encoded static args.
    Static tuples (e.g. revealAndSlash((address,uint256,bytes32))) are encoded
    INLINE in calldata: no offset header, components concatenated word-wise.
    """
    return function_selector(signature) + b"".join(
        w if len(w) == 32 else _word(w) for w in static_args
    )


# ---------------------------------------------------------------------------
# PerformanceCollateralVault calldata builders (Base L2)
# ---------------------------------------------------------------------------

SIG_DEPOSIT_COLLATERAL = "depositCollateral(uint256,bytes32,address)"
SIG_COMMIT_FRAUD_PROOF = "commitFraudProof(address,bytes32)"
SIG_REVEAL_AND_SLASH = "revealAndSlash((address,uint256,bytes32))"


def encode_deposit_collateral(amount_micro_usdc: int, merkle_root: bytes,
                              signing_address: bytes) -> bytes:
    return encode_call(
        SIG_DEPOSIT_COLLATERAL,
        abi_encode_uint256(amount_micro_usdc),
        abi_encode_bytes32(merkle_root),
        abi_encode_address(signing_address),
    )


def commit_hash_for(extracted_sk32: bytes, finder_address20: bytes, salt32: bytes) -> bytes:
    """
    Mirrors vault revealAndSlash preimage AND the C Bloodhound payload:
    keccak256(abi.encodePacked(uint256 extractedSk, address finder, bytes32 salt)).
    `extracted_sk32` must be the canonical 32-byte big-endian scalar mod q.
    """
    if len(extracted_sk32) != 32 or len(finder_address20) != 20 or len(salt32) != 32:
        raise ValueError("commit preimage components have fixed sizes: 32/20/32 bytes")
    return keccak256(extracted_sk32 + finder_address20 + salt32)


def encode_commit_fraud_proof(target_agent: bytes, commit_hash: bytes) -> bytes:
    return encode_call(
        SIG_COMMIT_FRAUD_PROOF,
        abi_encode_address(target_agent),
        abi_encode_bytes32(commit_hash),
    )


def encode_reveal_and_slash(malicious_agent: bytes, extracted_sk: int, salt: bytes) -> bytes:
    return encode_call(
        SIG_REVEAL_AND_SLASH,
        abi_encode_address(malicious_agent),
        abi_encode_uint256(extracted_sk),
        abi_encode_bytes32(salt),
    )


# ---------------------------------------------------------------------------
# Swarm Merkle anchoring (100 subagent commitments -> master bond nonceMerkleRoot)
# ---------------------------------------------------------------------------

_EMPTY_LEAF = keccak256(b"causal-slash/dormant-slot")


def merkle_leaf(subagent_pk33: bytes, index: int) -> bytes:
    """leaf_i = keccak256(compressed_pk(33) || uint32be(index))."""
    if len(subagent_pk33) != 33:
        raise ValueError("subagent commitment needs a 33-byte compressed pubkey")
    return keccak256(subagent_pk33 + index.to_bytes(4, "big"))


def _hash_pair(left: bytes, right: bytes) -> bytes:
    return keccak256(left + right)


def build_merkle_tree(leaves: Sequence[bytes]) -> Tuple[List[List[bytes]], bytes]:
    """
    Binary keccak Merkle tree. Leaf count is padded up to the next power of two
    with a constant dormant-slot hash; returns (levels, root) where levels[0]
    is the (padded) leaf layer.
    """
    if not leaves:
        raise ValueError("merkle tree needs at least one leaf")
    level = list(leaves)
    width = 1
    while width < len(level):
        width <<= 1
    level += [_EMPTY_LEAF] * (width - len(level))
    levels: List[List[bytes]] = [level]
    while len(level) > 1:
        level = [_hash_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        levels.append(level)
    return levels, levels[-1][0]


def merkle_proof(levels: List[List[bytes]], index: int) -> List[bytes]:
    """Sibling path for leaf `index` (order: leaf layer -> root)."""
    proof = []
    pos = index
    for level in levels[:-1]:
        sibling = pos ^ 1
        proof.append(level[sibling])
        pos >>= 1
    return proof


def merkle_verify(leaf: bytes, proof: Iterable[bytes], index: int, root: bytes) -> bool:
    node = leaf
    for sibling in proof:
        if index & 1:
            node = _hash_pair(sibling, node)
        else:
            node = _hash_pair(node, sibling)
        index >>= 1
    return node == root
