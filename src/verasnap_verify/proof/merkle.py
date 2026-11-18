"""Merkle batch anchoring as implemented by the VeraSnap apps (iOS `MerkleTree`).

* leaf   = SHA-256(EventHash bytes)
* parent = SHA-256(left || right)      (no domain-separation prefix)
* the leaf list is padded to a power of two by repeating the last leaf
* single-event trees: root = leaf (legacy proofs used root = EventHash)
* proof = sibling hashes from leaf to root; index parity picks the side

Note: draft-vso-cpp-core uses 0x00/0x01 domain separation; proofs made by the
apps up to 1.6.1 do not, and this module matches the apps.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


def _strip(h: str) -> str:
    return h.lower().removeprefix("sha256:")


def _bytes(h: str) -> bytes:
    return bytes.fromhex(_strip(h))


def leaf_hash(event_hash: str) -> str:
    return hashlib.sha256(_bytes(event_hash)).hexdigest()


def verify_inclusion(event_hash: str, proof: list[str], index: int, root: str) -> bool:
    try:
        current = bytes.fromhex(leaf_hash(event_hash))
        idx = index
        for sibling in proof:
            sib = _bytes(sibling)
            current = hashlib.sha256(current + sib if idx % 2 == 0 else sib + current).digest()
            idx //= 2
        return current.hex() == _strip(root)
    except ValueError:
        return False


def verify_single(event_hash: str, root: str) -> tuple[bool, bool]:
    """(matches, legacy) for a one-leaf tree."""
    try:
        if leaf_hash(event_hash) == _strip(root):
            return True, False
        if _strip(event_hash) == _strip(root):
            return True, True
    except ValueError:
        pass
    return False, False


@dataclass(frozen=True)
class Tree:
    root: str  # hex
    tree_size: int
    proofs: list[list[str]]  # per leaf, "sha256:<hex>" siblings


def build(event_hashes: list[str]) -> Tree:
    """Build a tree the way the apps do (used by tests and fixture tools)."""
    leaves = [leaf_hash(h) for h in event_hashes]
    n = len(leaves)
    if n == 0:
        raise ValueError("no leaves")
    if n == 1:
        return Tree(leaves[0], 1, [[]])
    size = 1
    while size < n:
        size *= 2
    level = leaves + [leaves[-1]] * (size - n)
    levels = [level]
    while len(level) > 1:
        level = [
            hashlib.sha256(bytes.fromhex(level[i]) + bytes.fromhex(level[i + 1])).hexdigest()
            for i in range(0, len(level), 2)
        ]
        levels.append(level)
    proofs = []
    for i in range(n):
        idx, path = i, []
        for lvl in levels[:-1]:
            sib = idx + 1 if idx % 2 == 0 else idx - 1
            if sib < len(lvl):
                path.append("sha256:" + lvl[sib])
            idx //= 2
        proofs.append(path)
    return Tree(levels[-1][0], n, proofs)
