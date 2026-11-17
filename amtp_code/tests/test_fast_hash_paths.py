"""H, leaf_hash, node_hash and root_from_proof were rewritten for speed (one SHA-256 call over the
joined length-prefixed bytes, and one sort per multiproof instead of one per tree level). These tests
keep the old code verbatim as the reference and require the new code to give the same digest, the
same hash count and hashed-byte count, the same accept / None on every proof, and the same errors.
"""
import hashlib
import os
import random

import pytest

from amtp.core import hashing, merkle
from amtp.core.hashing import H, HashCounter, to_bytes
from amtp.core.merkle import MerkleTree, leaf_hash, node_hash, root_from_proof, multiverify


# ---------------------------------------------------------------- the old code, verbatim
def old_H(*parts) -> bytes:
    h = hashlib.sha256()
    n = 0
    for p in parts:
        b = to_bytes(p)
        h.update(len(b).to_bytes(4, "big"))
        h.update(b)
        n += 4 + len(b)
    HashCounter.calls += 1
    HashCounter.bytes += n
    return h.digest()


def old_leaf_hash(value):
    return old_H(b"\x00", value)


def old_node_hash(left, right):
    return old_H(b"\x01", left, right)


def old_root_from_proof(size, known, proof):
    if not known or any(not (0 <= i < size) for i in known):
        return None
    known = dict(known)
    remaining, k = list(proof), 0
    while size > 1:
        nxt = {}
        for p in sorted({i // 2 for i in known}):
            pair = []
            for child in (2 * p, 2 * p + 1):
                if child in known:
                    pair.append(known[child])
                elif k < len(remaining):
                    pair.append(remaining[k])
                    k += 1
                else:
                    return None
            nxt[p] = old_node_hash(pair[0], pair[1])
        known = nxt
        size //= 2
    return known.get(0) if k == len(remaining) else None


def counted(fn, *args):
    """(result or exception type, hash calls, hashed bytes) of one call."""
    c0, b0 = HashCounter.calls, HashCounter.bytes
    try:
        out = fn(*args)
    except Exception as e:                                  # noqa: BLE001 - the error itself is compared
        out = ("raised", type(e).__name__)
    return out, HashCounter.calls - c0, HashCounter.bytes - b0


def same(new, old, *args):
    assert counted(new, *args) == counted(old, *args), args


# ---------------------------------------------------------------- H
PARTS = [b"", b"\x00", os.urandom(31), os.urandom(32), os.urandom(33), os.urandom(1000), "", "abc", "ไทย",
         0, 1, 2 ** 63, 2 ** 64 - 1, bytearray(b"ab"), memoryview(b"ab"), True, None, 1.5, 2 ** 64, -1]


@pytest.mark.parametrize("seed", range(30))
def test_H_same_digest_count_and_errors(seed):
    rnd = random.Random(seed)
    for _ in range(200):
        parts = [rnd.choice(PARTS) for _ in range(rnd.randint(0, 5))]
        same(H, old_H, *parts)


class SubBytes(bytes):
    pass


def test_H_bytes_subclass_and_empty():
    same(H, old_H)
    same(H, old_H, SubBytes(b"xyz"), b"q")


# ---------------------------------------------------------------- leaf / node
@pytest.mark.parametrize("seed", range(20))
def test_leaf_and_node_same_digest_and_count(seed):
    rnd = random.Random(seed)
    for _ in range(300):
        a, b = rnd.choice(PARTS), rnd.choice(PARTS)
        same(leaf_hash, old_leaf_hash, a)
        same(node_hash, old_node_hash, a, b)
    for _ in range(300):                                     # the common case: two 32-byte hashes
        a, b = os.urandom(32), os.urandom(32)
        same(node_hash, old_node_hash, a, b)
        same(leaf_hash, old_leaf_hash, a)


def test_pad_unchanged():
    assert merkle.PAD == old_H(b"\x02")


# ---------------------------------------------------------------- root_from_proof
def tree_and_proof(rnd, n, k):
    vals = [os.urandom(rnd.choice([1, 8, 32, 40])) for _ in range(n)]
    t = MerkleTree(vals)
    idx = sorted(rnd.sample(range(n), k))
    return t, vals, idx, t.multiproof(idx)


def both_rfp(size, known, proof):
    return (counted(root_from_proof, size, known, proof), counted(old_root_from_proof, size, known, proof))


@pytest.mark.parametrize("seed", range(40))
def test_root_from_proof_honest_and_tampered(seed):
    rnd = random.Random(seed)
    for _ in range(40):
        n = rnd.randint(1, 70)
        t, vals, idx, proof = tree_and_proof(rnd, n, rnd.randint(1, n))
        size = merkle.tree_size(n)
        known = {i: old_leaf_hash(vals[i]) for i in idx}
        new, old = both_rfp(size, known, proof)
        assert new == old and new[0] == t.root
        variants = [proof[:-1], proof + [os.urandom(32)], proof[1:], list(reversed(proof)), [],
                    [x if rnd.random() < 0.8 else os.urandom(32) for x in proof]]
        kn2 = dict(known)
        kn2[rnd.choice(list(kn2))] = os.urandom(32)               # a wrong leaf
        extra = rnd.randrange(size)
        kn3 = dict(known)
        kn3[extra] = os.urandom(32)                                # an extra, maybe padding, position
        for pr in variants:
            new, old = both_rfp(size, known, pr)
            assert new == old, ("proof variant", n, idx)
        for kn in (kn2, kn3):
            new, old = both_rfp(size, kn, proof)
            assert new == old, ("known variant", n, idx)


@pytest.mark.parametrize("known,size", [({}, 4), ({4: b"x" * 32}, 4), ({-1: b"x" * 32}, 4), ({0: b"r"}, 1),
                                        ({0: b"r", 1: b"s"}, 2), ({1: b"s"}, 2), ({0: "text"}, 2),
                                        ({True: b"t" * 32}, 2), ({1.0: b"f" * 32}, 2), ({0: None}, 2)])
def test_root_from_proof_edge_inputs(known, size):
    for proof in ([], [b"p" * 32], [b"p" * 32, b"q" * 32], ["str"], [None]):
        new, old = both_rfp(size, known, proof)
        assert new == old, (known, size, proof)


def test_root_from_proof_iterable_proof():
    t = MerkleTree([b"a", b"b", b"c", b"d", b"e"])
    known = {1: old_leaf_hash(b"b"), 4: old_leaf_hash(b"e")}
    pr = t.multiproof([1, 4])
    assert root_from_proof(8, known, iter(pr)) == old_root_from_proof(8, known, iter(pr)) == t.root


@pytest.mark.parametrize("seed", range(10))
def test_multiverify_matches_old_code(seed, monkeypatch):
    rnd = random.Random(seed)
    cases = []
    for _ in range(30):
        n = rnd.randint(1, 50)
        t, vals, idx, proof = tree_and_proof(rnd, n, rnd.randint(1, n))
        leaves = {i: vals[i] for i in idx}
        if rnd.random() < 0.5:
            leaves[rnd.choice(idx)] = b"forged"
        cases.append((t.root, n, leaves, proof if rnd.random() < 0.7 else proof[:-1]))
    new = [counted(multiverify, *c) for c in cases]
    monkeypatch.setattr(merkle, "root_from_proof", old_root_from_proof)
    monkeypatch.setattr(merkle, "leaf_hash", old_leaf_hash)
    old = [counted(multiverify, *c) for c in cases]
    assert new == old


def test_hashing_module_exports_unchanged():
    assert hashing.H is H and merkle.H is H
