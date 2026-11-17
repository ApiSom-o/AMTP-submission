"""MerkleTree.set_leaves (one pass, every changed inner node hashed once) against the reference: set_leaf on
each position (one root path per leaf).

  1. every node of the tree, the root and n are identical to the reference, for random trees and positions,
     including positions that fill padding slots
  2. it spends exactly (leaves + distinct ancestors) hashes, never more than the reference
  3. the undo action restores every node and n; an empty call does nothing
  4. the engine gives the same roots as a full rebuild when the IMT doubles its capacity inside a batch,
     and Engine.rollback restores the trees after batched updates
"""
import copy
import random

import pytest

from amtp.core.hashing import H, HashCounter
from amtp.core.merkle import MerkleTree
from amtp.engine import Engine
from amtp.variants import AdaptivePolicy


def _val(seed, i):
    return H("leaf", seed, i)


def _reference(tree, values, n=None):
    """The old way: one set_leaf (or try_append for a padding slot) per position, ascending."""
    ref = copy.deepcopy(tree)
    for i in sorted(values):
        if i < ref.n:
            ref.set_leaf(i, values[i])
        else:
            assert i == ref.n and ref.try_append(values[i])
    assert n is None or ref.n == n
    return ref


def _distinct_ancestors(positions, depth):
    total, level = 0, set(positions)
    for _ in range(depth):
        level = {i // 2 for i in level}
        total += len(level)
    return total


@pytest.mark.parametrize("seed", range(30))
def test_same_tree_as_one_set_leaf_per_position(seed):
    rnd = random.Random(seed)
    n = rnd.choice([1, 2, 3, 5, 8, 13, 64, 100, 257, 1000])
    tree = MerkleTree([_val(seed, i) for i in range(n)])
    capacity = len(tree.levels[0])
    k = rnd.randint(1, n)
    values = {i: _val(seed + 1000, i) for i in rnd.sample(range(n), k)}
    extra = rnd.randint(0, capacity - n)                       # also fill some padding slots
    values.update({n + j: _val(seed + 2000, j) for j in range(extra)})
    n_new = n + extra if extra else None

    ref = _reference(tree, values, n_new)
    c0, _ = HashCounter.snapshot()
    tree.set_leaves(values, n=n_new)
    c1, _ = HashCounter.snapshot()

    assert tree.levels == ref.levels and tree.root == ref.root and tree.n == ref.n
    depth = len(tree.levels) - 1
    assert c1 - c0 == len(values) + _distinct_ancestors(values, depth)
    assert c1 - c0 <= len(values) * (depth + 1)                # the reference: a full path per leaf


@pytest.mark.parametrize("seed", range(10))
def test_undo_restores_every_node_and_n(seed):
    rnd = random.Random(100 + seed)
    n = rnd.choice([1, 6, 33, 200])
    tree = MerkleTree([_val(seed, i) for i in range(n)])
    before, n_before = copy.deepcopy(tree.levels), tree.n
    values = {i: _val(seed + 1, i) for i in rnd.sample(range(n), rnd.randint(1, n))}
    room = len(tree.levels[0]) - n
    if room:
        values[n] = _val(seed + 2, n)
    undo = []
    tree.set_leaves(values, undo, n + 1 if room else None)
    assert tree.levels != before
    assert len(undo) == 1                                      # one action for the whole batch
    for action in reversed(undo):
        action()
    assert tree.levels == before and tree.n == n_before


def test_empty_call_changes_nothing():
    tree = MerkleTree([_val(0, i) for i in range(5)])
    before, undo = copy.deepcopy(tree.levels), []
    c0, _ = HashCounter.snapshot()
    tree.set_leaves({}, undo)
    assert tree.levels == before and undo == [] and HashCounter.snapshot()[0] == c0


def test_two_calls_equal_one_call():
    a = MerkleTree([_val(0, i) for i in range(50)])
    b = copy.deepcopy(a)
    v1 = {i: _val(1, i) for i in (0, 7, 8, 49)}
    v2 = {i: _val(2, i) for i in (7, 20, 21)}
    a.set_leaves(v1)
    a.set_leaves(v2)
    b.set_leaves({**v1, **v2})
    assert a.levels == b.levels


def _batch(eng, rnd, k, n_ops, vocab, live):
    for _ in range(n_ops):
        if live and rnd.random() < 0.3:
            eng.delete(live.pop(rnd.randrange(len(live))))
        else:
            cid = H("doc", k[0])
            k[0] += 1
            eng.insert(cid, rnd.sample(vocab, rnd.randint(1, 6)), rnd.randrange(4))
            live.append(cid)


@pytest.mark.parametrize("placement", ["least", "fill"])
def test_engine_roots_equal_full_rebuild_while_the_imt_grows(placement):
    """Many new keys per batch: the IMT fills its padding and doubles its capacity several times."""
    rnd = random.Random(11)
    vocab = [H("w", i) for i in range(600)]
    eng = Engine("A", AdaptivePolicy(4, 2, 8, placement))
    live, k, capacities = [], [0], set()
    for _ in range(40):
        _batch(eng, rnd, k, rnd.randint(1, 25), vocab, live)
        eng.commit()
        capacities.add(len(eng.imt.levels[0]))
        snap = eng.snapshot()                                  # full rebuild from the committed state
        assert eng.R_D == snap.R_D
        assert eng.imt.root == snap.R_idx and eng.part_tree.root == snap.R_part
        assert eng.imt.n == len(eng.imt_layout)
    assert len(capacities) >= 3                                # the capacity really doubled inside the run


@pytest.mark.parametrize("placement", ["least", "fill"])
def test_rollback_restores_the_trees_after_batched_updates(placement):
    rnd = random.Random(5)
    vocab = [H("w", i) for i in range(120)]
    eng = Engine("A", AdaptivePolicy(4, 2, 8, placement))
    live, k = [], [0]
    for _ in range(15):
        _batch(eng, rnd, k, 12, vocab, live)
        eng.commit()
    for _ in range(10):
        before = (eng.R_D, copy.deepcopy(eng.imt.levels), eng.imt.n, copy.deepcopy(eng.part_tree.levels),
                  {h: copy.deepcopy(t.levels) for h, (_, t) in eng.post.items()})
        kept = list(live)
        eng.begin()
        _batch(eng, rnd, k, 15, vocab, live)
        eng.commit()
        assert eng.R_D != before[0]
        eng.rollback()
        live[:] = kept
        after = (eng.R_D, eng.imt.levels, eng.imt.n, eng.part_tree.levels,
                 {h: t.levels for h, (_, t) in eng.post.items()})
        assert after == before
        assert eng.R_D == eng.snapshot().R_D
        _batch(eng, rnd, k, 10, vocab, live)                   # and the engine keeps working afterwards
        eng.commit()
        assert eng.R_D == eng.snapshot().R_D
