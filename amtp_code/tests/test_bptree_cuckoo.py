"""B+ Search Tree and Cuckoo filter (Phase 2 Step 2-3, Phase 4 lookup).

  1. B+ tree = dict under random insert / delete (every order), invariants hold, predecessor is right
  2. Cuckoo filter never answers "absent" for a stored key, through inserts, deletes and rebuilds
  3. the engine keeps its B+ tree and filter consistent with the indexed key set across splits/merges
  4. the filter is not evidence: a false "maybe" and a forced "absent" both end in a valid IMT proof
"""
import bisect
import json
import os
import random

import pytest

from amtp.bptree import BPlusTree
from amtp.core.hashing import H
from amtp.cuckoo import CuckooFilter
from amtp.engine import Engine
from amtp.scenario import World
from amtp.variants import AdaptivePolicy


@pytest.mark.parametrize("order", [4, 5, 8, 64])
def test_bptree_matches_dict_under_random_updates(order):
    rnd = random.Random(order)
    t, d = BPlusTree(order), {}
    for step in range(6000):
        k = rnd.randrange(800)
        r = rnd.random()
        if r < 0.45:
            t[k] = step
            d[k] = step
        elif r < 0.55:
            assert t.setdefault(k, -step) == d.setdefault(k, -step)
        else:
            assert t.pop(k, None) == d.pop(k, None)
        if step % 500 == 0:
            assert t.check()
    assert t.check()
    assert list(t.items()) == sorted(d.items())
    assert len(t) == len(d) and all((k in t) == (k in d) for k in range(-1, 801))
    keys = sorted(d)
    for q in range(-1, 802):
        i = bisect.bisect_left(keys, q)
        assert t.predecessor(q) == (keys[i - 1] if i else None)


def test_bptree_bulk_load_then_update():
    t = BPlusTree.from_sorted([(i, str(i)) for i in range(0, 20000, 2)], order=64)
    assert t.check() and len(t) == 10000
    for i in range(1, 20000, 4):
        t[i] = "odd"
    for i in range(0, 20000, 6):
        del t[i]
    assert t.check()
    with pytest.raises(KeyError):
        t[0]
    with pytest.raises(ValueError):
        BPlusTree.from_sorted([(2, 0), (1, 0)])


def test_cuckoo_has_no_false_negatives():
    rnd = random.Random(1)
    f, live = CuckooFilter(64), []
    for step in range(30000):
        if live and rnd.random() < 0.3:
            h = live.pop(rnd.randrange(len(live)))
            assert f.delete(h)
        else:
            h = os.urandom(32)
            live.append(h)
            if not f.insert(h):                       # full: rebuild from the complete key set
                f = CuckooFilter.from_keys(live, 2 * len(live))
        if step % 3000 == 0:
            assert all(f.might_contain(x) for x in live)
    assert all(f.might_contain(x) for x in live)
    fp = sum(f.might_contain(os.urandom(32)) for _ in range(20000))
    assert fp < 200                                   # well under 1 %


def test_engine_tree_and_filter_track_the_indexed_keys():
    eng = Engine("A", AdaptivePolicy(4, 2, 8))
    rnd = random.Random(9)
    vocab = [H("w", i) for i in range(400)]
    live, k = [], 0
    for _ in range(80):
        for _ in range(rnd.randint(1, 12)):
            if live and rnd.random() < 0.45:
                eng.delete(live.pop(rnd.randrange(len(live))))
            else:
                cid = H("doc", k)
                k += 1
                eng.insert(cid, rnd.sample(vocab, rnd.randint(1, 6)), rnd.randrange(4))
                live.append(cid)
        eng.commit()
        assert isinstance(eng.comp, BPlusTree) and eng.comp.check()
        assert set(eng.comp.keys()) == set(eng.rho)
        assert all(eng.cuckoo.might_contain(h) for h in eng.comp.keys())
        assert eng.R_D == eng.snapshot().R_D


class _Always:
    def __init__(self, answer):
        self.answer = answer

    def might_contain(self, h):
        return self.answer


@pytest.mark.parametrize("answer", [True, False])
def test_filter_answer_never_replaces_imt_proof(answer):
    """True: a false positive for an absent key must still fall through to the tree and an IMT
    non-membership proof. False (forced "absent"): the server must still send the IMT proof,
    and for a key that IS indexed the user rejects the absence claim."""
    w = World()
    user = w.users["mali"]
    state = w.server.current("A")
    state.cuckoo = _Always(answer)
    t_q, ctx = user.make_query("A", "nosuchword OR insulin", w.anchor)
    resp = json.loads(json.dumps(w.server.search(t_q)["response"]))
    ev = {e["status"] for e in resp["proof"]["evidence"]}
    rep = user.verify(ctx, resp)
    if answer:
        assert rep["accepted"] and ev == {"absent", "present"}
    else:
        assert ev == {"absent"}                       # 'insulin' wrongly reported absent ...
        assert not rep["accepted"] and rep["failed"] == "idx"   # ... and the IMT bracket check catches it
