"""Placement rule "fill" (amtp/variants.py): a new file goes to the fullest partition of its bucket with
n < θ_max; if every partition of the bucket is full, to the fullest one, and split repairs it at commit.

  1. the rule picks exactly that partition (ties: smaller PID), "least" is unchanged, a bad name is refused
  2. AMTP with fill: incremental root = full rebuild, θ_min <= n <= θ_max after every commit, splits and merges
  3. Static-MT with fill never restructures and lets the fullest partition grow past θ_max
  4. one batch touches fewer partitions with fill than with least (the point of the rule)
  5. honest queries verify on a fill layout
Validator, tamper and protocol checks with fill: tests/test_update_protocol.py (parametrized over both rules).
"""
import json
import random

import pytest

from amtp.core import boolean
from amtp.core.hashing import H
from amtp.dht import DHT
from amtp.engine import Engine
from amtp.server import build_response
from amtp.user import DataUser
from amtp.variants import AdaptivePolicy, StaticPolicy
from bench.workload import synthetic_docs


class FakeEngine:
    """Only what place() reads: the partitions of each bucket and their live counts."""

    def __init__(self, live, bucket=0):
        self.live = dict(live)
        self.by_bucket = {bucket: set(live)}


@pytest.mark.parametrize("live, want", [
    ({"p1": 10, "p2": 30, "p3": 20}, "p2"),            # fullest
    ({"p1": 63, "p2": 64, "p3": 70}, "p1"),            # n < θ_max first, even if others are fuller
    ({"p2": 40, "p1": 40, "p3": 5}, "p1"),             # tie: smaller PID
    ({"p1": 64, "p2": 66, "p3": 65}, "p2"),            # all full: the fullest one anyway
    ({"p2": 64, "p1": 64}, "p1"),                      # all full, tie: smaller PID
    ({"p1": 0}, "p1"),                                 # a single empty partition
])
def test_fill_picks_the_fullest_partition_below_theta_max(live, want):
    assert AdaptivePolicy(1, 16, 64, "fill").place(FakeEngine(live), 0) == want


def test_least_rule_is_unchanged_and_default():
    eng = FakeEngine({"p1": 10, "p2": 30, "p3": 10})
    assert AdaptivePolicy(1, 16, 64).placement == "least"
    assert AdaptivePolicy(1, 16, 64).place(eng, 0) == "p1"
    assert AdaptivePolicy(1, 16, 64, "least").place(eng, 0) == "p1"


def test_unknown_placement_is_refused():
    with pytest.raises(ValueError):
        AdaptivePolicy(1, 16, 64, "random")


def test_static_inherits_the_rule():
    assert StaticPolicy(1, 16, 64, "fill").place(FakeEngine({"p1": 10, "p2": 30}), 0) == "p2"


def random_updates(eng, seed, steps=60, b_max=12):
    rnd = random.Random(seed)
    vocab = [H("w", i) for i in range(50)]
    live, k, splits, merges = [], 0, 0, 0
    for _ in range(steps):
        for _ in range(rnd.randint(1, b_max)):
            if live and rnd.random() < 0.45:
                eng.delete(live.pop(rnd.randrange(len(live))))
            else:
                cid = H("doc", seed, k)
                k += 1
                eng.insert(cid, rnd.sample(vocab, rnd.randint(1, 5)), rnd.randrange(4))
                live.append(cid)
        st = eng.commit()
        splits, merges = splits + st["splits"], merges + st["merges"]
        assert eng.R_D == eng.snapshot().R_D            # incremental maintenance = full rebuild
    return splits, merges


@pytest.mark.parametrize("seed", range(4))
def test_amtp_fill_keeps_thresholds_and_roots(seed):
    pol = AdaptivePolicy(4, 2, 8, "fill")
    eng = Engine("A", pol)
    rnd = random.Random(seed)
    vocab = [H("w", i) for i in range(50)]
    live, k, splits, merges = [], 0, 0, 0
    for _ in range(60):
        for _ in range(rnd.randint(1, 12)):
            if live and rnd.random() < 0.45:
                eng.delete(live.pop(rnd.randrange(len(live))))
            else:
                cid = H("doc", seed, k)
                k += 1
                eng.insert(cid, rnd.sample(vocab, rnd.randint(1, 5)), rnd.randrange(4))
                live.append(cid)
        st = eng.commit()
        splits, merges = splits + st["splits"], merges + st["merges"]
        assert eng.R_D == eng.snapshot().R_D
        assert all(n <= pol.theta_max for n in eng.live.values())      # split repaired every overflow
    assert splits > 0 and merges > 0


def test_static_fill_never_restructures_and_grows_past_theta_max():
    eng = Engine("A", AdaptivePolicy(4, 2, 8, "fill"))
    random_updates(eng, seed=5, steps=10)
    eng.policy = StaticPolicy(4, 2, 8, "fill")
    before = set(eng.parts)
    rnd = random.Random(1)
    for i in range(80):                                 # inserts only: every bucket fills up
        eng.insert(H("more", i), [H("w", rnd.randrange(50))], i % 4)
    eng.commit()
    assert set(eng.parts) == before
    assert max(eng.live.values()) > 8
    assert eng.R_D == eng.snapshot().R_D
    # the overflow piles up instead of spreading: at most one overgrown partition per bucket
    # (a merged partition can serve two buckets, so count over the whole domain)
    assert sum(n > 8 for n in eng.live.values()) <= 4


def _touched_by_one_batch(placement, b=40):
    eng = Engine("A", AdaptivePolicy(4, 4, 16, placement))
    docs = synthetic_docs(800, 4, vocab=200, seed=3)
    for d in docs:
        eng.insert(d.cid, d.keys, d.bucket)
    eng.commit()
    eng.policy = StaticPolicy(4, 4, 16, placement)       # as in exp3: frozen, only the placement matters
    for i, d in enumerate(synthetic_docs(b, 4, vocab=200, seed=99)):
        eng.insert(H("fresh", i), d.keys, d.bucket)
    return eng.commit()["partitions_changed"]


def test_fill_touches_fewer_partitions_per_batch():
    least, fill = _touched_by_one_batch("least"), _touched_by_one_batch("fill")
    assert 2 * fill <= least                            # 15 vs 35 partitions for 40 files


def test_queries_verify_on_a_fill_layout():
    docs = synthetic_docs(300, 4, vocab=200, seed=2)
    dht = DHT()
    eng = Engine("A", AdaptivePolicy(4, 2, 8, "fill"))
    for d in docs[:200]:
        dht.put(d.cid, d.ct)
        eng.insert(d.cid, d.keys, d.bucket)
    eng.commit()
    for i in range(0, 100, 10):                         # later batches go through the fill rule
        for d in docs[200 + i:210 + i]:
            dht.put(d.cid, d.ct)
            eng.insert(d.cid, d.keys, d.bucket)
        eng.commit()
    state = eng.snapshot()
    user = DataUser("t", "t", "", [], {}, {})
    words = [H("kw", f"w{i}").hex() for i in (1, 5, 30, 199)]
    for ast in [("leaf", words[0]), ("AND", [("leaf", words[1]), ("leaf", words[2])]),
                ("OR", [("leaf", words[2]), ("leaf", H("kw", "absent").hex())])]:
        b_q = boolean.canonical(ast)
        resp = json.loads(json.dumps(build_response(state, b_q, "00" * 16, dht)))
        ctx = {"domain": "A", "B_Q": json.loads(json.dumps(b_q)), "epoch": state.epoch,
               "nonce": "00" * 16, "R_D": state.R_D.hex()}
        assert user.verify(ctx, resp)["accepted"]
