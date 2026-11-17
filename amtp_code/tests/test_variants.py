"""Gates for the ablation variants: run with  python -m pytest -q"""
import json
import random

import pytest

from amtp.core import boolean
from amtp.engine import Engine
from amtp.core.hashing import H
from amtp.server import build_response
from amtp.user import DataUser
from amtp.variants import AdaptivePolicy, GlobalPolicy, StaticPolicy
from bench.workload import synthetic_docs
from amtp.dht import DHT

POLICIES = {
    "AMTP": lambda: AdaptivePolicy(4, 2, 8),
    "Global-MT": lambda: GlobalPolicy(4),
    "Global-MT(v)": lambda: GlobalPolicy(4, versioned=True),
}


def random_updates(eng, seed, steps=50):
    rnd = random.Random(seed)
    vocab = [H("w", i) for i in range(50)]
    live, k, splits, merges = [], 0, 0, 0
    for _ in range(steps):
        for _ in range(rnd.randint(1, 10)):
            if live and rnd.random() < 0.45:
                eng.delete(live.pop(rnd.randrange(len(live))))
            else:
                cid = H("doc", seed, k)
                k += 1
                eng.insert(cid, rnd.sample(vocab, rnd.randint(1, 5)), rnd.randrange(4))
                live.append(cid)
        st = eng.commit()
        splits, merges = splits + st["splits"], merges + st["merges"]
        # Gate: incremental maintenance gives exactly the full-rebuild root
        assert eng.R_D == eng.snapshot().R_D
    return splits, merges


@pytest.mark.parametrize("name", POLICIES)
def test_incremental_root_equals_full_rebuild(name):
    eng = Engine("A", POLICIES[name]())
    splits, merges = random_updates(eng, seed=7)
    if name == "AMTP":
        assert splits > 0 and merges > 0          # both adaptations were exercised


def test_amtp_respects_thresholds_after_each_batch():
    eng = Engine("A", AdaptivePolicy(4, 2, 8))
    random_updates(eng, seed=3)
    assert all(n <= 8 for n in eng.live.values())


def test_static_never_restructures():
    eng = Engine("A", AdaptivePolicy(4, 2, 8))
    random_updates(eng, seed=5, steps=10)
    eng.policy = StaticPolicy(4, 2, 8)
    before = set(eng.parts)
    random_updates(eng, seed=6, steps=20)
    assert set(eng.parts) == before


def test_global_has_one_partition():
    eng = Engine("A", GlobalPolicy(4))
    random_updates(eng, seed=9, steps=20)
    assert len(eng.parts) == 1


@pytest.mark.parametrize("name", POLICIES)
def test_queries_verify_on_every_variant(name):
    docs = synthetic_docs(300, 4, vocab=200, seed=2)
    dht = DHT()
    eng = Engine("A", POLICIES[name]())
    for d in docs:
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
