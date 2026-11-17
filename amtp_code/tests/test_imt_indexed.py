"""Indexed IMT: incremental maintenance must equal a full rebuild, and present /
absent evidence must verify, after any mix of key additions and removals."""
import json
import random

from amtp.core import boolean
from amtp.dht import DHT
from amtp.engine import Engine
from amtp.core.hashing import H
from amtp.server import _absent_evidence, build_response
from amtp.user import DataUser
from amtp.variants import AdaptivePolicy
from bench.workload import Doc


def _check(eng, dht, user, queries):
    state = eng.snapshot()                      # recomputes next pointers from the sorted keys
    assert state.R_D == eng.R_D
    for i, ast in enumerate(queries):
        b_q = boolean.canonical(ast)
        resp = json.loads(json.dumps(build_response(state, b_q, f"{i:032x}", dht)))
        ctx = {"domain": "A", "B_Q": json.loads(json.dumps(b_q)), "epoch": state.epoch,
               "nonce": f"{i:032x}", "R_D": state.R_D.hex()}
        rep = user.verify(ctx, resp)
        assert rep["accepted"], rep["failed"]


def test_incremental_imt_equals_rebuild_under_churn():
    rnd = random.Random(7)
    vocab = [f"w{i}" for i in range(300)]
    eng = Engine("A", AdaptivePolicy(4, 2, 8))
    dht, live, n = DHT(), [], 0
    user = DataUser("u", "u", "", [], {}, {})

    def new_doc():
        nonlocal n
        n += 1
        words = set(rnd.sample(vocab, 3)) | {f"rare{n}"}      # every doc brings a new key
        d = Doc(f"d{n}", rnd.randrange(4), words)
        dht.put(d.cid, d.ct)
        return d

    for d in (new_doc() for _ in range(20)):
        eng.insert(d.cid, d.keys, d.bucket)
        live.append(d.cid)
    eng.commit()
    for step in range(40):                       # grows past several capacity doublings
        for _ in range(rnd.randint(1, 6)):
            if live and rnd.random() < 0.4:
                eng.delete(live.pop(rnd.randrange(len(live))))
            else:
                d = new_doc()
                eng.insert(d.cid, d.keys, d.bucket)
                live.append(d.cid)
        eng.commit()
        keys = sorted(eng.rho)
        present = rnd.choice(keys).hex()
        absent = H("kw", f"never-{step}").hex()
        _check(eng, dht, user, [("leaf", present), ("leaf", absent),
                                ("OR", [("leaf", present), ("leaf", absent)])])


def test_forged_absence_of_an_indexed_key_is_rejected():
    eng = Engine("A", AdaptivePolicy(2, 1, 4))
    dht = DHT()
    for i in range(6):
        d = Doc(f"d{i}", i % 2, {f"w{i}", "shared"})
        dht.put(d.cid, d.ct)
        eng.insert(d.cid, d.keys, d.bucket)
    eng.commit()
    state = eng.snapshot()
    h = sorted(eng.rho)[3]
    ev = _absent_evidence(state, h)              # honest predecessor of an indexed key
    assert bytes.fromhex(ev["lo"]["next"]) == h  # so h < next(h_lo) fails at the verifier
