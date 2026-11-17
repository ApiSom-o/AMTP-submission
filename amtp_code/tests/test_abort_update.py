"""Rejected candidates are discarded (Phase 2, Step 5: "obsolete proposals must be regenerated
against the current predecessor").

  1. a candidate rejected by the owner's Validator or by the Root Anchor is rolled back: the
     Cloud Server's engine returns exactly to the finalized predecessor, and the next update passes
  2. a batch that fails half-way (an invalid second request) leaves no trace either
  3. ciphertexts stored only for a discarded candidate are removed; deleted ones are kept
  4. random histories with splits, merges and random rejections: after every rollback the engine
     equals its state before the candidate, and every accepted epoch is validated and anchored
  5. the undo log changes no root: an engine with the log (and rollbacks in between) and one
     without it give the same R_D at every epoch for the same operations
  6. the Root Anchor's own checks (wrong epoch, wrong Δ / signature) reject, and the CS rolls back
  7. after an abort, a Data User's query is accepted (all seven checks) and returns the plaintext
     ground truth of the finalized snapshot
"""
import json
import copy
import random

import pytest

from amtp.core.hashing import H
from amtp.engine import Engine
from amtp.scenario import World
from amtp.validator import Invalid
from amtp.variants import AdaptivePolicy
from tests.test_update_protocol import make_owner, random_requests


def engine_state(eng) -> dict:
    """Every mapping and commitment of the engine, as plain values."""
    def tree(t):
        return (t.n, [list(level) for level in t.levels])
    return {
        "epoch": eng.epoch, "R_D": eng.R_D, "pid_counter": eng._pid_counter,
        "parts": {p: (q.v, list(q.slots)) for p, q in eng.parts.items()},
        "trees": {p: tree(t) for p, t in eng.trees.items()},
        "lineage": dict(eng.lineage), "by_bucket": {b: sorted(s) for b, s in eng.by_bucket.items()},
        "live": dict(eng.live), "free": {p: list(f) for p, f in eng.free.items()},
        "loc": dict(eng.loc), "fwd": dict(eng.fwd),
        "comp": {h: {p: dict(e) for p, e in v.items()} for h, v in eng.comp.items()},
        "keys_in": {p: dict(c) for p, c in eng.keys_in.items()},
        "gam": {h: dict(g) for h, g in eng.gam.items()}, "rho": dict(eng.rho),
        "post": {h: (dict(o), tree(t)) for h, (o, t) in eng.post.items()},
        "part_pos": dict(eng.part_pos), "part_tree": tree(eng.part_tree),
        "imt": tree(eng.imt), "imt_layout": list(eng.imt_layout), "imt_sorted": list(eng.imt_sorted),
        "imt_nxt": dict(eng.imt_nxt), "imt_pos": dict(eng.imt_pos), "imt_free": list(eng.imt_free),
        "cuckoo_count": eng.cuckoo.count,
    }


def assert_finalized(owner):
    """The CS engine, its query snapshot, the validator and the anchor agree on one epoch."""
    eng = owner.server.engines["A"]
    e_star, r_star = owner.anchor.latest("A")
    assert not eng.in_progress and not eng.pending_ops
    assert (eng.epoch, eng.R_D) == (e_star, r_star) == (owner.validator.epoch, owner.validator.R_D)
    assert owner.server.current("A").R_D == r_star
    assert eng.snapshot().R_D == r_star                  # equals the full rebuild
    assert all(eng.cuckoo.might_contain(h) for h in eng.comp.keys())
    eng.comp.check()


def history(seed, b=3, rounds=15):
    rnd = random.Random(seed)
    owner = make_owner(b=b)
    live, k = [], [0]
    for _ in range(rounds):
        owner.update(random_requests(owner, rnd, b, live, k))
    return owner, rnd, live, k


def test_validator_rejection_rolls_back_and_the_next_update_passes(monkeypatch):
    owner, rnd, live, k = history(1)
    eng = owner.server.engines["A"]
    before = engine_state(eng)
    reqs = random_requests(owner, rnd, 3, live, k)

    def reject(proposal, requests):
        raise Invalid("Δ (or Aff_i) differs from the validated update")
    monkeypatch.setattr(owner.validator, "check", reject)
    with pytest.raises(Invalid):
        owner.update(reqs)
    assert engine_state(eng) == before
    assert_finalized(owner)

    monkeypatch.undo()
    owner.update(reqs)                                   # regenerated against the same predecessor
    assert_finalized(owner)
    assert owner.anchor.latest("A")[0] == before["epoch"] + 1


def test_tampered_proposal_is_discarded_and_regenerated():
    owner, rnd, live, k = history(2)
    eng = owner.server.engines["A"]
    before = engine_state(eng)
    reqs = random_requests(owner, rnd, 3, live, k)
    prop = owner.server.prepare_update("A", reqs)
    bad = copy.deepcopy(prop)
    bad["delta"] = bytes(32)
    with pytest.raises(Invalid):
        owner.validator.check(bad, reqs)
    owner.server.abort_update("A")
    assert engine_state(eng) == before
    with pytest.raises(KeyError):                        # nothing left to abort
        owner.server.abort_update("A")
    prop2 = owner.server.prepare_update("A", reqs)
    assert prop2["R_new"] == prop["R_new"] and prop2["delta"] == prop["delta"]
    sig = owner.validator.check(prop2, reqs)
    owner.anchor.submit("A", prop2["epoch_new"], prop2["R_new"], sig, prop2["delta"], prev=prop2["R_old"])
    owner.validator.advance()
    owner.server.finalize_update("A")
    assert_finalized(owner)


def test_anchor_rejection_rolls_back(monkeypatch):
    owner, rnd, live, k = history(3)
    eng = owner.server.engines["A"]
    before = engine_state(eng)
    reqs = random_requests(owner, rnd, 3, live, k)

    def refuse(*args, **kwargs):
        raise ValueError("predecessor root is not the current anchored root")
    monkeypatch.setattr(owner.anchor, "submit", refuse)
    with pytest.raises(ValueError):
        owner.update(reqs)
    assert engine_state(eng) == before
    monkeypatch.undo()
    assert_finalized(owner)
    owner.update(reqs)
    assert_finalized(owner)


def test_batch_failing_half_way_leaves_no_trace():
    owner, rnd, live, k = history(4)
    eng, dht = owner.server.engines["A"], owner.server.dht
    before = engine_state(eng)
    good = random_requests(owner, rnd, 1, live, k)[0]
    bad = copy.deepcopy(good)                            # same nonce: rejected at admission
    with pytest.raises(ValueError):
        owner.server.prepare_update("A", [good, bad])
    assert engine_state(eng) == before
    assert not dht.has(H(good["U"]["ct"]))
    owner.update([good])
    assert_finalized(owner)


def test_storage_follows_the_finalized_state():
    owner, rnd, live, k = history(5, b=2)
    dht = owner.server.dht
    victim = live[0]
    old_cid = owner.doc[victim]
    ins = random_requests(owner, rnd, 1, [], k)[0]       # an insert only
    new_cid = H(ins["U"]["ct"])
    prop = owner.server.prepare_update("A", [owner.delete_request(victim), ins])
    assert dht.has(new_cid) and dht.has(old_cid)
    owner.server.abort_update("A")
    assert not dht.has(new_cid)                          # stored only for the discarded candidate
    assert dht.has(old_cid)                              # its delete was never finalized
    assert prop["epoch_new"] == owner.anchor.latest("A")[0] + 1
    assert_finalized(owner)


@pytest.mark.parametrize("seed", range(5))
def test_random_rejections_with_split_and_merge(seed):
    rnd = random.Random(1000 + seed)
    b = rnd.choice([1, 2, 5])
    owner = make_owner(b=b)
    eng = owner.server.engines["A"]
    live, k = [], [0]
    rejected = accepted = 0
    for _ in range(60):
        snap_live, snap_k = list(live), list(k)
        reqs = random_requests(owner, rnd, b, live, k)
        if rnd.random() < 0.35:
            before = engine_state(eng)
            prop = owner.server.prepare_update("A", reqs)
            assert prop["epoch_new"] == before["epoch"] + 1
            owner.server.abort_update("A")
            assert engine_state(eng) == before
            live[:], k[:] = snap_live, snap_k                # the batch never happened
            rejected += 1
        else:
            owner.update(reqs)
            accepted += 1
        assert_finalized(owner)
    assert rejected and accepted
    full = eng.snapshot()
    assert full.R_D == eng.R_D


@pytest.mark.parametrize("seed", range(4))
def test_undo_log_changes_no_root(seed):
    """Same operations into an engine with the undo log (plus discarded candidates in between)
    and into one without it: the same R_D at every epoch and the same final state."""
    rnd = random.Random(500 + seed)
    plain = Engine("D", AdaptivePolicy(2, 2, 6))
    logged = Engine("D", AdaptivePolicy(2, 2, 6))
    vocab = [H("w", i) for i in range(40)]
    live, nxt = [], 0
    for _ in range(80):
        ops = []
        for _ in range(rnd.randint(1, 4)):
            if live and rnd.random() < 0.4:
                ops.append(("del", live.pop(rnd.randrange(len(live)))))
            else:
                ops.append(("ins", H("cid", nxt), set(rnd.sample(vocab, rnd.randint(1, 5))),
                            rnd.randrange(2)))
                nxt += 1
        if rnd.random() < 0.3:                           # a candidate that gets rejected
            junk = H("junk", nxt)
            nxt += 1
            logged.begin()
            logged.insert(junk, set(rnd.sample(vocab, 3)), 0)
            for op in ops:
                if op[0] == "del":
                    logged.delete(op[1])
            logged.commit(evidence=True)
            logged.rollback()
        logged.begin()
        for eng in (plain, logged):
            for op in ops:
                if op[0] == "ins":
                    eng.insert(op[1], op[2], op[3])
                else:
                    eng.delete(op[1])
        live += [op[1] for op in ops if op[0] == "ins"]
        plain.commit()
        logged.commit(evidence=True)
        logged.accept()
        assert logged.R_D == plain.R_D and logged.epoch == plain.epoch
    assert engine_state(logged) == engine_state(plain)


@pytest.mark.parametrize("change", ["epoch", "delta", "signature"])
def test_root_anchor_rejection_rolls_back(monkeypatch, change):
    """The anchor's own checks reject (no stub raising an error): e' != e* + 1, a Δ the
    signature does not cover, or a signature by a key that is not the domain's owner."""
    from amtp.core.crypto import Signer
    owner, rnd, live, k = history(7)
    eng = owner.server.engines["A"]
    before = engine_state(eng)
    reqs = random_requests(owner, rnd, 3, live, k)
    real = owner.anchor.submit

    def submit(domain, epoch, r_d, sig, delta, prev=None):
        if change == "epoch":
            epoch += 1
        elif change == "delta":
            delta = bytes(32)
        else:
            sig = Signer().sign(b"not the owner")
        return real(domain, epoch, r_d, sig, delta, prev=prev)
    monkeypatch.setattr(owner.anchor, "submit", submit)
    with pytest.raises(ValueError):
        owner.update(reqs)
    assert engine_state(eng) == before
    assert owner.anchor.latest("A") == (before["epoch"], before["R_D"])
    monkeypatch.undo()
    assert_finalized(owner)
    owner.update(reqs)                                   # regenerated, validated, anchored
    assert_finalized(owner)


def _answer(w, user, domain, query):
    t_q, ctx = user.make_query(domain, query, w.anchor)
    out = w.server.search(t_q)
    assert out["status"] == "ok"
    rep = user.verify(ctx, json.loads(json.dumps(out["response"])))
    assert rep["accepted"], rep["failed"]
    got = {r["cid"] for r in out["response"]["R_ct"]}
    owner = w.owners[domain]
    want = {owner.doc[i].hex() for i in w.plaintext_answer(domain, query)}
    assert got == want
    return got, ctx["epoch"]


@pytest.mark.parametrize("query", ["insulin OR diabetes", "insulin AND glucose", "obesity"])
def test_query_after_abort_uses_the_finalized_snapshot(query):
    w = World()
    owner, user = w.owners["A"], w.users["mali"]
    got0, e0 = _answer(w, user, "A", query)
    new_doc = w.pending["A"][0]
    prop = w.server.prepare_update("A", [owner.insert_request(new_doc)])
    assert prop["epoch_new"] == e0 + 1
    w.server.abort_update("A")                           # e.g. the Validator rejected it
    got1, e1 = _answer(w, user, "A", query)
    assert (got1, e1) == (got0, e0)
    w.publish_next("A")                                  # the same document, properly finalized
    got2, e2 = _answer(w, user, "A", query)
    assert e2 == e0 + 1
