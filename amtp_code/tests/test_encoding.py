"""Binary encodings, one Norm, canonical B_Q.

  1. encodings are unambiguous: different values never share bytes, kinds never collide (tags)
  2. γ is the same whether a cid arrives as bytes (server) or hex (user)
  3. queries with the same meaning (order, grouping, repetition, absorption, Norm) give the same
     B_Q and the same query digest; canonical form keeps the meaning
  4. the server refuses a B_Q that is not canonical; index and query share Norm
"""
import itertools
import json
import random

import pytest

from amtp.anchor import transition_message
from amtp.core import boolean
from amtp.core.hashing import (TAG_BQ, TAG_POSTING, TAG_QUERY, TAG_TRANSITION, enc_bq, enc_posting,
                               lp, u64)
from amtp.core.crypto import hmac_tag
from amtp.index import gamma
from amtp.nlp import norm
from amtp.scenario import World
from amtp.server import query_digest

CID = [bytes([i]) * 32 for i in range(4)]


def test_length_prefix_is_unambiguous():
    assert lp("ab", "c") != lp("a", "bc")
    assert lp(b"", b"x") != lp(b"x", b"")
    assert lp(1) == (8).to_bytes(4, "big") + (1).to_bytes(8, "big")


def test_tags_are_distinct_prefixes():
    tags = [TAG_POSTING, TAG_QUERY, TAG_TRANSITION, TAG_BQ]
    assert len(set(tags)) == len(tags)
    assert not any(a != b and b.startswith(a) for a in tags for b in tags)
    assert enc_posting([]).startswith(TAG_POSTING) and enc_bq(("leaf", "x")).startswith(TAG_BQ)


def test_posting_encoding_is_fixed_width_and_injective():
    comps = [[], [(CID[0], 0)], [(CID[0], 1)], [(CID[1], 0)], [(CID[0], 0), (CID[1], 1)],
             [(CID[1], 1), (CID[0], 0)], [(CID[0], 0), (CID[0], 0)]]
    encs = [enc_posting(c) for c in comps]
    assert len(set(encs)) == len(encs)
    assert len(enc_posting([(CID[0], 5)])) == len(TAG_POSTING) + 8 + 32 + 8


@pytest.mark.parametrize("bad", [[(b"\x00" * 31, 0)], [(CID[0], -1)], [(CID[0], True)], [("zz", 0)]])
def test_posting_encoding_rejects_bad_fields(bad):
    with pytest.raises((ValueError, TypeError)):
        enc_posting(bad)


def test_gamma_is_the_same_for_bytes_and_hex_cids(monkeypatch):
    import amtp.index
    monkeypatch.setattr(amtp.index, "_GAMMA_V", True)     # the paper's γ (with v); without v: test_gamma_flag.py
    comp = [(CID[2], 3), (CID[3], 7)]
    assert gamma("P1", 4, comp) == gamma("P1", 4, [[c.hex(), s] for c, s in comp])
    assert gamma("P1", 4, comp) != gamma("P1", 5, comp) != gamma("P2", 4, comp)


def _random_ast(rnd, depth=0):
    if depth > 2 or rnd.random() < 0.35:
        return ("leaf", rnd.choice("abcde"))
    return (rnd.choice(["AND", "OR"]), [_random_ast(rnd, depth + 1) for _ in range(rnd.randint(1, 3))])


def test_bq_encoding_is_injective_on_trees():
    rnd = random.Random(1)
    seen = {}
    for _ in range(3000):
        ast = _random_ast(rnd)
        e = enc_bq(ast)
        key = json.dumps(ast)
        assert seen.setdefault(e, key) == key


def test_canonical_keeps_meaning_and_is_idempotent():
    rnd = random.Random(2)
    for _ in range(1500):
        ast = _random_ast(rnd)
        c = boolean.canonical(ast)
        assert boolean.canonical(c) == c
        for bits in itertools.product([0, 1], repeat=5):
            sets = {k: ({1} if b else set()) for k, b in zip("abcde", bits)}
            assert boolean.evaluate(ast, sets) == boolean.evaluate(c, sets)


SAME_MEANING = [
    ("insulin AND diabetes", "diabetes AND insulin", "(Insulin AND diabetes) AND insulin"),
    ("insulin OR (glucose AND trial)", "(trial AND glucose) OR insulin", "insulin OR (glucose AND trials)"),
    ("insulin", "insulin AND (insulin OR obesity)", "insulin OR (insulin AND obesity)"),
    ('"machine learning" AND study', 'Studies AND "Machine   Learning"', "study AND \"machine learning's\""),
]


@pytest.mark.parametrize("group", SAME_MEANING)
def test_same_meaning_same_bq_and_digest(group):
    w = World()
    user = w.users["mali"]
    domain = sorted(user.domain_keys)[0]
    qs = [user.make_query(domain, text, w.anchor)[0] for text in group]
    assert len({enc_bq(boolean.from_json(q["B_Q"])) for q in qs}) == 1
    assert len({query_digest(domain, q["B_Q"], 7, 1000, "00" * 16) for q in qs}) == 1


def test_different_meaning_different_digest():
    w = World()
    user = w.users["mali"]
    domain = sorted(user.domain_keys)[0]
    a = user.make_query(domain, "insulin AND diabetes", w.anchor)[0]
    b = user.make_query(domain, "insulin OR diabetes", w.anchor)[0]
    assert query_digest(domain, a["B_Q"], 1, 1, "00" * 16) != query_digest(domain, b["B_Q"], 1, 1, "00" * 16)


def test_transition_message_binds_every_field():
    base = ("A", 3, b"\x01" * 32, b"\x02" * 32)
    m = transition_message(*base)
    assert m.startswith(lp(TAG_TRANSITION))
    for i, alt in enumerate(["B", 4, b"\x03" * 32, b"\x04" * 32]):
        args = list(base)
        args[i] = alt
        assert transition_message(*args) != m


def test_server_rejects_a_non_canonical_bq():
    w = World()
    user = w.users["mali"]
    domain = sorted(user.domain_keys)[0]
    t_q, _ = user.make_query(domain, "insulin AND diabetes", w.anchor)
    leaves = sorted(boolean.leaves(boolean.from_json(t_q["B_Q"])))
    t_q["B_Q"] = ["AND", [["leaf", leaves[1]], ["leaf", leaves[0]]]]      # same meaning, wrong order
    t_q["tau"] = hmac_tag(w.keys[domain].k_a, query_digest(domain, t_q["B_Q"], t_q["epoch"], t_q["t"],
                                                           t_q["nonce"])).hex()
    out = w.server.search(t_q)
    assert out["status"] != "ok" and "canonical" in out["reason"]


def test_index_and_query_share_norm():
    assert norm("Studies") == norm("study") == "study"
    assert norm(norm("Government's  Trials")) == norm("Government's  Trials")
    w = World()
    doc = {"id": "N-01", "title": "t", "body": "b", "policy": "doctor", "keywords": ["Clinical Trials"]}
    w.owners["A"].add_documents([doc])
    user = w.users["mali"]
    t_q, ctx = user.make_query("A", '"clinical trial"', w.anchor)
    resp = w.server.search(t_q)["response"]
    rep = user.verify(ctx, json.loads(json.dumps(resp)))
    assert rep["accepted"] and len(resp["R_ct"]) == 1


def test_u64_rejects_non_integers():
    for bad in (-1, True, 1.0, "1"):
        with pytest.raises(ValueError):
            u64(bad)
