"""Shared-dataset keywords: AMTP indexes W(d) from documents.csv like every baseline.

  1. Phase 1 Norm is idempotent, so a stored keyword is its own query term
  2. quoted multi-word keywords parse as one leaf
  3. a Data Owner given precomputed keywords indexes exactly those (no re-extraction)
  4. (only if the arXiv dataset is unpacked) the benchmark workload reads documents.csv
"""
import json
import os

import pytest

from amtp.core import boolean
from amtp.core.crypto import unpack_ct
from amtp.nlp import normalise_query_term, phase1_keywords
from amtp.scenario import World


def doc_of(r):
    """Document id from the aad of a returned ciphertext (raw CT bytes, hex on the wire)."""
    return unpack_ct(bytes.fromhex(r["ct"]))["aad"]["doc"]


def run(world, uid, domain, text):
    user = world.users[uid]
    t_q, ctx = user.make_query(domain, text, world.anchor)
    out = world.server.search(t_q)
    resp = json.loads(json.dumps(out["response"]))
    return resp, user.verify(ctx, resp)


def test_norm_is_idempotent_and_drops_possessive():
    assert normalise_query_term("Government's") == "government"
    W = phase1_keywords("McCarthy's function and Takeuchi's triple recursion are textbook examples.")
    assert W and all("'" not in w for w in W)
    assert all(normalise_query_term(w) == w for w in W)


def test_quoted_phrase_is_one_keyword():
    ast = boolean.parse('"Machine  Verification" AND (recursion OR "textbook example")')
    assert boolean.leaves(ast) == {"machine verification", "recursion", "textbook example"}
    assert boolean.parse(boolean.to_text(ast)) == ast


def test_owner_uses_precomputed_keywords():
    w = World()
    doc = {"id": "X-01", "title": "Plain title", "body": "plain body text", "policy": "doctor",
           "keywords": ["machine verification", "textbook example"]}
    w.owners["A"].add_documents([doc])
    resp, rep = run(w, "mali", "A", '"machine verification" AND "textbook example"')
    assert rep["accepted"]
    assert {doc_of(r) for r in resp["R_ct"]} == {"X-01"}
    resp, rep = run(w, "mali", "A", "plain")            # in the text, not in W(d): not indexed
    assert rep["accepted"]
    assert "X-01" not in {doc_of(r) for r in resp["R_ct"]}


def _arxiv_available():
    try:
        from bench.workload import arxiv_loader
        ds = arxiv_loader()
        return os.path.exists(os.path.join(ds.DEFAULT_DATA, "documents.csv"))
    except Exception:
        return False


@pytest.mark.skipif(not _arxiv_available(), reason="arXiv dataset not unpacked (python3 datasets/arxiv/unpack.py)")
def test_arxiv_workload_matches_documents_csv():
    from bench.workload import arxiv_docs, arxiv_loader
    from amtp.core.hashing import H
    ds = arxiv_loader()
    docs = arxiv_docs(400, buckets=16, extra=40)
    ref = ds.sample(400) + ds.insert_pool()[:40]
    assert [d.doc_id for d in docs] == [r.doc_id for r in ref]
    assert all(d.keys == frozenset(H("kw", k) for k in r.keywords) for d, r in zip(docs, ref))
