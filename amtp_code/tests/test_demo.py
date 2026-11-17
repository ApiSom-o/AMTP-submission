"""Run with:  python -m pytest -q

These tests are the "correctness gates" from the experiment plan:
  1. honest answers equal a plaintext Boolean search,
  2. every server attack is rejected by the check it targets,
  3. attributes control decryption,
  4. updates move the anchor forward and old snapshots are refused.
"""
import itertools
import json

import pytest

from amtp.core import boolean
from amtp.core.crypto import unpack_ct
from amtp.core.merkle import MerkleTree, multiverify
from amtp.scenario import World


def doc_of(r):
    """Document id from the aad of a returned ciphertext (raw CT bytes, hex on the wire)."""
    return unpack_ct(bytes.fromhex(r["ct"]))["aad"]["doc"]

WORDS = ["insulin", "diabetes", "obesity", "glucose", "trial", "hypertension",
         "nurse", "budget", "cancer", "study"]


def run(world, uid, domain, text, mode="honest"):
    user = world.users[uid]
    t_q, ctx = user.make_query(domain, text, world.anchor)
    out = world.adversary.search(t_q, mode)
    if out["status"] != "ok":
        return out, None, None
    resp = json.loads(json.dumps(out["response"]))
    return out, resp, user.verify(ctx, resp)


@pytest.fixture(scope="module")
def world():
    return World()


def test_merkle_multiproof_roundtrip():
    values = [bytes([i]) * 4 for i in range(11)]
    tree = MerkleTree(values)
    for picks in ([0], [10], [1, 2, 7], list(range(11))):
        proof = tree.multiproof(picks)
        assert multiverify(tree.root, 11, {i: values[i] for i in picks}, proof)
        bad = {i: values[i] for i in picks}
        bad[picks[0]] = b"evil"
        assert not multiverify(tree.root, 11, bad, proof)


def queries():
    for a, b in itertools.combinations(WORDS, 2):
        yield a
        yield f"{a} AND {b}"
        yield f"{a} OR {b}"
    yield "(diabetes AND insulin) OR obesity"
    yield "trial AND (budget OR ethics)"


@pytest.mark.parametrize("domain", ["A", "B"])
def test_honest_results_equal_plaintext(world, domain):
    for q in queries():
        out, resp, rep = run(world, "nina", domain, q)
        assert rep["accepted"], (q, rep["failed"])
        got = {doc_of(r) for r in resp["R_ct"]}
        assert got == world.plaintext_answer(domain, q), q


EXPECTED_FAIL = {
    "tamper_ct": "ct", "drop_result": "comp", "extra_result": "comp",
    "hide_posting": "papc", "false_absent": "idx", "forge_partition": "part",
    "stale": "anchor", "replay": "ctx",
}


@pytest.mark.parametrize("mode,check", EXPECTED_FAIL.items())
def test_attacks_are_rejected(world, mode, check):
    run(world, "mali", "A", "insulin")                  # gives replay something to replay
    out, resp, rep = run(world, "mali", "A", "(diabetes AND insulin) OR obesity", mode)
    assert out["attack"]["applied"]
    assert not rep["accepted"]
    assert rep["failed"] == check


def test_storage_loss_is_an_error_not_a_partial_answer(world):
    out, _, _ = run(world, "mali", "A", "insulin", "storage_loss")
    assert out["status"] == "storage_error"


def test_attributes_control_decryption(world):
    _, resp, rep = run(world, "kit", "B", "trial")
    assert rep["accepted"]
    files = {f["doc"]: f["status"] for f in world.users["kit"].decrypt(resp)}
    assert files["B-03"] == "open" and files["B-04"] == "open"     # auditor OR researcher
    assert files["B-01"] == "locked"                                 # researcher AND lab_b


def test_user_without_query_key_cannot_search(world):
    with pytest.raises(PermissionError):
        world.users["ton"].make_query("B", "insulin", world.anchor)


def test_update_moves_epoch_and_new_file_is_found():
    w = World()
    e_before, _ = w.anchor.latest("A")
    w.publish_next("A")                                  # adds A-08 'Insulin dose correction'
    assert w.anchor.latest("A")[0] == e_before + 1
    _, resp, rep = run(w, "mali", "A", "hypoglycemia")
    assert rep["accepted"]
    assert {doc_of(r) for r in resp["R_ct"]} == {"A-08"}
    _, _, stale = run(w, "mali", "A", "insulin", "stale")
    assert stale["failed"] == "anchor"


def test_split_keeps_threshold_rule():
    w = World()
    for _ in range(3):
        w.publish_next("A")
    owner = w.owners["A"]
    pol = owner.policy
    assert all(n <= pol.theta_max for n in owner.validator.live.values())
    assert 0 < pol.theta_min and 2 * pol.theta_min < pol.theta_max
    assert any(r[0] == "split" for r in owner.structure_log)       # the demo data does split


def test_boolean_canonical_form():
    a = boolean.parse("obesity OR (insulin AND diabetes)")
    b = boolean.parse("(diabetes and insulin) or obesity")
    assert a == b
