"""γ with or without the partition version v (study B4, AMTP_GAMMA_V=0 / --gamma-no-v).

  1. the definition: with v (default) γ changes with v; without v it does not, and still binds PID and L
  2. honest update histories (splits, merges, b = 1 / 3 / 10) are validated and anchored, and the
     incremental R_D equals the full rebuild, without v as with it
  3. without v a version bump re-hashes fewer γ (keys_refreshed), never more, for the same history
  4. without v every tampered update proposal is still rejected by the owner's Validator
  5. without v every query attack is still caught by its Phase 5 check, and honest queries return the
     plaintext ground truth
The whole suite also passes with AMTP_GAMMA_V=0 set before pytest starts.
"""
import random

import pytest

import amtp.index as index
from amtp.index import gamma
from tests import test_abort_update as ab
from tests import test_adversary as adv
from tests import test_update_protocol as up

COMP = [(bytes([i]) * 32, i) for i in range(1, 4)]


@pytest.fixture
def no_v(monkeypatch):
    monkeypatch.setattr(index, "_GAMMA_V", False)


@pytest.fixture
def with_v(monkeypatch):
    monkeypatch.setattr(index, "_GAMMA_V", True)


def test_gamma_with_v_changes_with_the_version(with_v):
    assert index.gamma_has_v()
    assert gamma("P1", 4, COMP) != gamma("P1", 5, COMP)


def test_gamma_without_v_ignores_the_version_but_binds_pid_and_postings(no_v):
    assert not index.gamma_has_v()
    assert gamma("P1", 4, COMP) == gamma("P1", 5, COMP)
    assert gamma("P1", 4, COMP) != gamma("P2", 4, COMP)
    assert gamma("P1", 4, COMP) != gamma("P1", 4, COMP[:2])
    assert gamma("P1", 4, COMP) != gamma("P1", 4, [(c, s + 1) for c, s in COMP])


@pytest.mark.parametrize("b", [1, 3, 10])
def test_honest_histories_validate_without_v(no_v, b):
    up.test_honest_transitions_are_validated_and_anchored(b, "least")
    owner, *_ = ab.history(b, b=b, rounds=30)
    ab.assert_finalized(owner)                            # incremental R_D == full rebuild


def test_plain_engine_and_protocol_agree_without_v(no_v):
    up.test_b1_protocol_equals_plain_engine("least")


def _keys_refreshed(monkeypatch, on, seed=7, rounds=40):
    monkeypatch.setattr(index, "_GAMMA_V", on)
    rnd = random.Random(seed)
    owner = up.make_owner(b=3)
    real = owner.server.prepare_update
    seen = []

    def spy(domain, requests):
        prop = real(domain, requests)
        seen.append(prop["stats"]["keys_refreshed"])
        return prop
    owner.server.prepare_update = spy
    live, k = [], [0]
    for _ in range(rounds):
        owner.update(up.random_requests(owner, rnd, 3, live, k))
    assert len(seen) == rounds
    return sum(seen), owner.anchor.latest("A")[0]


def test_without_v_fewer_gammas_are_rehashed(monkeypatch):
    with_v, e1 = _keys_refreshed(monkeypatch, True)
    without_v, e2 = _keys_refreshed(monkeypatch, False)
    assert e1 == e2
    assert without_v < with_v


@pytest.mark.parametrize("seed", range(3))
def test_tampered_proposals_are_rejected_without_v(no_v, seed):
    up.test_targeted_tampers_on_fresh_proposals(seed, "least")
    up.test_random_changes_to_evidence_are_rejected_or_harmless(seed, "least")


@pytest.mark.parametrize("mode", sorted(set(adv.ATTACKS) - {"honest"}))
def test_query_attacks_are_caught_without_v(no_v, mode):
    adv.test_every_attack_is_caught(mode)


@pytest.mark.parametrize("query", ["insulin OR diabetes", "insulin AND glucose", "obesity"])
def test_queries_return_the_ground_truth_without_v(no_v, query):
    ab.test_query_after_abort_uses_the_finalized_snapshot(query)
