"""The Validator's two IMT next-pointer checks were rewritten from direct scans (every opened leaf against every
removed / new key, O(n·m)) to a set lookup and a sorted prefix search (O((n + m) log n)). These tests keep the
old scans as the reference and require the new code to decide exactly the same: the same accept, the same
bracketing leaf, or the same Invalid message — on random inputs, on the edge cases, and end to end on honest
and tampered update proposals.
"""
import copy
import random

import pytest

from amtp import validator as V
from amtp.validator import Invalid, bracket_new_keys, check_removed_predecessors

from test_update_protocol import _fresh_case, _paths, _set, make_owner, random_requests


# ---------------------------------------------------------------- the old code, verbatim
def old_check_removed_predecessors(touched, removed):
    for r in removed:
        if not any(nx == r for _, _, nx in touched.values()):
            raise Invalid("the predecessor of a removed key is missing")


def old_bracket_new_keys(touched, added):
    bracket = {}
    for a in added:
        lo = [h for h, (_, _, nx) in touched.items() if h < a < nx]
        if len(lo) != 1:
            raise Invalid("a new key is not bracketed by exactly one predecessor leaf")
        bracket[a] = lo[0]
    return bracket


def outcome(fn, *args):
    try:
        return ("ok", fn(*args))
    except Invalid as e:
        return ("invalid", str(e))


def both(touched, removed, added):
    """(old, new) outcome of the two checks in the Validator's order."""
    def run(rem, br):
        rem(touched, removed)
        return br(touched, added)
    return (outcome(run, old_check_removed_predecessors, old_bracket_new_keys),
            outcome(run, check_removed_predecessors, bracket_new_keys))


def k(i):
    return i.to_bytes(2, "big")


def leaves(*pairs):
    return {k(h): (pos, b"rho", k(nx)) for pos, (h, nx) in enumerate(pairs)}


# ---------------------------------------------------------------- edge cases
def test_honest_chain():
    t = leaves((0, 10), (10, 20), (20, 30), (30, 99))
    old, new = both(t, {k(20)}, [k(5), k(25), k(31)])
    assert old == new == ("ok", {k(5): k(0), k(25): k(20), k(31): k(30)})


def test_new_key_without_predecessor_in_the_evidence():
    t = leaves((0, 10), (20, 30))                       # the leaf (10, 20) is not sent
    old, new = both(t, set(), [k(15)])
    assert old == new == ("invalid", "a new key is not bracketed by exactly one predecessor leaf")


def test_removed_key_without_predecessor_in_the_evidence():
    t = leaves((20, 30), (30, 40))                      # nothing points to 20
    old, new = both(t, {k(20)}, [])
    assert old == new == ("invalid", "the predecessor of a removed key is missing")


def test_wrong_predecessor():
    t = leaves((0, 10), (20, 30))                       # 25 is in (20, 30), not in (0, 10)
    assert both(t, set(), [k(25)])[1] == ("ok", {k(25): k(20)})
    t = leaves((0, 10), (40, 50))                       # sent leaves bracket neither 25 ...
    old, new = both(t, set(), [k(25)])
    assert old == new and new[0] == "invalid"
    t = leaves((0, 10), (10, 15))                       # ... and nothing points to 20
    old, new = both(t, {k(20)}, [])
    assert old == new == ("invalid", "the predecessor of a removed key is missing")


def test_two_leaves_bracket_one_key():
    t = leaves((0, 50), (10, 40))                       # overlapping ranges: 20 is in both
    old, new = both(t, set(), [k(20)])
    assert old == new == ("invalid", "a new key is not bracketed by exactly one predecessor leaf")
    t = leaves((0, 50), (10, 50))                       # equal largest next
    assert both(t, set(), [k(20)])[0] == both(t, set(), [k(20)])[1]


@pytest.mark.parametrize("a", [10, 20])
def test_range_ends_are_excluded(a):
    t = leaves((10, 20))                                # h < a < next, both ends open
    old, new = both(t, set(), [k(a)])
    assert old == new == ("invalid", "a new key is not bracketed by exactly one predecessor leaf")


def test_backwards_and_empty_ranges():
    t = leaves((30, 10), (40, 40), (0, 35))             # next <= h never brackets anything
    for a in (5, 20, 34, 35, 38, 45):
        old, new = both(t, set(), [k(a)])
        assert old == new, a


def test_removed_check_comes_first():
    t = leaves((0, 10))
    old, new = both(t, {k(77)}, [k(99)])                # both checks fail: the removed one is reported
    assert old == new == ("invalid", "the predecessor of a removed key is missing")


def test_empty_inputs():
    assert both({}, set(), []) == (("ok", {}), ("ok", {}))
    assert both({}, set(), [k(1)])[0] == both({}, set(), [k(1)])[1]
    assert both({}, {k(1)}, [])[0] == both({}, {k(1)}, [])[1]


# ---------------------------------------------------------------- random inputs
@pytest.mark.parametrize("seed", range(40))
def test_random_inputs_decide_the_same(seed):
    rnd = random.Random(seed)
    space = rnd.choice([12, 40, 300])                   # small spaces: many ties and touching ends
    for _ in range(200):
        n = rnd.randint(0, 25)
        hs = rnd.sample(range(space), min(n, space))
        if rnd.random() < 0.5:                          # an honest-looking chain ...
            hs.sort()
            t = {k(h): (i, b"r", k(hs[i + 1] if i + 1 < len(hs) else space + 1)) for i, h in enumerate(hs)}
        else:                                           # ... or arbitrary next pointers
            t = {k(h): (i, b"r", k(rnd.randrange(space + 2))) for i, h in enumerate(hs)}
        nexts = [nx for _, _, nx in t.values()]
        removed = {rnd.choice(nexts) if nexts and rnd.random() < 0.8 else k(rnd.randrange(space))
                   for _ in range(rnd.randint(0, 3))}
        added = list({k(rnd.randrange(space + 2)) for _ in range(rnd.randint(0, 6))})
        old, new = both(t, removed, added)
        assert old == new, (t, removed, added)


# ---------------------------------------------------------------- end to end, through Validator.check
def check_with(monkeypatch, owner, prop, reqs, old):
    if old:
        monkeypatch.setattr(V, "check_removed_predecessors", old_check_removed_predecessors)
        monkeypatch.setattr(V, "bracket_new_keys", old_bracket_new_keys)
    else:
        monkeypatch.setattr(V, "check_removed_predecessors", check_removed_predecessors)
        monkeypatch.setattr(V, "bracket_new_keys", bracket_new_keys)
    try:
        owner.validator.check(copy.deepcopy(prop), copy.deepcopy(reqs))
        return ("ok",)
    except Invalid as e:
        return ("invalid", str(e))
    except (KeyError, ValueError, TypeError, IndexError, AttributeError) as e:
        return (type(e).__name__,)


def _history(monkeypatch, old, b, seed):
    """Run a random honest history through the full protocol; the Domain Root after every epoch."""
    monkeypatch.setattr(V, "check_removed_predecessors",
                        old_check_removed_predecessors if old else check_removed_predecessors)
    monkeypatch.setattr(V, "bracket_new_keys", old_bracket_new_keys if old else bracket_new_keys)
    rnd = random.Random(seed)
    owner = make_owner(b=b)
    live, kk = [], [0]
    epochs = 60 // b + 15
    for _ in range(epochs):                             # owner.update raises if the Validator rejects
        owner.update(random_requests(owner, rnd, b, live, kk))
        assert owner.validator.R_D == owner.server.engines["A"].R_D == owner.anchor.latest("A")[1]
    return owner.anchor.latest("A")[0]


@pytest.mark.parametrize("b,seed", [(1, 1), (5, 2), (20, 3)])
def test_honest_histories_end_to_end(monkeypatch, b, seed):
    """Every honest epoch is validated and anchored by both versions (keys and nonces are random, so the
    two histories have different roots; each must stay in step with the server and the anchor)."""
    assert _history(monkeypatch, True, b, seed) == _history(monkeypatch, False, b, seed) == 60 // b + 15


def _neighbour_tampers(prop):
    """Proposals with an IMT leaf left out, or swapped for another one."""
    pi = prop["pi"]
    for h in list(pi["neighbours"]):
        p = copy.deepcopy(prop)
        p["pi"]["neighbours"].pop(h)
        yield f"drop neighbour {h.hex()[:8]}", p
    nb = list(pi["neighbours"].items())
    for (h1, e1), (h2, e2) in zip(nb, nb[1:]):
        p = copy.deepcopy(prop)
        p["pi"]["neighbours"][h1] = dict(e1, next=e2["next"])
        yield f"wrong next {h1.hex()[:8]}", p


@pytest.mark.parametrize("seed", range(8))
def test_tampered_proposals_end_to_end(monkeypatch, seed):
    owner, prop, reqs = _fresh_case(seed)
    assert check_with(monkeypatch, owner, prop, reqs, old=False) == ("ok",)
    rnd = random.Random(seed)
    cases = list(_neighbour_tampers(prop))
    for _ in range(80):                                 # plus random single changes anywhere in π
        p = copy.deepcopy(prop)
        paths = [q for q, v in _paths(p["pi"], ("pi",)) if isinstance(v, (bytes, int)) and q]
        path = rnd.choice(paths)
        val = p
        for x in path:
            val = val[x]
        try:
            _set(p, path, bytes([val[0] ^ 1]) + val[1:] if isinstance(val, bytes) and val
                 else val + rnd.choice([-1, 1]) if isinstance(val, int) else val)
        except TypeError:
            continue
        cases.append((f"change {path}", p))
    for name, p in cases:
        assert check_with(monkeypatch, owner, p, reqs, old=True) == \
            check_with(monkeypatch, owner, p, reqs, old=False), name
