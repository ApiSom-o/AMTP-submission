"""Phase 5 fuzz test: random changes to honest responses.

Property (soundness + completeness of Accept_Q): whatever the change, verify() never crashes,
and if it accepts, the returned results are exactly the honest ones (same (cid, PID, ℓ) set and
the same ciphertext bytes). A change that is accepted must therefore be harmless.
"""
import copy
import json
import random

import pytest

from amtp.scenario import World

QUERIES = ["insulin", "insulin AND diabetes", "insulin OR obesity", "(diabetes AND insulin) OR obesity",
           "nosuchword", "nosuchword OR insulin", "trial AND nosuchword"]


def _paths(obj, path=()):
    """Every (path, value) inside a JSON value, containers included."""
    yield path, obj
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _paths(v, path + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _paths(v, path + (i,))


def _get(obj, path):
    for p in path:
        obj = obj[p]
    return obj


def _set(obj, path, value):
    _get(obj, path[:-1])[path[-1]] = value


def _mutate(rnd, resp):
    paths = [p for p, _ in _paths(resp) if p]
    path = rnd.choice(paths)
    val = _get(resp, path)
    parent = _get(resp, path[:-1])
    op = rnd.randrange(6)
    if isinstance(val, str) and op < 3 and val:
        i = rnd.randrange(len(val))
        c = val[i]
        new = "0" if c != "0" else "1"
        _set(resp, path, val[:i] + new + val[i + 1:])
    elif isinstance(val, int) and not isinstance(val, bool) and op < 3:
        _set(resp, path, val + rnd.choice([-1, 1]))
    elif isinstance(parent, list) and op == 3:
        parent.pop(path[-1])
    elif isinstance(parent, list) and op == 4:
        parent.insert(path[-1], copy.deepcopy(val))
    elif isinstance(parent, list) and len(parent) > 1:
        j = rnd.randrange(len(parent))
        parent[path[-1]], parent[j] = parent[j], parent[path[-1]]
    else:
        _set(resp, path, rnd.choice([None, "", 0, [], {}, "present", "absent"]))


STATUSES = ["present", "absent", "hidden", "", None, "PRESENT", 0]


def _cheat(rnd, resp):
    """Coordinated changes a cheating server would make together (one random field at a time
    rarely reaches these): relabel or empty a keyword's evidence, then drop the partition proof
    and results that would contradict it."""
    ev = resp["proof"]["evidence"]
    for e in rnd.sample(ev, rnd.randint(1, len(ev))):
        e["status"] = rnd.choice(STATUSES)
        if rnd.random() < 0.7:
            e["L"] = []
    if rnd.random() < 0.7:
        resp["proof"]["partitions"], resp["proof"]["domain"]["proof"] = [], []
    if rnd.random() < 0.7:
        resp["R_ct"] = []


def _result(resp):
    return sorted((r["cid"], r["pid"], r["loc"], r["ct"]) for r in resp["R_ct"])


@pytest.mark.parametrize("seed", range(4))
def test_random_changes_are_rejected_or_harmless(seed):
    rnd = random.Random(seed)
    w = World()
    user = w.users["mali"]
    domain = sorted(user.domain_keys)[0]
    for text in QUERIES:
        t_q, ctx = user.make_query(domain, text, w.anchor)
        honest = json.loads(json.dumps(w.server.search(t_q)["response"]))
        assert user.verify(ctx, copy.deepcopy(honest))["accepted"], text
        truth = _result(honest)
        for i in range(160):
            resp = copy.deepcopy(honest)
            if i % 4 == 0:
                _cheat(rnd, resp)
            for _ in range(rnd.randint(0 if i % 4 == 0 else 1, 3)):
                _mutate(rnd, resp)
            rep = user.verify(ctx, resp)                     # must not raise
            if rep["accepted"]:
                assert _result(resp) == truth, (text, rep)
