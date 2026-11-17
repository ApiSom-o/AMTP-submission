"""bench_split: the three search-only forms (plain, partition-first, fast with the search index) return exactly the
files of the full response (amtp.server.build_response), for AND / OR / nested queries and absent keywords, with the
query flags off and on; and wrapping run_query changes nothing of amtp/ or bench/."""
import json
import random

import pytest

from amtp.core import boolean
from amtp.core.hashing import H
from amtp.dht import DHT
from amtp.engine import Engine
from amtp.index import (and_plan_greedy_on, and_prune_on, part_results_on, set_and_plan_greedy, set_and_prune,
                        set_part_results)
from amtp.server import build_response
from amtp.variants import AdaptivePolicy
from bench.workload import Doc
from bench_split.search_only import SearchIndex, search_fast, search_only

VOCAB = [f"w{i}" for i in range(14)]


def _leaf(word):
    return ("leaf", H("kw", word).hex())


QUERIES = [
    _leaf("w0"),
    _leaf("never-indexed"),
    ("AND", [_leaf("w0"), _leaf("w1")]),
    ("AND", [_leaf("w0"), _leaf("w1"), _leaf("w2"), _leaf("w3")]),
    ("AND", [_leaf("w12"), _leaf("w13")]),                      # rare words: below the index threshold
    ("AND", [_leaf("w0"), _leaf("w12")]),                       # one indexed, one not
    ("OR", [_leaf("w4"), _leaf("w5")]),
    ("OR", [_leaf("w4"), _leaf("never-indexed")]),
    ("AND", [("OR", [_leaf("w0"), _leaf("w6")]), _leaf("w2")]),
    ("OR", [("AND", [_leaf("w1"), _leaf("w7")]), _leaf("w8")]),
    ("AND", [_leaf("w0"), _leaf("never-indexed")]),
]


@pytest.fixture(params=[False, True], ids=["flags_off", "flags_on"])
def flags(request):
    old = (and_prune_on(), part_results_on(), and_plan_greedy_on())
    set_and_prune(request.param)
    set_part_results(request.param)
    set_and_plan_greedy(request.param)
    yield
    set_and_prune(old[0])
    set_part_results(old[1])
    set_and_plan_greedy(old[2])


def _state(seed):
    rnd = random.Random(seed)
    eng, dht = Engine("A", AdaptivePolicy(4, 2, 8)), DHT()
    for i in range(150):
        words = rnd.sample(VOCAB[:12], rnd.randint(2, 6))
        if i in (0, 75):
            words.append("w12")                                  # in at most 2 partitions: not in the index
        if i in (10, 75):
            words.append("w13")
        d = Doc(f"d{i}", rnd.randrange(4), words)
        dht.put(d.cid, d.ct)
        eng.insert(d.cid, d.keys, d.bucket)
    eng.commit()
    return eng.snapshot(), dht


@pytest.mark.parametrize("seed", [3, 11])
def test_every_form_returns_the_full_responses_files(flags, seed):
    state, dht = _state(seed)
    idx = SearchIndex(state)
    assert 0 < idx.keys < len(list(state.postings.keys()))      # some keywords indexed, rare ones not
    for i, ast in enumerate(QUERIES):
        b_q = boolean.canonical(ast)
        resp = json.loads(json.dumps(build_response(state, b_q, f"{i:032x}", dht)))
        want = {r["cid"] for r in resp["R_ct"]}
        for timing in ({}, None):
            assert search_only(state, b_q, dht, timing=timing) == want
            assert search_only(state, b_q, dht, timing=timing, partition_first=True) == want
            assert search_fast(state, idx, b_q, dht, timing=timing) == want


def test_timing_parts_are_reported():
    state, dht = _state(5)
    idx = SearchIndex(state)
    b_q = boolean.canonical(("AND", [_leaf("w0"), _leaf("w1")]))
    for fn, keys in ((lambda t: search_only(state, b_q, dht, timing=t), {"lookup", "focus", "sets", "eval", "fetch"}),
                     (lambda t: search_fast(state, idx, b_q, dht, timing=t),
                      {"lookup", "focus", "sets", "eval", "fetch"})):
        t = {}
        fn(t)
        assert set(t) == keys and all(v >= 0 for v in t.values())


def test_runner_wraps_run_query_without_changing_bench():
    from bench import experiments as E
    original = E.run_query
    import bench_split.run as R
    assert R._full_query is original                            # the unchanged full query is what it calls
    assert E.run_query is original                              # importing does not patch; only main() does


def test_index_is_dropped_with_its_snapshot():
    """The suites free a snapshot after each size; the runner's index cache must not keep it alive."""
    import gc
    import bench_split.run as R
    state, _ = _state(7)
    R._INDEX.clear()
    R._index_for(state, "A")
    assert R._index_for(state, "A") is R._INDEX[id(state)][1] and len(R._INDEX) == 1    # built once, reused
    del state
    gc.collect()
    assert not R._INDEX
    R._STATS.clear()
