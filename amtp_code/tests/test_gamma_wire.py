"""gamma_wire (the user's fast γ) must equal gamma() exactly: same value, same HashCounter calls and bytes,
and the same exception type on malformed input."""
import os
import random

import pytest

from amtp.core.hashing import HashCounter
from amtp.index import gamma, gamma_wire, set_gamma_v


def _run(fn, *args):
    c0, b0 = HashCounter.snapshot()
    try:
        out = fn(*args)
    except Exception as err:                     # compared by type below
        out = type(err)
    c1, b1 = HashCounter.snapshot()
    return out, c1 - c0, b1 - b0


@pytest.mark.parametrize("seed", range(5))
def test_same_value_and_counts(seed):
    rnd = random.Random(seed)
    for _ in range(300):
        pid = os.urandom(8).hex()
        v = rnd.choice([0, 1, 7, rnd.randrange(1 << 40)])
        comp = [(os.urandom(32).hex() if rnd.random() < 0.8 else os.urandom(32), rnd.randrange(1 << 20))
                for _ in range(rnd.randrange(0, 6))]
        assert _run(gamma_wire, pid, v, comp) == _run(gamma, pid, v, comp)


@pytest.mark.parametrize("comp", [
    [("zz" * 32, 1)],                     # not hex
    [("ab" * 31, 1)],                     # 31 bytes
    [("ab" * 32, -1)],                    # negative slot
    [("ab" * 32, True)],                  # bool slot
    [("ab" * 32, 1.0)],                   # float slot
    [("ab" * 32, 1 << 64)],               # slot too large
    [(None, 1)],                          # no cid
    [("ab" * 32,)],                       # malformed entry
])
def test_same_errors(comp):
    assert _run(gamma_wire, "p1", 3, comp)[0] == _run(gamma, "p1", 3, comp)[0]


@pytest.mark.parametrize("v", [-1, True, 1 << 64, "3", None])
def test_odd_versions_fall_back(v):
    comp = [("ab" * 32, 1)]
    assert _run(gamma_wire, "p1", v, comp) == _run(gamma, "p1", v, comp)


def test_gamma_without_v_falls_back():
    comp = [("ab" * 32, 1)]
    set_gamma_v(False)
    try:
        assert _run(gamma_wire, "p1", 3, comp) == _run(gamma, "p1", 3, comp)
    finally:
        set_gamma_v(True)
