"""bench.ablation --variants: a variant run alone sees exactly the workload it sees next to the others.

The cost counters (hash_calls, hash_bytes, keys refreshed, ...) do not depend on the machine, so the rows of
Global-MT(v) run alone must equal its rows in the run with every variant, field by field (timings aside).
"""
import csv
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TIMING = {"update_ms", "commit_ms", "server_ms", "verify_ms"}


def _run(out, *extra):
    cmd = [sys.executable, "-m", "bench.ablation", "--source", "synthetic", "--n", "300", "--theta-max", "16",
           "--theta-min", "4", "--batches", "4", "--batch-size", "10", "--skews", "0.95",
           "--hot-delete-frac", "0.5", "--query-every", "2", "--queries-per-shape", "2", "--out", str(out), *extra]
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)


def _rows(out, name, variant):
    with open(os.path.join(out, f"{name}.csv")) as f:
        return [{k: v for k, v in r.items() if k not in TIMING and not k.endswith("_ms")}
                for r in csv.DictReader(f) if r["variant"] == variant]


def test_variant_alone_sees_the_same_workload(tmp_path):
    full, alone = tmp_path / "full", tmp_path / "alone"
    r = _run(full, "--global-versioned")
    assert r.returncode == 0, r.stderr
    r = _run(alone, "--variants", "Global-MT(v),Global-MT")
    assert r.returncode == 0, r.stderr
    with open(alone / "updates.csv") as f:
        assert {row["variant"] for row in csv.DictReader(f)} == {"Global-MT(v)", "Global-MT"}
    for name in ("updates", "layout", "queries"):
        for variant in ("Global-MT(v)", "Global-MT"):
            a, b = _rows(full, name, variant), _rows(alone, name, variant)
            assert a and a == b, (name, variant)


@pytest.mark.parametrize("bad", ["Global", "AMTP,Nope", " , "])
def test_unknown_variant_is_refused(tmp_path, bad):
    r = _run(tmp_path / "x", "--variants", bad)
    assert r.returncode != 0
    assert "--variants" in r.stderr
