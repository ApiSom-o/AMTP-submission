"""Adversary plug-in: the honest server has no attack hooks, and every attack, applied by the
plug-in around the honest server, is caught by the Phase 5 check it targets."""
import inspect
import json

import pytest

import amtp.server as server_mod
from amtp.adversary import ATTACKS
from amtp.scenario import World

EXPECTED = {
    "tamper_ct": "ct", "drop_result": "comp", "extra_result": "comp", "hide_posting": "papc",
    "false_absent": "idx", "forge_partition": "part", "stale": "anchor", "replay": "ctx",
}


def test_honest_server_has_no_attack_code():
    src = inspect.getsource(server_mod)
    for word in ("ATTACKS", "tamper", "forge", "fake_absent", "hide=", "offline=", "last_response"):
        assert word not in src, word
    assert list(inspect.signature(server_mod.build_response).parameters) == ["state", "b_q", "nonce", "dht",
                                                                            "timing"]


@pytest.mark.parametrize("mode", sorted(set(ATTACKS) - {"honest"}))
def test_every_attack_is_caught(mode):
    w = World()
    user = w.users["mali"]
    query = "insulin OR diabetes"
    t_q, ctx = user.make_query("A", query, w.anchor)
    honest = w.adversary.search(t_q)                     # gives the replay attack something to replay
    assert honest["status"] == "ok"
    t_q, ctx = user.make_query("A", query, w.anchor)
    out = w.adversary.search(t_q, mode)
    assert out["attack"]["applied"], mode
    if mode == "storage_loss":
        assert out["status"] == "storage_error"
        return
    rep = user.verify(ctx, json.loads(json.dumps(out["response"])))
    assert not rep["accepted"] and rep["failed"] == EXPECTED[mode], (mode, rep["failed"])
