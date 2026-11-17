"""Regression test: a server must not hide results by giving a keyword's evidence a status
other than "present" or "absent" (before the fix, such evidence skipped the PAPC check and
an empty answer was accepted)."""
import json

import pytest

from amtp.scenario import World


@pytest.mark.parametrize("status", ["hidden", "", "PRESENT", None])
def test_unknown_status_is_rejected(status):
    w = World()
    user = w.users["mali"]
    domain = sorted(user.domain_keys)[0]
    t_q, ctx = user.make_query(domain, "insulin AND diabetes", w.anchor)
    resp = json.loads(json.dumps(w.server.search(t_q)["response"]))
    assert user.verify(ctx, json.loads(json.dumps(resp)))["accepted"]
    for e in resp["proof"]["evidence"]:
        e["status"], e["L"] = status, []
    resp["proof"]["partitions"], resp["proof"]["domain"]["proof"], resp["R_ct"] = [], [], []
    rep = user.verify(ctx, resp)
    assert not rep["accepted"]
    assert rep["failed"] == "idx"


def test_present_with_empty_list_is_rejected():
    w = World()
    user = w.users["mali"]
    domain = sorted(user.domain_keys)[0]
    t_q, ctx = user.make_query(domain, "insulin AND diabetes", w.anchor)
    resp = json.loads(json.dumps(w.server.search(t_q)["response"]))
    for e in resp["proof"]["evidence"]:
        e["L"] = []
    resp["proof"]["partitions"], resp["proof"]["domain"]["proof"], resp["R_ct"] = [], [], []
    rep = user.verify(ctx, resp)
    assert not rep["accepted"]
