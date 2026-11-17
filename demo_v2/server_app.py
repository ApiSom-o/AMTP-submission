"""Cloud Server process: the real amtp.server.CloudServer behind HTTP + a WebSocket of live events.

What this process holds: ciphertexts (DHT), the index (Engine + snapshots), K_a (to check τ_Q, by design)
and the owners' PUBLIC keys. It never receives K_s, a plaintext keyword or a file key.
The attack switch lives here; the client process is never told which attack is active.
"""
import argparse
import threading
import time

import common  # noqa: F401
from common import BUCKETS, EventHub, add_cors, ev_counts, ns_ms, pack, unpack
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, HTTPException, WebSocket

import wire_sizes as W
from amtp.adversary import ATTACKS, Adversary
from amtp.core import boolean
from amtp.core.hashing import HashCounter
from amtp.dht import ciphertext_id
from amtp.index import gamma_has_v
from amtp.server import CloudServer, build_response
from amtp.variants import AdaptivePolicy
from attacks import DEMO_ATTACKS, DemoAttacks

ALL_ATTACKS = {**ATTACKS, **DEMO_ATTACKS}


def bq_shape(b_q):
    """B_Q as the server sees it: operators and 32-byte keys (shown as 8 hex digits)."""
    if b_q[0] == "leaf":
        return b_q[1][:8] + "…"
    return "(" + f" {b_q[0]} ".join(bq_shape(c) for c in b_q[1]) + ")"


def create_app():
    if not gamma_has_v():
        raise SystemExit("this demo runs the paper's γ = H(PID ‖ v ‖ H(Enc(L))); unset AMTP_GAMMA_V=0")
    app = FastAPI(title="AMTP demo: Cloud Server")
    add_cors(app)
    server, lock, hub = CloudServer(), threading.RLock(), EventHub()
    adversary, demo_attacks = Adversary(server), DemoAttacks(server)
    attack = {"mode": "honest"}
    bulk = {}            # domain -> {"docs": {id: cid}, "timing": {...}}

    def engine(domain):
        if domain not in server.engines:
            raise HTTPException(404, "unknown domain")
        return server.engines[domain]

    def domain_stats(domain):
        st, eng = server.current(domain), server.engines[domain]
        sizes = sorted(eng.live.values())
        return {"epoch": st.epoch, "R_D": st.R_D.hex(), "R_part": st.R_part.hex(), "R_idx": st.R_idx.hex(),
                "partitions": len(st.partitions), "files": len(st.loc), "keys": len(st.rho), "imt_leaves": st.imt_n,
                "max_partition": sizes[-1] if sizes else 0, "min_partition": sizes[0] if sizes else 0,
                "bulk": bulk.get(domain, {}).get("timing")}

    # ------------------------------------------------------------------ info
    @app.get("/health")
    def health():
        return {"ok": True}

    @app.get("/stats")
    def stats():
        with lock:
            return {"gamma_has_v": gamma_has_v(), "theta_max": common.THETA_MAX, "theta_min": common.THETA_MIN,
                    "domains": {d: domain_stats(d) for d in sorted(server.states) if d in server.engines},
                    "attack": {"mode": attack["mode"], "label": ALL_ATTACKS[attack["mode"]]},
                    "tampered": demo_attacks.tampered()}

    @app.get("/layout/{domain}")
    def layout(domain: str):
        with lock:
            eng = engine(domain)
            return {"partitions": [{"pid": pid, "live": eng.live[pid], "slots": len(p.slots), "v": p.v,
                                    "buckets": sorted(eng.lineage[pid])} for pid, p in sorted(eng.parts.items())]}

    @app.get("/events")
    def events(since: int = 0):
        return hub.since(since)

    @app.websocket("/ws")
    async def ws(sock: WebSocket):
        await hub.serve(sock)

    # ------------------------------------------------------------------ attack switch (server side only)
    @app.get("/attack")
    def get_attack():
        return {"mode": attack["mode"], "label": ALL_ATTACKS[attack["mode"]], "modes": ALL_ATTACKS,
                "tampered": demo_attacks.tampered()}

    @app.post("/attack")
    def set_attack(body: dict):
        if body.get("mode") not in ALL_ATTACKS:
            raise HTTPException(400, "unknown attack mode")
        with lock:
            attack["mode"] = body["mode"]
        hub.publish("attack_mode", mode=attack["mode"], label=ALL_ATTACKS[attack["mode"]])
        return get_attack()

    @app.post("/attack/restore")
    def restore():
        with lock:
            n = demo_attacks.restore()
        hub.publish("restored", count=n)
        return {"restored": n, "tampered": demo_attacks.tampered()}

    # ------------------------------------------------------------------ Phase 4: search
    @app.post("/search")
    def search(body: dict):
        t_q = body["t_q"]
        with lock:
            mode = attack["mode"]
            info = {"mode": mode, "label": ALL_ATTACKS[mode], "applied": False, "what": ""}
            phase, h0 = {}, HashCounter.calls
            t0 = time.perf_counter_ns()
            if mode == "honest":
                out = server.search(t_q, respond=lambda state, b_q, nonce: build_response(
                    state, b_q, nonce, server.dht, timing=phase))
            elif mode in ATTACKS:
                out = adversary.search(t_q, mode)
                info = out.pop("attack")
            else:
                out = server.search(t_q, respond=lambda state, b_q, nonce: demo_attacks.respond(
                    mode, info, state, b_q, t_q))
            total_ns = time.perf_counter_ns() - t0
            hashes = HashCounter.calls - h0
            if mode == "honest" and out["status"] == "ok":
                adversary.last_response[t_q["domain"]] = out["response"]     # what a replay attack would resend
            timing = {"total_ms": ns_ms(total_ns), "phase_ms": {k: round(v, 3) for k, v in phase.items()}}
            if phase:
                timing["admission_ms"] = round(ns_ms(total_ns) - sum(phase.values()), 3)
            event = {"domain": t_q.get("domain"), "status": out["status"], "reason": out.get("reason"),
                     "token": {"epoch": t_q.get("epoch"), "nonce": str(t_q.get("nonce"))[:12] + "…",
                               "tau": str(t_q.get("tau"))[:16] + "…", "B_Q": bq_shape(t_q["B_Q"]),
                               "keys": len(boolean.leaves(boolean.from_json(t_q["B_Q"]))),
                               "bytes": W.amtp_token_bytes(t_q)},
                     "timing": timing, "hash_calls": hashes, "attack": info}
            if out["status"] == "ok":
                resp, st = out["response"], server.current(t_q["domain"])
                ev = resp["proof"]["evidence"]
                event.update(
                    evidence=[{"h": e["h"][:8] + "…", "status": e["status"], **ev_counts(e)} for e in ev],
                    touched=len(resp["proof"]["partitions"]), partitions=len(st.partitions),
                    domains_touched=1, domains=len(server.engines), files=len(st.loc),
                    results=len(resp["R_ct"]), proof_bytes=W.amtp_proof_bytes(resp["proof"]),
                    response_bytes=W.amtp_response_bytes(resp),
                    tree={"R_D": st.R_D.hex(), "R_part": resp["R_part"], "R_idx": resp["R_idx"],
                          "epoch": resp["epoch"], "imt_leaves": st.imt_n,
                          "domain_proof_hashes": len(resp["proof"]["domain"]["proof"]),
                          "touched_pos": [d["pos"] for d in resp["proof"]["partitions"]],
                          "parts": [{"pid": d["pid"], "pos": d["pos"], "v": d["v"], "n_slots": d["n_slots"],
                                     "R_P": d["R_P"][:12], "proof_hashes": len(d["proof"])}
                                    for d in resp["proof"]["partitions"][:48]]})
        hub.publish("query", **event)
        # The reply carries the response and the server's own timing. No verdict and no attack label.
        return {"status": out["status"], "reason": out.get("reason"), "response": out.get("response"),
                "server": {"total_ns": total_ns, "phase_ms": timing["phase_ms"], "hash_calls": hashes}}

    # ------------------------------------------------------------------ set-up (called by the Data Owner)
    @app.post("/owner/create_domain")
    def create_domain(body: dict):
        b = unpack(body)
        with lock:
            policy = AdaptivePolicy(b.get("buckets", BUCKETS), b["theta_min"], b["theta_max"])
            genesis = server.create_domain(b["domain"], policy,
                                           [Ed25519PublicKey.from_public_bytes(b["owner_key"])], b["ops_per_epoch"])
            bulk[b["domain"]] = {"docs": {}, "timing": {"files": 0, "insert_ms": 0.0}}
        hub.publish("domain_created", domain=b["domain"], partitions=len(genesis))
        return {"genesis": genesis}

    @app.post("/owner/register_query_key")
    def register_query_key(body: dict):
        b = unpack(body)
        with lock:
            server.register_query_key(b["domain"], b["k_a"])
        return {"ok": True}

    @app.post("/owner/bulk_load")
    def bulk_load(body: dict):
        """Start-up only: store the ciphertexts and index them with Engine.insert (the benchmarks' bulk path).
        The server derives cid = H(CT) itself. Nothing is exposed to queries before bulk_finalize."""
        b = unpack(body)
        with lock:
            eng, rec = engine(b["domain"]), bulk[b["domain"]]
            if eng.epoch != 0:
                raise HTTPException(409, "bulk load is only allowed before the first epoch")
            t0 = time.perf_counter_ns()
            for doc_id, ct, keys, bucket in b["docs"]:
                cid = ciphertext_id(ct)
                server.store_ciphertext(cid, ct)
                eng.insert(cid, keys, bucket)
                rec["docs"][doc_id] = cid
            rec["timing"]["insert_ms"] += ns_ms(time.perf_counter_ns() - t0)
            rec["timing"]["files"] = len(rec["docs"])
        return {"files": len(rec["docs"])}

    @app.post("/owner/bulk_commit")
    def bulk_commit(body: dict):
        with lock:
            eng, rec = engine(body["domain"]), bulk[body["domain"]]
            t0 = time.perf_counter_ns()
            st = eng.commit()
            rec["timing"]["commit_ms"] = ns_ms(time.perf_counter_ns() - t0)
            return {"epoch": eng.epoch, "R_D": eng.R_D.hex(), "splits": st["splits"], "layout": eng.layout()}

    @app.post("/owner/bulk_finalize")
    def bulk_finalize(body: dict):
        """After the Root Anchor accepted the owner-signed transition: expose the snapshot."""
        with lock:
            eng, rec = engine(body["domain"]), bulk[body["domain"]]
            t0 = time.perf_counter_ns()
            state = eng.snapshot()
            if state.R_D != eng.R_D:
                raise HTTPException(500, "incremental R_D differs from the full rebuild")
            server.store_state(state)
            server.docs[body["domain"]] = dict(rec["docs"])
            rec["timing"]["snapshot_ms"] = ns_ms(time.perf_counter_ns() - t0)
            rec["timing"]["path"] = "bulk (Engine.insert + one commit), not the per-epoch update protocol"
            rec["docs"] = {}
            out = domain_stats(body["domain"])
        hub.publish("bulk_loaded", domain=body["domain"], **out)
        return out

    # ------------------------------------------------------------------ Phase 2: update protocol (CS side)
    @app.post("/owner/prepare_update")
    def prepare_update(body: dict):
        b = unpack(body)
        with lock:
            t0 = time.perf_counter_ns()
            try:
                proposal = server.prepare_update(b["domain"], b["requests"])
            except ValueError as e:
                hub.publish("update_refused", domain=b["domain"], reason=str(e))
                raise HTTPException(409, str(e))
            ms = ns_ms(time.perf_counter_ns() - t0)
            st = proposal["stats"]
        hub.publish("update_prepared", domain=b["domain"], epoch_new=proposal["epoch_new"],
                    R_old=proposal["R_old"].hex(), R_new=proposal["R_new"].hex(), prepare_ms=ms,
                    ops=[r["U"]["op"] for r in b["requests"]],
                    stats={k: st[k] for k in ("splits", "merges", "partitions_changed", "keys_refreshed",
                                              "posting_components_refreshed", "hash_calls")},
                    structure=[common.show(r) for r in proposal["aff"] if r[0] in ("split", "merge")])
        return pack(proposal)

    @app.post("/owner/abort_update")
    def abort_update(body: dict):
        with lock:
            server.abort_update(body["domain"])
        hub.publish("update_aborted", domain=body["domain"])
        return {"ok": True}

    @app.post("/owner/finalize_update")
    def finalize_update(body: dict):
        with lock:
            t0 = time.perf_counter_ns()
            server.finalize_update(body["domain"])
            out = domain_stats(body["domain"])
            out["finalize_ms"] = ns_ms(time.perf_counter_ns() - t0)
        hub.publish("update_finalized", domain=body["domain"], **out)
        return out

    return app


if __name__ == "__main__":
    import uvicorn
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8101)
    a = ap.parse_args()
    uvicorn.run(create_app(), host="127.0.0.1", port=a.port, log_level="warning")
