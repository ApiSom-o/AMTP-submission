"""Network path between the Data User and the Cloud Server, as its own process.

Every search of the client goes through here. With mode "off" the bytes are forwarded unchanged.
With an attack mode the RESPONSE is changed in transit (the server answered honestly or not; this
process does not know and does not care). The client is never told the mode.
"""
import argparse
import json
import os
import threading
import time
import urllib.error
import urllib.request

import common  # noqa: F401
from common import EventHub, add_cors, ns_ms
from fastapi import FastAPI, HTTPException, Request, Response, WebSocket
from starlette.concurrency import run_in_threadpool

from amtp.adversary import flip_one_byte

MODES = {
    "off": "Forward unchanged",
    "flip_ct": "Change one byte of a returned file",
    "drop_result": "Remove one returned file",
    "rewrite_root": "Replace R^idx in the response",
}


def mutate(mode, resp):
    """Change the server's response object in place; returns what was done ('' if not applicable)."""
    if mode == "flip_ct" and resp["R_ct"]:
        resp["R_ct"][0]["ct"] = flip_one_byte(resp["R_ct"][0]["ct"])
        return f"changed one byte of file {resp['R_ct'][0]['cid'][:8]} in transit"
    if mode == "drop_result" and resp["R_ct"]:
        gone = resp["R_ct"].pop()
        return f"removed file {gone['cid'][:8]} from the response in transit"
    if mode == "rewrite_root":
        resp["R_idx"] = os.urandom(32).hex()
        return "replaced R^idx by other bytes in transit"
    return ""


def create_app(server_url):
    app = FastAPI(title="AMTP demo: network path (man in the middle)")
    add_cors(app)
    state, lock, hub = {"mode": "off", "last": None}, threading.Lock(), EventHub()

    @app.get("/health")
    def health():
        return {"ok": True}

    @app.get("/mitm")
    def get_mode():
        return {"mode": state["mode"], "label": MODES[state["mode"]], "modes": MODES, "last": state["last"]}

    @app.post("/mitm")
    def set_mode(body: dict):
        if body.get("mode") not in MODES:
            raise HTTPException(400, "unknown mode")
        with lock:
            state["mode"] = body["mode"]
        hub.publish("mitm_mode", mode=state["mode"], label=MODES[state["mode"]])
        return get_mode()

    @app.get("/events")
    def events(since: int = 0):
        return hub.since(since)

    @app.websocket("/ws")
    async def ws(sock: WebSocket):
        await hub.serve(sock)

    def upstream(body):
        req = urllib.request.Request(server_url + "/search", data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=600) as r:
                return r.read(), r.status
        except urllib.error.HTTPError as e:
            return e.read(), e.code

    @app.post("/search")
    async def forward(request: Request):
        body = await request.body()
        t0 = time.perf_counter_ns()
        raw, status = await run_in_threadpool(upstream, body)
        t1 = time.perf_counter_ns()
        mode, what = state["mode"], ""
        if mode != "off" and status == 200:
            out = json.loads(raw)
            if out.get("status") == "ok":
                what = mutate(mode, out["response"])
                if what:
                    raw = json.dumps(out).encode()
        state["last"] = {"mode": mode, "applied": bool(what), "what": what or (
            "forwarded unchanged" if mode == "off" else "not applicable to this response, forwarded unchanged"),
            "bytes": len(raw), "upstream_ms": ns_ms(t1 - t0), "tamper_ms": ns_ms(time.perf_counter_ns() - t1)}
        hub.publish("forwarded", **state["last"])
        return Response(content=raw, status_code=status, media_type="application/json")

    return app


if __name__ == "__main__":
    import uvicorn
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8104)
    ap.add_argument("--server", default="http://127.0.0.1:8101")
    a = ap.parse_args()
    uvicorn.run(create_app(a.server), host="127.0.0.1", port=a.port, log_level="warning")
