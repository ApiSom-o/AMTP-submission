"""Root Anchor process: the real amtp.anchor.RootAnchor behind HTTP.

SIMULATED ANCHOR: a Python class in its own process, not a blockchain. It applies the same acceptance
rules as the paper's contract (owner signature, predecessor root, e' = e* + 1) and recomputes R_G.
The client reads (e*, R_D) from here, never from the Cloud Server.
"""
import argparse
import threading

import common  # noqa: F401  (sets the import paths)
from common import EventHub, add_cors, unpack
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, HTTPException, WebSocket

from amtp.anchor import NO_DELTA, RootAnchor


def create_app():
    app = FastAPI(title="AMTP demo: Root Anchor (simulated)")
    add_cors(app)
    anchor, lock, hub = RootAnchor(), threading.Lock(), EventHub()

    def state():
        return {"simulated": True, "block": anchor.block, "R_G": anchor.R_G.hex(),
                "domains": {d: {"epoch": e, "R_D": r.hex()} for d, (e, r) in sorted(anchor.current.items())},
                "history": [{"domain": h.domain, "epoch": h.epoch, "R_D": h.R_D.hex(), "R_G": h.R_G.hex(),
                             "block": h.block, "delta": h.delta.hex()} for h in anchor.history[-30:]]}

    @app.get("/health")
    def health():
        return {"ok": True}

    @app.get("/state")
    def get_state():
        with lock:
            return state()

    @app.get("/latest/{domain}")
    def latest(domain: str):
        with lock:
            if domain not in anchor.current:
                raise HTTPException(404, "unknown domain")
            e, r = anchor.latest(domain)
            return {"epoch": e, "R_D": r.hex()}

    @app.post("/register")
    def register(body: dict):
        b = unpack(body)
        with lock:
            try:
                anchor.register_domain(b["domain"], Ed25519PublicKey.from_public_bytes(b["owner_key"]), b["r0"])
            except ValueError as e:
                raise HTTPException(409, str(e))
            hub.publish("registered", domain=b["domain"], R_D=b["r0"].hex(), R_G=anchor.R_G.hex())
            return state()

    @app.post("/submit")
    def submit(body: dict):
        b = unpack(body)
        with lock:
            try:
                anchor.submit(b["domain"], b["epoch"], b["r_d"], b["sig"],
                              b.get("delta") or NO_DELTA, prev=b.get("prev"))
            except ValueError as e:
                hub.publish("refused", domain=b["domain"], epoch=b["epoch"], reason=str(e))
                raise HTTPException(409, str(e))
            hub.publish("anchored", domain=b["domain"], epoch=b["epoch"], R_D=b["r_d"].hex(),
                        R_G=anchor.R_G.hex(), block=anchor.block)
            return state()

    @app.websocket("/ws")
    async def ws(sock: WebSocket):
        await hub.serve(sock)

    return app


if __name__ == "__main__":
    import uvicorn
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8103)
    a = ap.parse_args()
    uvicorn.run(create_app(), host="127.0.0.1", port=a.port, log_level="warning")
