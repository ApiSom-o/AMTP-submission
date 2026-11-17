"""Adversary plug-in: a malicious Cloud Server for the demo and the tests (never the benchmarks).

The honest server (server.py) has no attack code. This module wraps it: every attack takes the
honest server's real response, or the honest response builder run on a deliberately altered view
of the state or the storage, and changes it in one specific way, so the user can watch the
Phase 5 check that catches it. Nothing about the verdict is faked.
"""
import copy

from .core import boolean
from .core.hashing import H
from .core.merkle import MerkleTree
from .dht import StorageError
from .server import _components, build_response, evaluate_on_state, lookup

ATTACKS = {
    "honest": "Honest server",
    "tamper_ct": "Modify a returned file",
    "drop_result": "Hide one matching file",
    "extra_result": "Add a file that does not match",
    "hide_posting": "Remove an entry from a keyword's posting list",
    "false_absent": "Claim a keyword does not exist",
    "forge_partition": "Forge a partition's content",
    "stale": "Answer from an old epoch (rollback)",
    "replay": "Replay an earlier response",
    "storage_loss": "Ciphertext lost in storage",
}


def flip_one_byte(ct_hex: str, index: int = -1) -> str:
    """Tamper with a returned ciphertext: XOR one byte of the raw CT bytes (hex on the wire)."""
    b = bytearray.fromhex(ct_hex)
    b[index] ^= 0x01
    return b.hex()


class _StateView:
    """A domain snapshot with some lookup structures replaced (everything else is the real state)."""

    def __init__(self, state, cuckoo=None, postings=None):
        self._state = state
        if cuckoo is not None:
            self.cuckoo = cuckoo
        if postings is not None:
            self.postings = postings

    def __getattr__(self, name):
        return getattr(self._state, name)


class _DenyKey:
    """Cuckoo filter that answers "absent" for one key (the server pretends it is not indexed)."""

    def __init__(self, base, h: bytes):
        self.base, self.h = base, h

    def might_contain(self, h):
        return h != self.h and self.base.might_contain(h)


class _HideEntry:
    """Search Tree whose posting state for one key lacks one file."""

    def __init__(self, base, h: bytes, cid: bytes):
        self.base, self.h, self.cid = base, h, cid

    def get(self, key, default=None):
        posting = self.base.get(key, default)
        if key != self.h or posting is None:
            return posting
        posting = [(pid, [e for e in comp if e[0] != self.cid]) for pid, comp in posting]
        return [(pid, comp) for pid, comp in posting if comp]

    def __getitem__(self, key):
        return self.get(key)

    def __contains__(self, key):
        return key in self.base

    def predecessor(self, key):
        return self.base.predecessor(key)


class _OfflineStorage:
    """DHT in which every replica of one ciphertext is down."""

    def __init__(self, dht, cid: bytes):
        self.dht, self.down = dht, set(dht.replica_nodes(cid))

    def get(self, cid, offline=()):
        return self.dht.get(cid, offline=set(offline) | self.down)


def _pick_entry(state, b_q, present):
    """Pick a (keyword, file) whose removal changes the visible result if possible."""
    m_q = {c for c, _, _ in evaluate_on_state(state, b_q)}
    for h in present:
        for _, comp in _components(state, bytes.fromhex(h)):
            for cid, _ in comp:
                if cid in m_q:
                    return h, cid
    h = present[0]
    return h, _components(state, bytes.fromhex(h))[0][1][0][0]


class Adversary:
    """A cheating front for an honest CloudServer: search(t_q, mode)."""

    def __init__(self, server):
        self.server = server
        self.last_response = {}        # domain -> last honest response (for the replay attack)

    def search(self, t_q: dict, mode: str = "honest") -> dict:
        attack = {"mode": mode, "label": ATTACKS.get(mode, mode), "applied": False, "what": ""}

        def respond(state, b_q, nonce):
            return self._respond(mode, attack, state, b_q, t_q)

        out = self.server.search(t_q, respond=respond)
        out["attack"] = attack
        if out["status"] == "ok" and mode == "honest":
            self.last_response[t_q["domain"]] = copy.deepcopy(out["response"])
        return out

    def _respond(self, mode, attack, state, b_q, t_q):
        domain, nonce = t_q["domain"], t_q["nonce"]
        dht = self.server.dht
        present = [h for h in sorted(boolean.leaves(b_q)) if lookup(state, bytes.fromhex(h)) is not None]

        if mode == "stale":
            older = self.server.states[domain].get(state.epoch - 1)
            if older is not None:
                resp = build_response(older, b_q, nonce, dht)
                resp["epoch"] = state.epoch      # pretend it is the current epoch
                attack.update(applied=True, what=f"used snapshot of epoch {older.epoch} "
                                                 f"but labelled it epoch {state.epoch}")
                return resp
        if mode == "replay" and domain in self.last_response:
            attack.update(applied=True, what="returned the previous search's response")
            return copy.deepcopy(self.last_response[domain])
        if mode == "hide_posting" and present:
            h, cid = _pick_entry(state, b_q, present)
            attack.update(applied=True, what=f"removed file {cid[:8]} from one keyword's list")
            view = _StateView(state, postings=_HideEntry(state.postings, bytes.fromhex(h), bytes.fromhex(cid)))
            return build_response(view, b_q, nonce, dht)
        if mode == "false_absent" and present:
            attack.update(applied=True, what="claimed one queried keyword is not indexed")
            view = _StateView(state, cuckoo=_DenyKey(state.cuckoo, bytes.fromhex(present[0])))
            return build_response(view, b_q, nonce, dht)
        if mode == "storage_loss":
            m_q = evaluate_on_state(state, b_q)
            if m_q:
                cid = bytes.fromhex(sorted(m_q)[0][0])
                attack.update(applied=True, what="all replicas of one result file are offline")
                return build_response(state, b_q, nonce, _OfflineStorage(dht, cid))

        resp = build_response(state, b_q, nonce, dht)
        rct = resp["R_ct"]
        if mode == "tamper_ct" and rct:
            rct[0]["ct"] = flip_one_byte(rct[0]["ct"])
            attack.update(applied=True, what=f"changed one byte of file {rct[0]['cid'][:8]}")
        elif mode == "drop_result" and rct:
            gone = rct.pop()
            attack.update(applied=True, what=f"left out file {gone['cid'][:8]}")
        elif mode == "extra_result":
            inside = {r["cid"] for r in rct}
            extra = next((c for c in sorted(state.loc) if c.hex() not in inside), None)
            if extra is not None:
                pid, slot = state.loc[extra]
                rct.append({"cid": extra.hex(), "pid": pid, "loc": slot, "ct": dht.get(extra).hex()})
                attack.update(applied=True, what=f"added non-matching file {extra.hex()[:8]}")
        elif mode == "forge_partition" and resp["proof"]["partitions"]:
            desc = resp["proof"]["partitions"][0]
            fake = list(state.by_pid[desc["pid"]].slots) + [H("forged file")]
            tree = MerkleTree(fake)
            desc.update(R_P=tree.root.hex(), n_slots=len(fake),
                        proof=[x.hex() for x in tree.multiproof(desc["_positions"])])
            attack.update(applied=True, what=f"slipped a forged file into partition {desc['pid']}")
        if mode != "honest" and not attack["applied"]:
            attack["what"] = "not applicable to this query, server answered honestly"
        return resp


__all__ = ["Adversary", "ATTACKS", "flip_one_byte", "StorageError"]
