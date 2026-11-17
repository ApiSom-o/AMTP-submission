"""Demo-only attacks that amtp/adversary.py does not have. Every one is a real mutation: of the data the
server stores, or of the response it builds with the real build_response. No verdict is produced here;
only the Data User's verifier (in another process) decides.

  wrong_partition      one partition descriptor is replaced by another partition's real root and proof
  wrong_domain         the answer is built from another domain's index and relabelled
  tamper_store_ct      a stored ciphertext is overwritten in every DHT replica, then served
  tamper_store_index   a posting entry of the stored index snapshot is overwritten
"""
import common  # noqa: F401

from amtp.adversary import flip_one_byte
from amtp.core import boolean
from amtp.server import build_response, evaluate_on_state, lookup

DEMO_ATTACKS = {
    "wrong_partition": "Answer with another partition's root and proof",
    "wrong_domain": "Answer from another domain's index",
    "tamper_store_ct": "Tamper a stored ciphertext in every replica, then serve it",
    "tamper_store_index": "Tamper a posting entry in the stored index",
}


class RawStorage:
    """A cheating server's read path: returns whatever is stored, skipping the DHT's own H(CT) = cid check."""

    def __init__(self, dht):
        self.dht = dht

    def get(self, cid, offline=()):
        for node in self.dht.replica_nodes(cid):
            ct = self.dht.store[node].get(cid)
            if ct is not None:
                return ct
        return self.dht.get(cid)          # raises StorageError


class DemoAttacks:
    def __init__(self, server):
        self.server = server
        self.ct_backup = {}       # cid -> {node: original bytes}
        self.index_backup = []    # (posting list object, index, original entry, description)

    # ---------------------------------------------------------------- stored-data tampering
    def tampered(self):
        return {"ciphertexts": [c.hex()[:16] for c in self.ct_backup],
                "index_entries": [d for *_, d in self.index_backup]}

    def restore(self):
        n = len(self.ct_backup) + len(self.index_backup)
        dht = self.server.dht
        for cid, nodes in self.ct_backup.items():
            for node, ct in nodes.items():
                dht.store[node][cid] = ct
        for posting, i, original, _ in reversed(self.index_backup):
            posting[i] = original
        self.ct_backup, self.index_backup = {}, []
        return n

    def _tamper_ct(self, cid: bytes):
        dht = self.server.dht
        nodes = {n: dht.store[n][cid] for n in dht.replica_nodes(cid) if cid in dht.store[n]}
        self.ct_backup.setdefault(cid, nodes)
        for n, ct in nodes.items():
            dht.store[n][cid] = bytes.fromhex(flip_one_byte(ct.hex()))
        return len(nodes)

    def _tamper_index(self, state, hb: bytes):
        posting = state.postings.get(hb)            # the stored list: [(PID, [(cid, slot), ...]), ...]
        pid, comp = posting[0]
        if len(comp) > 1:
            new, what = list(comp[:-1]), f"deleted file {comp[-1][0].hex()[:8]} from a stored posting list"
        else:
            other = next(c for c in sorted(state.loc) if c != comp[0][0])
            new = [(other, comp[0][1])]
            what = f"replaced file {comp[0][0].hex()[:8]} by {other.hex()[:8]} in a stored posting list"
        desc = f"domain {state.domain} epoch {state.epoch}, keyword {hb.hex()[:8]}, partition {pid}: {what}"
        self.index_backup.append((posting, 0, (pid, comp), desc))
        posting[0] = (pid, new)
        return what

    # ---------------------------------------------------------------- response builders
    def respond(self, mode, attack, state, b_q, t_q):
        domain, nonce, dht = t_q["domain"], t_q["nonce"], self.server.dht
        if mode == "wrong_domain":
            others = [d for d in sorted(self.server.states) if d != domain]
            if others:
                other = self.server.current(others[0])
                resp = build_response(other, b_q, nonce, dht)
                resp["domain"], resp["epoch"] = domain, state.epoch          # relabel as the queried domain
                attack.update(applied=True, what=f"built the answer from domain {other.domain}'s index "
                                                 f"and labelled it {domain}")
                return resp
        if mode == "tamper_store_ct":
            m_q = sorted(evaluate_on_state(state, b_q))
            if m_q:
                cid = bytes.fromhex(m_q[0][0])
                if cid not in self.ct_backup:
                    n = self._tamper_ct(cid)
                    attack.update(applied=True, what=f"overwrote stored file {cid.hex()[:8]} in {n} replica(s), "
                                                     "then served it without the storage check")
                else:
                    attack.update(applied=True, what=f"served already-tampered stored file {cid.hex()[:8]}")
            elif self.ct_backup:
                attack.update(applied=True, what="stored data is tampered, but this query returns no file")
            return build_response(state, b_q, nonce, RawStorage(dht))
        if mode == "tamper_store_index":
            present = [h for h in sorted(boolean.leaves(b_q)) if lookup(state, bytes.fromhex(h)) is not None]
            if present:
                hb = bytes.fromhex(present[0])
                done = [d for *_, d in self.index_backup if f"keyword {hb.hex()[:8]}" in d
                        and f"epoch {state.epoch}," in d and f"domain {state.domain} " in d]
                what = "answered from the already-tampered stored index" if done else self._tamper_index(state, hb)
                attack.update(applied=True, what=what)
            return build_response(state, b_q, nonce, dht)

        resp = build_response(state, b_q, nonce, dht)
        if mode == "wrong_partition" and resp["proof"]["partitions"]:
            desc = resp["proof"]["partitions"][0]
            positions = desc["_positions"]
            covered = {d["pid"] for d in resp["proof"]["partitions"]}
            fits = [p for p in state.partitions if p.pid != desc["pid"] and len(p.slots) > max(positions)]
            other = next((p for p in fits if p.pid not in covered), fits[0] if fits else None)
            if other is not None:
                tree = state.part_trees[other.pid]
                desc.update(v=other.v, R_P=tree.root.hex(), n_slots=len(other.slots),
                            pos=state.part_pos[other.pid],
                            proof=[x.hex() for x in tree.multiproof(positions)])
                attack.update(applied=True, what=f"answered partition {desc['pid']} with the root and proof "
                                                 f"of partition {other.pid}")
        if not attack["applied"]:
            attack["what"] = "not applicable to this query, server answered honestly"
        return resp
