"""Validating Data Owner (Phase 2, Step 5): check a CS-proposed transition, then sign σ_root.

The validator keeps trusted domain-wide metadata: Doc_i, Loc_i, Fwd_i, the slots and version of
every partition, the PIDs ever used, the IMT size, accepted request nonces, the finalized epoch
and Domain Root. It never trusts the server's result. For one proposal it

  1. checks every signed request U_op (σ_op, epoch e*, fresh nonce, identifiers, cid = H(CT),
     h_w = H(C_w)) and every placement the server chose,
  2. replays the logical operations and the partition policy on its own partition model, so
     splits, merges, relocations, fresh PIDs and versions follow from its own metadata,
  3. derives the affected keys W_aff and every changed posting component from its metadata,
  4. checks the evidence π^upd against the anchored predecessor root (multiproof openings,
     R^post openings or γ lists, IMT leaves, neighbours, free and appended positions) and replays
     the changes on those dirty paths to get R^part', R^idx' and R_D',
  5. recomputes Aff_i and Δ_i, and signs σ_root only if everything equals the proposal.

The work is proportional to the affected partitions and keys and their Merkle paths (plus the
partition list when a split or merge changes the partition-tree layout, and the γ list of a key
whose partition set changes), not to the whole domain.
"""
import bisect

from .core.crypto import sig_ok
from .core.hashing import H, enc_posting
from .core.merkle import (PAD, grown_root, leaf_hash, merkle_root, root_from_proof, root_of_leaf_hashes,
                          tree_size)
from .index import EMPTY_SLOT, IMT_EMPTY, SENTINEL_LO, ZERO, domain_root, gamma_has_v, gamma_inner, imt_leaf, rho
from .anchor import transition_message
from .update import aff_records, delta, enc_aff, genesis_roots, request_digest


class Invalid(Exception):
    """The proposed transition is not authorized; the reason says which check failed."""


# ---------------------------------------------------------------- IMT next-pointer checks
# touched: key -> (IMT position, ρ, next) of every IMT leaf the evidence opens. Both checks decide exactly
# what the direct scans decide (every leaf against every key), with the same messages, in O((n + m) log n)
# instead of O(n · m): at b = 1000 with v in γ, n ≈ 4·10^5 opened leaves made the scans take minutes.

def check_removed_predecessors(touched, removed):
    """Every removed key must be the next pointer of some opened leaf (its predecessor is in the evidence)."""
    nexts = {nx for _, _, nx in touched.values()}
    for r in removed:
        if r not in nexts:
            raise Invalid("the predecessor of a removed key is missing")


def bracket_new_keys(touched, added):
    """For every new key a: the one opened leaf h with h < a < next(h). Invalid unless there is exactly one.
    Leaves sorted by h; for each prefix keep the largest and the second largest next. The leaves with h < a
    are a prefix; a lies in the range of one of them iff that prefix's largest next is > a, of two or more
    iff its second largest next is > a too, and when it is exactly one, that leaf holds the largest next."""
    items = sorted((h, nx) for h, (_, _, nx) in touched.items())
    hs = [h for h, _ in items]
    top = []                                   # per prefix: (index of the largest next, second largest next)
    best = second = None
    for j, (_, nx) in enumerate(items):
        if best is None or nx > items[best][1]:
            best, second = j, (None if best is None else items[best][1])
        elif second is None or nx > second:
            second = nx
        top.append((best, second))
    bracket = {}
    for a in added:
        i = bisect.bisect_left(hs, a)          # items[:i] are the leaves with h < a
        count, j = 0, None
        if i:
            j, second = top[i - 1]
            count = (items[j][1] > a) + (second is not None and second > a)
        if count != 1:
            raise Invalid("a new key is not bracketed by exactly one predecessor leaf")
        bracket[a] = items[j][0]
    return bracket


class _Model:
    """The validator's working copy of the partition layout for one candidate transition.
    It offers the interface the partition policies use (parts, live, live_entries, split, merge),
    so the validator replays exactly the same adaptation rule as the server."""

    def __init__(self, v):
        self.v, self.domain = v, v.domain
        self.slots, self.vers, self.cnt = {}, {}, {}      # overlays on the trusted state
        self.retired, self.new = set(), set()
        self.loc, self.fwd = {}, {}                      # overlay; None = deleted
        self.counter = v.pid_counter
        self.modified = set()
        self.events = []                                  # (cid, pid) attach / detach events
        self.ops, self.structs, self.start_loc = [], [], {}

    # -- views used by the policies
    @property
    def parts(self):
        return _PartsView(self)

    @property
    def live(self):
        return _LiveView(self)

    def has(self, pid):
        return pid in self.new or (pid in self.v.slots and pid not in self.retired)

    def get_slots(self, pid):
        if pid not in self.slots:
            self.slots[pid] = list(self.v.slots[pid])
        return self.slots[pid]

    def count(self, pid):
        return self.cnt[pid] if pid in self.cnt else self.v.live[pid]

    def loc_of(self, cid):
        return self.loc[cid] if cid in self.loc else self.v.loc.get(cid)

    def fwd_of(self, cid):
        return self.fwd[cid] if cid in self.fwd else self.v.fwd[cid]

    def live_entries(self, pid):
        return [c for c in self.get_slots(pid) if c != EMPTY_SLOT]

    # -- logical operations
    def insert(self, cid, keys, pid, slot):
        if not self.has(pid):
            raise Invalid(f"insert placed in partition {pid} that is not active")
        slots = self.get_slots(pid)
        if slot == len(slots):
            slots.append(cid)
        elif 0 <= slot < len(slots) and slots[slot] == EMPTY_SLOT:
            slots[slot] = cid
        else:
            raise Invalid(f"insert placed at slot {slot} of {pid}, which is neither free nor the next slot")
        self.cnt[pid] = self.count(pid) + 1
        self.fwd[cid] = frozenset(keys)
        self.loc[cid] = (pid, slot)
        self.events.append((cid, pid))
        self._touch(pid)
        self.ops.append(("insert", cid, pid, slot))

    def delete(self, cid):
        pid, slot = self.loc_of(cid)
        self.get_slots(pid)[slot] = EMPTY_SLOT
        self.cnt[pid] = self.count(pid) - 1
        self.events.append((cid, pid))
        self.loc[cid] = None
        self._touch(pid)
        self.ops.append(("delete", cid, pid, slot))

    def _touch(self, pid):
        if pid not in self.new:
            self.modified.add(pid)

    # -- restructuring (same rules as Engine.split / Engine.merge)
    def split(self, pid):
        entries = self.live_entries(pid)
        half = len(entries) // 2
        self._retire(pid)
        left, right = self._new_partition(entries[:half]), self._new_partition(entries[half:])
        self.structs.append(("split", pid, left, right))
        return [left, right]

    def merge(self, a, b):
        first, second = sorted((a, b))
        entries = self.live_entries(first) + self.live_entries(second)
        self._retire(first)
        self._retire(second)
        m = self._new_partition(entries)
        self.structs.append(("merge", a, b, m))
        return m

    def _new_partition(self, cids):
        self.counter += 1
        pid = H("pid", self.domain, self.counter).hex()[:16]
        if pid in self.v.used_pids or pid in self.new:
            raise Invalid(f"partition identifier {pid} was used before")
        self.slots[pid], self.cnt[pid], self.vers[pid] = list(cids), len(cids), 0
        self.new.add(pid)
        for slot, cid in enumerate(cids):
            self.loc[cid] = (pid, slot)
            self.events.append((cid, pid))
        return pid

    def _retire(self, pid):
        for cid in self.live_entries(pid):
            self.start_loc.setdefault(cid, self.loc_of(cid))
            self.events.append((cid, pid))
        self.modified.discard(pid)
        if pid in self.new:
            self.new.discard(pid)
            del self.slots[pid], self.cnt[pid], self.vers[pid]
        else:
            self.retired.add(pid)


class _PartsView:
    def __init__(self, m):
        self.m = m

    def __contains__(self, pid):
        return self.m.has(pid)

    def __iter__(self):
        yield from (p for p in self.m.v.slots if p not in self.m.retired)
        yield from sorted(self.m.new)

    def keys(self):
        return set(self)


class _LiveView:
    def __init__(self, m):
        self.m = m

    def __getitem__(self, pid):
        return self.m.count(pid)


class Validator:
    def __init__(self, domain, signer, policy, genesis_pids, owner_keys):
        """genesis_pids: the initial empty partitions fixed at setup; owner_keys: public keys of the
        Data Owners allowed to sign insert / delete requests (σ_op)."""
        self.domain, self.signer, self.policy = domain, signer, policy
        self.owner_keys = list(owner_keys)
        self.slots = {p: [] for p in genesis_pids}
        self.v = {p: 0 for p in genesis_pids}
        self.live = {p: 0 for p in genesis_pids}
        self.used_pids = set(genesis_pids)
        self.pid_counter = len(genesis_pids)
        self.loc, self.fwd, self.doc = {}, {}, {}
        self.used_nonces = set()
        self.epoch = 0
        self.imt_n = 1
        self.R_part, self.R_idx = genesis_roots(genesis_pids)
        self.R_D = domain_root(domain, 0, self.R_part, self.R_idx)
        self._pending = None

    @classmethod
    def bootstrap(cls, domain, signer, policy, eng, docs, owner_keys):
        """Trusted metadata for an index the owner built itself and anchored (benchmark set-up, where
        the initial N documents are loaded in bulk). `docs` maps document id -> cid."""
        v = cls.__new__(cls)
        v.domain, v.signer, v.policy, v.owner_keys = domain, signer, policy, list(owner_keys)
        v.slots = {p: list(part.slots) for p, part in eng.parts.items()}
        v.v = {p: part.v for p, part in eng.parts.items()}
        v.live = dict(eng.live)
        v.loc, v.fwd, v.doc = dict(eng.loc), dict(eng.fwd), dict(docs)
        v.pid_counter = eng._pid_counter
        v.used_pids = {H("pid", domain, k).hex()[:16] for k in range(1, eng._pid_counter + 1)}
        v.used_nonces = set()
        v.epoch, v.imt_n = eng.epoch, len(eng.imt_layout)
        v.R_part, v.R_idx, v.R_D = eng.part_tree.root, eng.imt.root, eng.R_D
        v._pending = None
        return v

    # ================================================================ main check
    def check(self, proposal: dict, requests) -> bytes:
        """Validate one proposed transition; returns σ_root, or raises Invalid."""
        self._pending = None
        e0, e1 = self.epoch, self.epoch + 1
        if proposal["domain"] != self.domain or proposal["epoch_old"] != e0 or proposal["epoch_new"] != e1:
            raise Invalid("proposal is not for the current finalized epoch of this domain")
        if proposal["R_old"] != self.R_D:
            raise Invalid("proposal does not start from the anchored Domain Root")
        pi = proposal["pi"]
        if domain_root(self.domain, e0, pi["R_part_old"], pi["R_idx_old"]) != self.R_D:
            raise Invalid("predecessor subroots do not rebuild the anchored Domain Root")
        if pi["R_part_old"] != self.R_part or pi["R_idx_old"] != self.R_idx:
            raise Invalid("predecessor subroots differ from the finalized state")
        if not requests or len(requests) != len(proposal["placements"]):
            raise Invalid("every request needs exactly one placement")

        m = _Model(self)
        nonces = self._apply_requests(m, requests, proposal["placements"])
        self._adapt(m)
        changed = {p: (self.v[p], self.v[p] + (1 if self.policy.versioned else 0)) for p in m.modified}
        for p, (_, v1) in changed.items():
            m.vers[p] = v1
        moves = {c: (a, m.loc_of(c)) for c, a in m.start_loc.items()
                 if m.loc_of(c) is not None and m.loc_of(c) != a}
        aff = aff_records(m.ops, m.structs, moves, changed, {p: 0 for p in m.new},
                          {p: self.v[p] for p in m.retired})

        r_part = self._partition_root(m, pi["part"])
        r_idx, imt_n = self._index_root(m, pi)
        r_new = domain_root(self.domain, e1, r_part, r_idx)
        if r_new != proposal["R_new"]:
            raise Invalid("the proposed Domain Root does not follow from the validated update")
        aff_b = enc_aff(aff)
        d = delta(self.domain, e1, requests, aff_b, self.R_D, r_new)
        if d != proposal["delta"]:
            raise Invalid("Δ (or Aff_i) differs from the validated update")
        sig = self.signer.sign(transition_message(self.domain, e1, r_new, self.R_D, d))
        self._pending = (m, nonces, r_part, r_idx, r_new, imt_n)
        return sig

    def advance(self):
        """After the Root Anchor accepted the transition: advance the trusted metadata."""
        m, nonces, r_part, r_idx, r_new, imt_n = self._pending
        for p in m.retired:
            del self.slots[p], self.v[p], self.live[p]
        for p, s in m.slots.items():
            if p not in m.retired:
                self.slots[p] = s
        for p, n in m.cnt.items():
            if p not in m.retired:
                self.live[p] = n
        for p, v in m.vers.items():
            if p not in m.retired:
                self.v[p] = v
        self.used_pids |= m.new
        self.pid_counter = m.counter
        for c, where in m.loc.items():
            if where is None:
                self.loc.pop(c, None)
                self.fwd.pop(c, None)
            else:
                self.loc[c] = where
        for c, keys in m.fwd.items():
            if c in self.loc:
                self.fwd[c] = keys
        for op in m.doc_ops:
            if op[0] == "insert":
                self.doc[op[1]] = op[2]
            else:
                self.doc.pop(op[1], None)
        self.used_nonces |= nonces
        self.epoch += 1
        self.R_part, self.R_idx, self.R_D, self.imt_n = r_part, r_idx, r_new, imt_n
        self._pending = None

    # ================================================================ 1-2: requests and layout
    def _apply_requests(self, m, requests, placements):
        nonces, m.doc_ops, docs = set(), [], {}
        for req, place in zip(requests, placements):
            u, sig = req["U"], req["sig"]
            if not any(sig_ok(k, request_digest(u), sig) for k in self.owner_keys):
                raise Invalid("σ_op is not a valid signature of an authorized Data Owner")
            if u["domain"] != self.domain or u["epoch"] != self.epoch:
                raise Invalid("request is not bound to this domain's finalized epoch")
            if u["nonce"] in self.used_nonces or u["nonce"] in nonces:
                raise Invalid("request nonce was already used")
            nonces.add(u["nonce"])
            live_id = docs[u["id"]] if u["id"] in docs else self.doc.get(u["id"])
            if u["op"] == "insert":
                cid = H(u["ct"])
                if live_id is not None or m.loc_of(cid) is not None:
                    raise Invalid("insert of an identifier or ciphertext that is already live")
                if place is None:
                    raise Invalid("insert without a placement")
                m.insert(cid, {H(c) for c in u["C"]}, place[0], place[1])
                docs[u["id"]] = cid
                m.doc_ops.append(("insert", u["id"], cid))
            elif u["op"] == "delete":
                cid = bytes.fromhex(u["cid"]) if isinstance(u["cid"], str) else u["cid"]
                if live_id != cid or m.loc_of(cid) is None:
                    raise Invalid("delete of a document that is not live with this ciphertext")
                if place is not None:
                    raise Invalid("a delete takes its location from the trusted Loc_i, not from the server")
                m.delete(cid)
                docs[u["id"]] = None
                m.doc_ops.append(("delete", u["id"], cid))
            else:
                raise Invalid("unknown operation")
        return nonces

    def _adapt(self, m):
        touched = sorted((m.modified | m.new) & m.parts.keys())
        self.policy.adapt(m, touched)

    # ================================================================ 4: partition side
    def _A(self, m, pid, new):
        if new:
            slots, v = m.get_slots(pid), m.vers.get(pid, self.v.get(pid))
        else:
            slots, v = self.slots[pid], self.v[pid]
        return H(pid, v, merkle_root(slots))

    def _partition_root(self, m, ev):
        old_order = sorted(self.slots)
        old_pos = {p: i for i, p in enumerate(old_order)}
        structural = bool(m.new or m.retired)
        if ev["mode"] != ("full" if structural else "path"):
            raise Invalid("partition evidence has the wrong form for this transition")
        if not structural:
            known = {old_pos[p]: leaf_hash(self._A(m, p, False)) for p in m.modified}
            if not known:
                return self.R_part
            size = tree_size(len(old_order))
            if root_from_proof(size, known, ev["proof"]) != self.R_part:
                raise Invalid("partition-tree opening does not match R^part")
            return root_from_proof(size, {old_pos[p]: leaf_hash(self._A(m, p, True)) for p in m.modified},
                                   ev["proof"])
        hashes = list(ev["leaf_hashes"])
        if len(hashes) != len(old_order):
            raise Invalid("partition list has the wrong length")
        for p in m.modified | m.retired:
            if hashes[old_pos[p]] != leaf_hash(self._A(m, p, False)):
                raise Invalid(f"partition {p} does not match its trusted contents")
        if root_of_leaf_hashes(hashes) != self.R_part:
            raise Invalid("partition list does not rebuild R^part")
        new_order = sorted([p for p in old_order if p not in m.retired] + list(m.new))
        return root_of_leaf_hashes([leaf_hash(self._A(m, p, True)) if p in m.modified or p in m.new
                                    else hashes[old_pos[p]] for p in new_order])

    # ================================================================ 3-4: index side
    def _components(self, m, pids_events):
        """Old and new posting components L_{h,P} of every dirty pair, from trusted metadata."""
        old_by, new_by = {}, {}
        for p in pids_events:
            if p in self.slots:                                   # existed before
                for slot, c in enumerate(self.slots[p]):
                    if c != EMPTY_SLOT:
                        for h in self.fwd[c]:
                            old_by.setdefault((h, p), []).append((c, slot))
            if m.has(p):                                          # exists after
                for slot, c in enumerate(m.get_slots(p)):
                    if c != EMPTY_SLOT:
                        for h in m.fwd_of(c):
                            new_by.setdefault((h, p), []).append((c, slot))
        return old_by, new_by

    def _index_root(self, m, pi):
        # dirty pairs, exactly as the server's engine marks them
        dirty = set()
        for c, p in m.events:
            for h in (m.fwd[c] if c in m.fwd else self.fwd[c]):
                dirty.add((h, p))
        if self.policy.versioned and gamma_has_v():      # v in γ: a version bump refreshes every γ of p
            for p in m.modified:
                for c in m.live_entries(p):
                    for h in m.fwd_of(c):
                        dirty.add((h, p))
        touched_pids = {p for _, p in dirty}
        old_by, new_by = self._components(m, touched_pids)
        by_key = {}
        for h, p in dirty:
            by_key.setdefault(h, set()).add(p)

        def v_old(p):
            return self.v[p]

        def v_new(p):
            return m.vers.get(p, self.v.get(p))

        def g_old(h, p):
            return gamma_inner(p, v_old(p), H(enc_posting(old_by[(h, p)])))

        def g_new(h, p):
            return gamma_inner(p, v_new(p), H(enc_posting(new_by[(h, p)])))

        keys_ev = pi["keys"]
        rho_old, rho_new, present, added, removed = {}, {}, {}, [], set()
        expected = set()
        for h, pids in by_key.items():
            old_p = sorted(p for p in pids if (h, p) in old_by)
            new_p = sorted(p for p in pids if (h, p) in new_by)
            ev = keys_ev.get(h)
            if ev is None:
                if old_p or new_p:
                    raise Invalid("evidence is missing for an affected key")
                continue
            expected.add(h)
            if ev.get("new"):
                if old_p:
                    raise Invalid("a key with existing postings is claimed to be new")
                added.append(h)
                rho_new[h] = rho(h, len(new_p), merkle_root([g_new(h, p) for p in new_p]))
                continue
            n_sel = ev["n_sel"]
            if set(ev["positions"]) != set(old_p):
                raise Invalid("evidence does not open exactly the affected posting components")
            pos = ev["positions"]
            same_sel = set(old_p) == set(new_p)
            if ev["mode"] != ("path" if same_sel else "list"):
                raise Invalid("posting evidence has the wrong form for this key")
            size = tree_size(n_sel)
            if same_sel:
                r_old = root_from_proof(size, {pos[p]: leaf_hash(g_old(h, p)) for p in old_p}, ev["proof"])
                if r_old is None:
                    raise Invalid("malformed R^post opening")
                r_new = root_from_proof(size, {pos[p]: leaf_hash(g_new(h, p)) for p in new_p}, ev["proof"])
                rho_old[h], rho_new[h] = rho(h, n_sel, r_old), rho(h, n_sel, r_new)
            else:
                gl = list(ev["gammas"])
                if len(gl) != n_sel or any(not (0 <= pos[p] < n_sel) or gl[pos[p]] != g_old(h, p) for p in old_p):
                    raise Invalid("γ list does not hold the trusted old components")
                rho_old[h] = rho(h, n_sel, root_of_leaf_hashes([leaf_hash(g) for g in gl]))
                labels = {pos[p]: p for p in old_p}
                for j, (p, v, inner) in ev["pre"].items():
                    if not (0 <= j < n_sel) or gl[j] != gamma_inner(p, v, inner):
                        raise Invalid("neighbour preimage does not match the γ list")
                    labels[j] = p
                ins = ev["ins"]
                fresh = sorted(set(new_p) - set(old_p))
                if sorted(ins) != fresh:
                    raise Invalid("inserted partitions do not match the validated update")
                for p in fresh:
                    k = ins[p]
                    if not (0 <= k <= n_sel) or (k > 0 and k - 1 not in labels) or (k < n_sel and k not in labels):
                        raise Invalid("missing neighbour of a new posting component")
                    if (k > 0 and not labels[k - 1] < p) or (k < n_sel and not p < labels[k]):
                        raise Invalid("a new posting component is not inserted in PID order")
                new_set = set(new_p)                    # membership tests below: O(1), not a list scan
                gone = {pos[p] for p in old_p if p not in new_set}
                at = {}                                 # insertion point -> new components, in `fresh` order
                for p in fresh:
                    at.setdefault(ins[p], []).append(p)
                out = []
                for j in range(n_sel + 1):
                    out += [leaf_hash(g_new(h, p)) for p in at.get(j, ())]
                    if j < n_sel and j not in gone:
                        p = labels.get(j)
                        out.append(leaf_hash(g_new(h, p)) if p in pids and p in new_set else leaf_hash(gl[j]))
                if out:
                    rho_new[h] = rho(h, len(out), root_of_leaf_hashes(out))
                else:
                    removed.add(h)          # no component left anywhere: the key leaves the IMT
            present[h] = ev
        if set(keys_ev) != expected:
            raise Invalid("evidence covers keys that the update does not affect")
        return self._imt_root(pi, present, added, removed, rho_old, rho_new)

    def _imt_root(self, pi, present, added, removed, rho_old, rho_new):
        n_old = pi["imt_n_old"]
        if n_old != self.imt_n:
            raise Invalid("IMT size differs from the trusted size")
        if not present and not added:
            return self.R_idx, n_old
        touched = {}                                    # key -> (pos, rho_old, next_old)
        for h, ev in present.items():
            touched[h] = (ev["pos"], rho_old[h], ev["next"])
        for h, ev in pi["neighbours"].items():
            if h in touched:
                raise Invalid("a neighbour leaf duplicates an affected key")
            if h == SENTINEL_LO and ev["rho"] != ZERO:
                raise Invalid("malformed sentinel leaf")
            touched[h] = (ev["pos"], ev["rho"], ev["next"])
        size_old = tree_size(n_old)
        free_used = list(pi["free_used"])
        added_set = set(added)                          # membership below: O(1), not a list scan
        appended = sorted(keys["pos_new"] for h, keys in pi["keys"].items() if h in added_set
                          and keys["pos_new"] >= n_old)
        if appended != list(range(n_old, n_old + len(appended))):
            raise Invalid("appended IMT positions are not contiguous")
        old_known = {}
        for h, (p, r, nx) in touched.items():
            if p in old_known:
                raise Invalid("two leaves claim one IMT position")
            old_known[p] = leaf_hash(imt_leaf(h, r, nx))
        for p in free_used:
            if p in old_known or not (0 <= p < n_old):
                raise Invalid("bad free IMT position")
            old_known[p] = leaf_hash(IMT_EMPTY)
        for p in appended:
            if p < size_old:
                old_known[p] = None                      # padding in the old tree
        old_known = {p: (PAD if h is None else h) for p, h in old_known.items()}
        if root_from_proof(size_old, old_known, pi["imt_proof"]) != self.R_idx:
            raise Invalid("IMT opening does not match R^idx")

        # next pointers of the successor state
        check_removed_predecessors(touched, removed)
        bracket = bracket_new_keys(touched, added)
        add_sorted = sorted(added)

        def first_live(y):
            while y in removed:
                y = touched[y][2]
            return y

        def new_next(x, nxt_old):
            b = first_live(nxt_old)
            i = bisect.bisect_right(add_sorted, x)
            return min(b, add_sorted[i]) if i < len(add_sorted) else b

        freed = {touched[r][0] for r in removed}
        new_known = {}
        for h, (p, r, nx) in touched.items():
            if h in removed:
                new_known[p] = leaf_hash(IMT_EMPTY)
            else:
                new_known[p] = leaf_hash(imt_leaf(h, rho_new.get(h, r), new_next(h, nx)))
        allowed = set(free_used) | freed | set(appended)
        used = set()
        for a in added:
            p = pi["keys"][a]["pos_new"]
            if p not in allowed or p in used:
                raise Invalid("a new key was given an IMT position that is not free")
            used.add(p)
            new_known[p] = leaf_hash(imt_leaf(a, rho_new[a], new_next(a, touched[bracket[a]][2])))
        if not set(free_used) <= used:
            raise Invalid("a claimed free IMT position is not used")
        n_new = n_old + len(appended)
        left = root_from_proof(size_old, {p: h for p, h in new_known.items() if p < size_old}, pi["imt_proof"])
        r_idx = grown_root(size_old, left, tree_size(n_new), {p: h for p, h in new_known.items() if p >= size_old})
        return r_idx, n_new


__all__ = ["Validator", "Invalid"]
