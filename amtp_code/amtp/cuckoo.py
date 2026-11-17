"""Cuckoo filter over protected search keys h_w (optional lookup accelerator, Phase 2 Step 3).

Partial-key cuckoo hashing with 4-slot buckets and 16-bit fingerprints taken from the bytes of
h_w. "Absent" answers are always right (no false negatives); "maybe present" can be wrong with a
small probability, so the server still looks the key up in the B+ tree. The filter is never
evidence: an absent key is always answered with an IMT non-membership proof.

Each key must be inserted once when it enters the index and deleted once when it leaves it. If an
insertion cannot find room, the owner rebuilds the filter from its complete key set
(CuckooFilter.from_keys), so no stored key is ever lost.
"""
import hashlib
from array import array
from functools import lru_cache

SLOTS = 4
MAX_KICKS = 500
LOAD = 0.85


@lru_cache(maxsize=65536)
def _fp_hash(f: int) -> int:
    return int.from_bytes(hashlib.sha256(f.to_bytes(2, "big")).digest()[:8], "big")


def _pow2(n):
    p = 1
    while p < n:
        p *= 2
    return p


class CuckooFilter:
    def __init__(self, capacity: int = 1024):
        self.n_buckets = _pow2(max(1, -(-int(capacity / LOAD) // SLOTS)))
        self.mask = self.n_buckets - 1
        self.table = array("H", bytes(2 * self.n_buckets * SLOTS))     # 0 = empty slot
        self.count = 0
        self._kick = 0

    @classmethod
    def from_keys(cls, keys, capacity=None):
        keys = list(keys)
        cap = max(capacity or 0, len(keys), 16)
        while True:
            f = cls(cap)
            if all(f.insert(h) for h in keys):
                return f
            cap *= 2

    # ------------------------------------------------------------ hashing
    @staticmethod
    def _fp(h: bytes) -> int:
        f = int.from_bytes(h[:2], "big")
        return f or 1

    def _i1(self, h: bytes) -> int:
        return int.from_bytes(h[2:10], "big") & self.mask

    def _alt(self, i: int, f: int) -> int:
        return (i ^ _fp_hash(f)) & self.mask

    def _bucket(self, i):
        return range(i * SLOTS, i * SLOTS + SLOTS)

    # ------------------------------------------------------------ operations
    def might_contain(self, h: bytes) -> bool:
        f = self._fp(h)
        i1 = self._i1(h)
        t = self.table
        return any(t[s] == f for s in self._bucket(i1)) or any(t[s] == f for s in self._bucket(self._alt(i1, f)))

    __contains__ = might_contain

    def insert(self, h: bytes) -> bool:
        """Add h once. False if the table is too full (then rebuild with from_keys)."""
        if self.count + 1 > LOAD * self.n_buckets * SLOTS:
            return False
        f = self._fp(h)
        i1 = self._i1(h)
        i2 = self._alt(i1, f)
        for i in (i1, i2):
            if self._put(i, f):
                self.count += 1
                return True
        i = i1 if (self._kick & 1) else i2
        undo = []
        for _ in range(MAX_KICKS):
            self._kick += 1
            s = i * SLOTS + self._kick % SLOTS
            undo.append((s, self.table[s]))
            f, self.table[s] = self.table[s], f
            i = self._alt(i, f)
            if self._put(i, f):
                self.count += 1
                return True
        for s, old in reversed(undo):          # undo the kicks: nothing already stored is lost
            self.table[s] = old
        return False

    def delete(self, h: bytes) -> bool:
        """Remove one copy of h's fingerprint (only for a key that was inserted)."""
        f = self._fp(h)
        i1 = self._i1(h)
        for i in (i1, self._alt(i1, f)):
            for s in self._bucket(i):
                if self.table[s] == f:
                    self.table[s] = 0
                    self.count -= 1
                    return True
        return False

    def _put(self, i, f) -> bool:
        for s in self._bucket(i):
            if self.table[s] == 0:
                self.table[s] = f
                return True
        return False
