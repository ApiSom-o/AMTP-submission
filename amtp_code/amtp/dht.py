"""Ciphertext storage: a small consistent-hashing DHT run in one process.

Each ciphertext CT_d (raw bytes) is stored under its cid on r replica nodes. A read checks
H(CT) = cid and falls back to the next replica; if no replica is good the Cloud Server must
raise StorageError instead of returning a partial result. Stored values are immutable bytes,
so reads return them without copying.
"""
import bisect

from .core.hashing import H


class StorageError(Exception):
    pass


def ciphertext_id(ct: bytes) -> bytes:
    """cid_d = H(CT_d), over the raw ciphertext bytes."""
    if not isinstance(ct, bytes):
        raise TypeError("CT must be bytes")
    return H(ct)


class DHT:
    def __init__(self, nodes: int = 6, replicas: int = 3):
        self.replicas = replicas
        self.ring = sorted((H("node", k), k) for k in range(nodes))
        self.store = {k: {} for k in range(nodes)}

    def _owners(self, cid: bytes):
        keys = [r[0] for r in self.ring]
        start = bisect.bisect(keys, cid) % len(self.ring)
        return [self.ring[(start + i) % len(self.ring)][1] for i in range(self.replicas)]

    def put(self, cid: bytes, ct: bytes):
        if not isinstance(ct, bytes):
            raise TypeError("CT must be bytes")
        for node in self._owners(cid):
            self.store[node][cid] = ct

    def get(self, cid: bytes, offline=()) -> bytes:
        """`offline` lists nodes that are down (used by the storage-loss scenario)."""
        for node in self._owners(cid):
            if node in offline:
                continue
            ct = self.store[node].get(cid)
            if ct is not None and ciphertext_id(ct) == cid:
                return ct
        raise StorageError(f"no valid replica for ciphertext {cid.hex()[:8]}")

    def has(self, cid: bytes) -> bool:
        return any(cid in self.store[node] for node in self._owners(cid))

    def delete(self, cid: bytes):
        """Remove CT from every replica (after the deleting transition is finalized)."""
        for node in self._owners(cid):
            self.store[node].pop(cid, None)

    def replica_nodes(self, cid: bytes):
        return self._owners(cid)
