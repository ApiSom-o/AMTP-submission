"""Hashing and canonical encoding used everywhere in AMTP.

H(a ‖ b ‖ ...) is SHA-256 over length-prefixed parts, so two different
tuples can never produce the same byte string (no concatenation ambiguity).
Index commitments, query digests and signed messages use the binary encodings
below (domain tag + fixed-width or length-prefixed fields). enc(x), a canonical
JSON encoding, is kept only for plaintext payloads.
"""
import hashlib
import json


def to_bytes(part) -> bytes:
    if isinstance(part, bytes):
        return part
    if isinstance(part, str):
        return part.encode("utf-8")
    if isinstance(part, int) and not isinstance(part, bool):
        return part.to_bytes(8, "big", signed=False)
    raise TypeError(f"cannot hash {type(part)}")


class HashCounter:
    """Counts hash calls and hashed bytes: a machine-independent cost measure
    reported next to wall-clock time in the benchmarks."""
    calls = 0
    bytes = 0

    @classmethod
    def snapshot(cls):
        return cls.calls, cls.bytes


def H(*parts) -> bytes:
    """H(p1 ‖ p2 ‖ ...) = SHA-256(lp(p1, p2, ...)): 4-byte length prefix on every part."""
    h = hashlib.sha256()
    n = 0
    for p in parts:
        b = to_bytes(p)
        h.update(len(b).to_bytes(4, "big"))
        h.update(b)
        n += 4 + len(b)
    HashCounter.calls += 1
    HashCounter.bytes += n
    return h.digest()


# ---------------------------------------------------------------- binary encoding
# Every hashed or signed structure is encoded as bytes with a domain tag and either fixed-width
# fields or 4-byte length prefixes, so two different values never share an encoding and a value
# of one kind never encodes like a value of another kind.

TAG_POSTING = b"AMTP/posting/v1"      # L_{w,j} inside γ
TAG_QUERY = b"AMTP/query/v1"          # message under τ_Q
TAG_TRANSITION = b"AMTP/transition/v1"   # message signed by the owner for a root transition
TAG_BQ = b"AMTP/bq/v1"                # canonical Boolean expression B_Q
TAG_REQUEST = b"AMTP/request/v1"      # signed insert / delete request U_op
TAG_REQUESTS = b"AMTP/requests/v1"    # the batch of requests of one epoch
TAG_AFF = b"AMTP/aff/v1"              # affected-state descriptor Aff_i
TAG_DELTA = b"AMTP/delta/v1"          # AUDC Δ_i
CID_LEN = 32


def lp(*parts) -> bytes:
    """Length-prefixed concatenation: 4-byte big-endian length ‖ bytes, for every part
    (the exact byte string H hashes). str = UTF-8, int = 8-byte unsigned big-endian."""
    out = []
    for p in parts:
        b = to_bytes(p)
        out += [len(b).to_bytes(4, "big"), b]
    return b"".join(out)


def u64(n) -> bytes:
    if type(n) is not int or n < 0:
        raise ValueError(f"expected a non-negative integer, got {n!r}")
    return n.to_bytes(8, "big")


def cid_bytes(cid) -> bytes:
    """A cid as its 32 raw bytes (accepts bytes or the hex string used on the JSON wire)."""
    b = bytes.fromhex(cid) if isinstance(cid, str) else cid
    if not isinstance(b, bytes) or len(b) != CID_LEN:
        raise ValueError("cid must be 32 bytes")
    return b


def enc_posting(component) -> bytes:
    """Enc(L_{w,j}): tag ‖ count (8 B) ‖ for each entry in slot order: cid (32 B) ‖ slot ℓ (8 B)."""
    out = [TAG_POSTING, u64(len(component))]
    for cid, slot in component:
        out += [cid_bytes(cid), u64(slot)]
    return b"".join(out)


def enc_bq(ast) -> bytes:
    """Enc(B_Q): tag, then a prefix-free tree encoding. Leaf: 0x00 ‖ length-prefixed UTF-8 value;
    AND: 0x01, OR: 0x02, each followed by the child count (4 B) and the encoded children.
    Works for any AND/OR tree (query keys as hex, keywords or policy attributes)."""
    return TAG_BQ + _enc_node(ast)


def _enc_node(ast) -> bytes:
    kind = ast[0]
    if kind == "leaf":
        if not isinstance(ast[1], str):
            raise ValueError("leaf value must be a string")
        return b"\x00" + lp(ast[1])
    if kind not in ("AND", "OR") or not isinstance(ast[1], (list, tuple)):
        raise ValueError(f"unknown Boolean node {kind!r}")
    children = ast[1]
    return (b"\x01" if kind == "AND" else b"\x02") + len(children).to_bytes(4, "big") + \
        b"".join(_enc_node(c) for c in children)


def enc(value) -> bytes:
    """Canonical JSON encoding (sorted keys, no whitespace, bytes as hex). Used only for
    plaintext payloads (document body, CP-ABE stand-in blob, aad inside CT), never for an
    index commitment, query digest or signed message."""
    return json.dumps(_plain(value), sort_keys=True, separators=(",", ":")).encode()


def _plain(v):
    if isinstance(v, bytes):
        return v.hex()
    if isinstance(v, (list, tuple)):
        return [_plain(x) for x in v]
    if isinstance(v, dict):
        return {k: _plain(x) for k, x in v.items()}
    return v


def short(b: bytes, n: int = 8) -> str:
    """Short hex for display."""
    return b.hex()[:n]
