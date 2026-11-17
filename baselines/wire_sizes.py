"""One wire-size rule for every scheme (AMTP, Chen et al. [40], Du et al. [7], SE-COLLAB [37]).

Sizes are counted in binary, never as JSON or hex text:
  HASH  = 32 B   every hash value, Merkle node, HMAC / PRF tag and hash-sized identifier (cid)
  INT   = 8 B    every number: count, position, slot, epoch, version, file / partition identifier
  NONCE = 16 B   query nonce
  ciphertexts, group elements and other byte strings: their real length

  proof_bytes     the authentication data the user needs to verify the result, without the files
  response_bytes  everything the server returns: proof_bytes + the result entries (identifier and
                  ciphertext of every returned file) + any per-response header or signature

A scheme that does not model file encryption (Chen et al. returns only encrypted bitmaps) is
charged the standard AES-GCM ciphertext of each returned file, std_ct_bytes(plaintext length),
so every response_bytes includes the files the user receives.
"""
HASH = 32
INT = 8
NONCE = 16
GCM_NONCE, GCM_TAG = 12, 16


def std_ct_bytes(plain_len: int) -> int:
    """AES-GCM ciphertext of a file: nonce + body + tag."""
    return GCM_NONCE + plain_len + GCM_TAG


def result_entry_bytes(ct_len: int, id_bytes: int = INT) -> int:
    """One returned file: its identifier (or position) and its ciphertext."""
    return id_bytes + ct_len


# ---------------------------------------------------------------- AMTP
def amtp_bq_bytes(b_q) -> int:
    """Enc(B_Q): 1 B per node tag, INT child count per AND / OR node, HASH per protected key."""
    if b_q[0] == "leaf":
        return 1 + HASH
    return 1 + INT + sum(amtp_bq_bytes(c) for c in b_q[1])


def amtp_proof_bytes(proof: dict) -> int:
    """Π_Q of an AMTP response (dict as sent): evidence per keyword, partition multiproofs, domain multiproof."""
    n = 0
    for e in proof["evidence"]:
        n += HASH + INT                                      # h, status
        if e["status"] == "present" and e.get("mode") == "focus":       # AND pruning (amtp/server.py)
            n += INT + HASH                                  # n_sel, R^post
            n += INT + sum(INT + INT + INT + len(comp) * (HASH + INT) for _, _, comp in e["segs"])
            n += INT + len(e["nb"]) * (INT + INT + INT + HASH)   # neighbours: position, PID, v, H(Enc(L))
            n += INT + len(e["post_proof"]) * HASH           # R^post multiproof
            n += INT + HASH + INT + len(e["proof"]) * HASH   # pos, next, n, IMT path
        elif e["status"] == "present":
            n += INT + sum(INT + INT + len(comp) * (HASH + INT) for _, comp in e["L"])   # L_h
            n += INT + HASH + INT + len(e["proof"]) * HASH   # pos, next, n, IMT path
        else:
            n += INT + 3 * HASH + INT + len(e["proof"]) * HASH   # lo: pos, h, ρ, next; n; IMT path
    for d in proof["partitions"]:
        n += INT + INT + HASH + INT + INT + len(d["proof"]) * HASH   # PID, v, R_P, n_slots, pos, multiproof
    n += INT + len(proof["domain"]["proof"]) * HASH              # n, domain multiproof
    if "versions" in proof:                                      # result-only partition check: (PID, v) list
        n += INT + len(proof["versions"]) * (INT + INT)
    return n


def amtp_response_bytes(resp: dict) -> int:
    """R_Q: header (i, e, B_Q, η, R^part, R^idx) + Π_Q + every (cid, PID, ℓ, CT_d)."""
    header = INT + INT + amtp_bq_bytes(resp["B_Q"]) + NONCE + 2 * HASH
    files = sum(HASH + INT + INT + len(r["ct"]) // 2 for r in resp["R_ct"])   # CT is hex on the wire
    return header + amtp_proof_bytes(resp["proof"]) + files


def amtp_token_bytes(t_q: dict) -> int:
    """T_Q = <i, B_Q, e*, t, η, τ_Q>."""
    return INT + amtp_bq_bytes(t_q["B_Q"]) + INT + INT + NONCE + HASH
