# AMTP update cost: the positional IMT and the indexed Merkle tree (adopted)

**Decision:** option A below (indexed Merkle tree) is adopted. The code is changed accordingly; the paper text to
change is in section 6.

**Problem.** Measuring Exp. 3 (dynamic update) on dataset-v3 showed that inserting or deleting **one** document took
5.3 s at N = 200,000, against about 1 ms for Chen [40]. The cause is the IMT of eq. (20): a Merkle tree over the keys in
ascending order with position-bound leaves, so adding or removing one keyword shifts every later leaf and the root
must be recomputed almost entirely. With that design AMTP would lose Exp. 3 by orders of magnitude, contradicting the
paper's claim of localized updates.

## 1. Measurements with the positional IMT

`amtp_code/amtp/engine.py` (incremental: only dirty Merkle paths are recomputed), frozen partitions (no split/merge,
as the paper requires for Exp. 3), θ_max = 256, θ_min = 64.

| N | keywords (K) | insert 1 file with new keywords | insert 1 file with existing keywords only |
|---|---|---|---|
| 10,000 | 78,887 | 297 ms (295k hashes) | 63 ms (46k hashes) |
| 50,000 | 347,502 | 1,320 ms (1.23M hashes) | 53 ms (35k hashes) |
| 200,000 | 1,287,471 | 5,266 ms (4.68M hashes) | — |

- The new-keyword case grows almost linearly with K; at 200k its 4.68M hashes ≈ the whole IMT (2²¹ leaves).
- dataset-v3 keywords are RAKE phrases (κ = 10), mostly unique to one document (1.29M phrases in 200k files), so
  **almost every insert or delete adds or removes an IMT key**. The slow case is the normal case.
- Chen [40] on the same dataset: ~0.23 ms per file at N = 10k and ~1.0 ms at N = 200k.

## 2. Causes

### 2.1 Positional IMT (eq. 20): the main cost
```
R^idx = MerkleRoot(I_lo, I_w1, …, I_wq, I_hi)      I_w = H(h_w ‖ σ_w), leaves in ascending h_w order
```
- Leaves follow the order of h_w and the Merkle commitment binds positions (non-membership uses adjacent leaves, eq. 49).
- A new key at position p shifts every leaf from p onward by one (a removal shifts them back), so every node above
  those leaves changes: O(K) on average, not O(log K).
- This is a property of the structure in the paper, not a code bug.

### 2.2 Partition version bump (eqs. 24, 40): the remaining cost
- A modified partition bumps its version once, and since γ_{w,j} binds v_{i,j}, every keyword in that partition gets
  a new γ, R^post, σ_w and IMT leaf (~1,300–2,000 keys per partition at θ_max = 256).
- The paper states this explicitly ("a partition-version change also refreshes components whose posting contents are
  unchanged"). Its size depends on θ_max; see `docs/THETA_CHOICE.md`.

## 3. Options considered

**A. Indexed Merkle tree (adopted).** Leaves in insertion order; each leaf also stores the next key in value order:
```
I_w = H(h_w ‖ σ_w ‖ next(h_w))      next(h_w) = smallest indexed key above h_w (upper bound h_hi for the largest key)
```
- Add a key: append one leaf (or reuse a freed position) + update the predecessor's leaf → 2 paths, O(log K).
- Remove a key: relink the predecessor + free the position → O(log K).
- Non-membership: one authenticated leaf with h_lo < h < next(h_lo) (instead of two adjacent leaves).
- Same security argument under collision resistance; a known structure (e.g. Aztec's indexed Merkle tree); the
  smallest change to the paper.

**B. Sparse Merkle tree.** Leaf position = h_w (256-level tree). O(256) per update, non-membership = empty leaf.
Longer proofs and a larger change to the paper.

**C. Keep eq. (20).** Report Exp. 3 as is (AMTP ~5,000× slower than Chen at N = 200k) and explain it.

**D. Fewer distinct keywords** (e.g. single words instead of RAKE phrases). Needs a new dataset and new runs of
every scheme, and the cost is still O(K).

## 4. Implementation (option A)

- `index.py`: leaf `imt_leaf(h, ρ, next)`, freed positions hold `IMT_EMPTY`, `DomainState` takes the engine's IMT
  layout (position → key).
- `engine.py`: `_update_imt()` appends (or reuses a freed position) for a new key and updates its predecessor;
  a removed key frees its position and its predecessor is relinked. No full IMT rebuild after the initial build.
- `server.py`: present evidence also carries `next`; absent evidence is the single predecessor leaf.
- `user.py` (b_idx, b_papc): checks h_lo < h < next(h_lo) and rebuilds leaves as H(h ‖ ρ ‖ next).
- Tests: the 30 existing tests pass (the `false_absent` attack is still caught at b_idx) plus 2 new ones in
  `tests/test_imt_indexed.py`: 40 rounds of random inserts/deletes with engine root = full-rebuild root every round,
  and the predecessor of an indexed key has next = that key, so a forged absence claim is rejected.

Insert 1 file + commit, frozen partitions, θ_max = 256:

| N | positional IMT, new keywords | indexed IMT, new keywords | indexed IMT, existing keywords only |
|---|---|---|---|
| 10,000 | 297 ms | 41 ms | 58 ms |
| 50,000 | 1,320 ms | 75 ms | 45 ms |

The cost no longer grows with K; what remains is the version bump of section 2.2.

## 5. Results

Exp. 3 and the θ sweep with the indexed IMT: see `baselines/results/amtp/` and `docs/THETA_CHOICE.md`.

## 6. Paper text to change

**Phase 2, Step 3 (replaces eq. 20 and the following paragraph):**
> The Index Merkle Tree (IMT) is an indexed Merkle tree. Each leaf stores
> I_w = H(h_w ‖ σ_w ‖ next(h_w)), where next(h_w) is the smallest indexed key greater than h_w, and a fixed lower
> sentinel I_lo = H(h_lo ‖ 0 ‖ next(h_lo)) occupies position 0 (next of the largest key is the upper bound h_hi).
> Leaves are placed in insertion order: a new key occupies a free or appended position and its predecessor's
> next pointer is updated; a removed key frees its position and its predecessor is relinked.
> R^idx_{D_i} = MerkleRoot(I_lo, I_{w_1}, …). Non-membership of h is proven by one authenticated leaf
> I_{w'} with h_{w'} < h < next(h_{w'}).

**Phase 4, Step 2 (eq. 49):** `⟨present, L_h, next(h), π^idx_h⟩` and `⟨absent, (h_lo, σ_lo, next(h_lo)), π^nm_h⟩`.

**Phase 5, Step 1 (absent-key paragraph):**
> For an absent key, it verifies π^nm_h for I_lo = H(h_lo ‖ σ_lo ‖ next(h_lo)) against R^idx and requires
> h_lo < h < next(h_lo). Only a valid proof permits assigning M_h = ∅.

**Phase 5, Step 2 (eq. 68 / IMT check):** `Î_h = H(h ‖ σ̂_h ‖ next(h))`.

**Lemma 1 / Theorem 1 (i):** replace "adjacent bracketing leaves" with "an authenticated predecessor leaf whose next
pointer exceeds h". The argument is unchanged: if h is indexed, its true predecessor has next = h, so presenting
another leaf or another next value requires a collision in H.

**Phase 2, Step 4 / Table IV (Update column):** T_IMT = O(log K) per added or removed key (+ the predecessor's leaf).
