# AMTP paper: knowledge notes

Summary of the draft paper **"AMTP: Adaptive Multi-Domain Merkle Tree Partitioning for Dynamic Verifiable
Search over Encrypted Cloud Data"** (draft `AMTP-6.pdf`), written so that anyone on the team working in this
repo can check code and experiments against the paper without opening the PDF.
Equation numbers `(n)` refer to the paper.

Authors: Perabha Roiampaeng, Apisara Korcharoenkiat, Vanessa Nattacha Wenk, Wanitcha Saengbundit,
Somchart Fugkeaw (SIIT, Thammasat University).

## 1. Problem and contributions

Verifiable searchable encryption over **several independent domains** whose data grows unevenly.
Three challenges:
1. Fixed partitions become oversized or fragmented → partitions must adapt (split/merge) locally per domain.
2. Membership proofs do not prove **search completeness** → every queried keyword's complete posting
   state (or its absence) must be authenticated, and the DU evaluates the AND/OR query itself.
3. Dynamic updates → proofs from different epochs must not mix, old roots must not be replayed, and a
   server-proposed root must be **validated by an owner** before it is anchored.

Contributions:
- **Adaptive domain authentication**: per-domain occupancy-driven Merkle partitions, Domain Roots anchored
  independently, aggregated into a Global Root.
- **Consistent dynamic index maintenance**: insert/delete/split/merge repair every affected posting and
  version-dependent commitment before a successor is finalized.
- **Verifiable Boolean multi-keyword search**: PAPCs authenticate complete per-keyword postings, so
  AND / OR / nested queries are verified exactly without keyword-combination indexes. ASPA shares Merkle
  paths across covered records and partitions.
- **Validated epoch-bound state evolution**: DO validation + ABS-signed root transition + atomic anchoring.

## 2. Entities and keys

| Entity | Role |
|---|---|
| Domain Authority (DA) | CP-ABE + ABS setup, issues credentials, samples `K^s_i` (keyword protection) and `K^a_i` (query authentication). DOs and DUs get `K^s_i`; DUs and the CS get `K^a_i`. The CS never gets `K^s_i` or decryption keys. |
| Data Owner (DO) | Encrypts documents (AES-GCM, key under CP-ABE), derives protected keywords, signs insert/delete. A validating DO keeps trusted domain-wide metadata and checks every CS-proposed transition before signing the successor root. |
| Cloud Server (CS) | Ciphertexts in a replicated DHT keyed by `cid = H(CT)`; Search Tree (B+ tree), partitioned postings, PAPCs, IMT, partition Merkle trees. Prepares updates and split/merge, answers queries with ASPA proofs. **Malicious.** |
| Data User (DU) | Builds epoch-bound trapdoors, verifies every component posting / absence, evaluates the Boolean query itself, checks the exact result against an independently obtained anchored Domain Root, then decrypts what its attributes allow. |
| Root Anchor (RA) | Blockchain smart contract holding `(R*_Di, e*_i)` per domain; checks root-update authorization, predecessor and `e' = e* + 1` atomically; derives the Global Root `R*_G`. Only roots go on-chain. |

## 3. Threat model, guarantees, leakage

- CS: fully malicious (modify, fabricate, omit, duplicate, wrong partitions, false empty, replay, mix epochs,
  bad updates/repairs, withhold). DHT adds no trust because integrity is `cid = H(CT)` + authenticated postings.
- DUs: may try unauthorized search / replay / decryption. CP-ABE enforces decryption. `K^a_i` HMAC only stops
  outsiders (the CS knows `K^a_i`).
- Trusted: DAs, root-authorizing DOs (with complete metadata), RA contract, ledger finality, the DU's
  independent ledger view. Keyword extraction is assumed correct (completeness is relative to `W(d)`).
- Guarantees: correctness/integrity, completeness, snapshot consistency and freshness, authorized state
  evolution, document confidentiality.
- Leakage (Sec. IV-B): keyword equality (deterministic keys), document–keyword associations, posting/result
  sizes, partitions and positions, Boolean query structure, update patterns, public anchors.
  **Not claimed:** forward/backward privacy, access-pattern or query-structure hiding, availability/DoS.

## 4. Data structures and commitments

| Object | Definition |
|---|---|
| Domain partitions | `P_i = {P_i,1 … P_i,m}`, thresholds `0 < θ_min`, `2θ_min < θ_max` (31) |
| Partition state | `R_P = MerkleRoot(P_i,j)`, `A_i,j = H(PID ‖ v ‖ R_P)` (13). PIDs never reused; version +1 per logical update; new partition starts at v = 0 |
| Protected key | `C_w = DEnc_{K^s}(Norm(w))`, `h_w = H(C_w)` (6) |
| Document maps | `Doc(id)=cid`, `Loc(cid)=(PID, ℓ)`, `Fwd(cid)={h_w}` (12) |
| Postings | `L_w = [(PID, L_w,j)]` over `Sel(h_w)` (14–16), canonical order, no duplicates, no empty components |
| **PAPC** | `γ_w,j = H(PID ‖ v ‖ H(Enc(L_w,j)))` (17), `R^post_w = MerkleRoot([γ_w,j])` (18), `σ_w = H(h_w ‖ |Sel(h_w)| ‖ R^post_w)` (19) |
| **IMT** | indexed Merkle tree: leaves `I_w = H(h_w ‖ σ_w ‖ next(h_w))`, `next(h_w)` = smallest indexed key above `h_w` (`h_hi` for the largest), lower sentinel `I_lo` → `R^idx_Di` (20). Leaf positions are not sorted (a new key is appended or reuses a freed position). Non-membership = **one** leaf `h_lo` with `h_lo < h < next(h_lo)`. The code does this; the paper's eq. 20 text is in `IMT_UPDATE_COST.md` §6 |
| **Domain Root** | `R_Di^(e) = H(i ‖ e ‖ R^part_Di ‖ R^idx_Di)` (1, 26); `R^part = MerkleRoot([A_i,j])` in PID order (25) |
| Global Root | `R_G = MerkleRoot(R_D1 … R_Dn)` — audit only, **not needed** for query verification |
| AUDC | `Δ = H(i ‖ e' ‖ H(U_op) ‖ H(Aff) ‖ R^(e) ‖ R^(e'))` (27) |
| Root signature | `σ^root = ABS.Sign(H(i ‖ e' ‖ R^(e) ‖ R^(e') ‖ Δ))` (29) |
| Ciphertext | `(C_d, τ_d) = AES-GCM(K_d, N_d, d, aad_d)`, `CK_d = CPABE.Enc(K_d, A_d)`, `CT_d = ⟨E_d, CK_d, aad_d⟩`, `cid = H(CT_d)` (2–4) |

Merkle hashing uses distinct leaf / internal-node tags and canonical encodings everywhere.
An optional Cuckoo filter only speeds up lookup and is never verification evidence.

## 5. Phases

**Phase 1 – Initialization and data preparation.** DA setup, RA initialised with `(R^(0), 0)` from the empty
partition root and sentinel-only index (1). DO encrypts (2–4), extracts keywords with **RAKE**
`W(d) = {Norm(w)}` (5), derives `h_w` (6–7), submits `U_d = ⟨i, insert, e*, η, id, CT, C(d)⟩` with ABS
signature (8–9).

**Phase 2 – Indexing and dynamic update.** Insert/delete requests (10–11) against the finalized predecessor.
CS places/removes the document, updates postings (14–16), PAPCs and IMT (17–20), computes the repair set
`W_base` (24), calls Phase 3 if a partition leaves `[θ_min, θ_max]`, computes candidate roots (25–26) and the
descriptor `Aff_i`. Step 5: CS sends AUDC + evidence `π^upd` (28); DO re-derives everything from its trusted
metadata and signs only a valid transition (29); RA checks signature, predecessor, `e' = e* + 1` and updates
(30). One logical operation + any split/merge = **one epoch**.

**Phase 3 – Adaptive partition maintenance (Algorithm 1).** `Adapt(P)` (32): Split if `n > θ_max`;
Merge if `n < θ_min` and a partner exists with `n + n_k ≤ θ_max` (33), partner = argmin `(n, PID)` (34);
otherwise None. Split = two contiguous halves `||S_L| − |S_R|| ≤ 1` (35) into fresh PIDs at v = 0; merge =
concatenate in source-PID order into a fresh PID. Record `Move(cid)` (36), repair every key in
`W_aff = W_base ∪ ⋃ Fwd(cid)` for moved cids (39), recompute PAPCs (40–42), record `Struct_i` (45).
Split/merge never changes any `M_h`, so Boolean results are unchanged. Cost: `O(θ_max)` relocated ids,
`O(θ_max · k̄_mov)` postings.

**Phase 4 – Boolean search and ASPA (Algorithm 2).** Trapdoor `τ_Q = HMAC_{K^a}(H(i ‖ Enc(B_Q) ‖ e* ‖ t ‖ η))`,
`T_Q = ⟨i, B_Q, e*, t, η, τ_Q⟩` (46–48). CS admits, pins the snapshot, builds evidence per leaf key:
`present` (complete `L_h` + IMT proof) or `absent` (non-membership) (49). `M_Q = Eval(B_Q, {M_h})` (51),
AND = ∩, OR = ∪ (22). ASPA proves **coverage** `M_cov = ⋃ M_h`, `S_cov` (52) with one multiproof per covered
partition (53–55) + one domain multiproof (56–57); ciphertexts are fetched only for `M_Q` (58); a missing or
hash-inconsistent ciphertext → `StorageError`. Response `R_Q` (59–60). Cost parameters (61):
`p_Q = Σ|M_h|`, `r_Q = |M_Q|`, `s_Q = |S_cov|`, `b_Q = |B_Q|`.

**Phase 5 – Verification and decryption (Algorithm 3).**
`Accept_Q = b_ctx ∧ b_anchor ∧ b_idx ∧ b_papc ∧ b_part ∧ b_comp ∧ b_ct` (76):

| Check | Meaning | Eq. |
|---|---|---|
| `b_ctx` | domain, epoch, `B_Q`, nonce equal the retained context | (62) |
| `b_anchor` | `H(i ‖ e_Q ‖ R^part ‖ R^idx) = R^(e_Q)_Di` from the ledger | (63) |
| `b_idx` | exactly one evidence entry per leaf key; absence via adjacent-key non-membership | |
| `b_papc` | rebuild `γ̂, R̂^post, σ̂` from the complete posting, verify `Î_h` in IMT | (66–68) |
| `b_part` | partition multiproofs for all covered positions + domain multiproof | (69–72) |
| `b_comp` | DU's own `M̂_Q = Eval(B_Q, {M_h})`; `Proj(R^ct) = M̂_Q`, same size, no duplicates | (73–74) |
| `b_ct` | `H(CT_d) = cid` for each returned ciphertext | (75) |

Then CP-ABE recovers `K_d` and AES-GCM decrypts (77–79). Access denial or decryption error is **not** an
empty search result. An empty result is valid only if the authenticated component states evaluate to ∅.

## 6. Security results (Sec. IV)

- Lemma 1: a Domain Root binds domain, epoch, partition states and the full posting index (collision resistance).
- Theorem 1: exact authenticated Boolean results, `Pr[Bad_Q] ≤ Adv^CR_H` (soundness + completeness,
  includes false-empty resistance (95)).
- Theorem 2: snapshot freshness and domain binding, `Pr[Bad_snap] ≤ Adv^CR_H`.
- Theorem 3: root-transition authorization, `≤ Adv^UF_ABS + Adv^CR_H`; plus atomic ordering (108).
- Proposition 1: indexing invariants (109–111) preserved by validated transitions.
- Confidentiality (117–121): CP-ABE IND-CPA + AEAD; keyword protection leaks equality (122–124);
  query admission HMAC bound (126) only against outsiders.

## 7. Evaluation plan (Sec. V)

**Baselines** (each compared only on what it supports):

| Scheme | Query gen. | Search / proof | Verification | Update | Repo |
|---|---|---|---|---|---|
| Du et al. [7] | `r T_H` | `O(n_c r v_Q) T_H` | `O(n_c |R|)(T_H + T_HMAC)` | N/A | `baselines/du_et_al_sim.py` |
| SE-COLLAB [37] | `3T_E + T_P` | `j T_B` | `T_E + T_P + t_leaf T_H` | N/A | `baselines/se_collab_sim.py` |
| Chen et al. [40] | `O(n_w) T_PRF` | `O(n_w n_u)(T_H + T_A + T_X)` | `O(r_C)(T_PRF + T_X)` | `O(N_u m)(T_PRF + T_H + T_Enc)` | `baselines/chen_et_al_sim.py` |
| AMTP | `k_Q(T_DEnc + T_H) + T_HMAC` | `k_Q T_lookup + T_Eval + Σ T_MP(q_j, n_j) + T_MP(s_Q, m_i)` | `C_idx + Σ T_MV(q_j, n_j) + T_MV(s_Q, m_i) + T_Eval + r_Q T_H` | `T_part + u T_post + T_IMT + T_ABS` | `amtp_code/` |

**Experiments:**

| # | What | Variables in the paper | Compared with |
|---|---|---|---|
| 1 | Boolean search scalability | `N ∈ {10⁴, 5·10⁴, 10⁵, 5·10⁵, 10⁶}`, `k_Q ∈ {1,2,4,8,16}`, shapes A∧B∧C∧D, A∨B∨C∨D, (A∨B)∧(C∨D), (A∧B)∨(C∧D) | SE-COLLAB (all shapes), Du / Chen (AND only) |
| 2 | Selective proof and verification | `N = 10⁶`, vary `p_Q, r_Q, s_Q`, clustered vs dispersed | baselines as reference |
| 3 | Dynamic update scalability | `N` 10⁴–10⁶, batches 1/10/100/1000 insert+delete, no split/merge | Chen |
| 4 | Adaptive partitioning under skewed growth | increasingly skewed updates | internal Global-MT and Static-MT |
| 5 | Multi-domain scalability and isolation | `D ∈ {1,2,4,8,16,32}`, update one domain | Du (multi-cloud) where applicable |

Defaults in the text: 4 keywords per query; reported values averaged over runs after warm-up
(baselines in this repo use 30 reps + 3 warm-up).

## 8. Paper vs. repo: open items

These are places where the draft and the current code/data disagree or the draft is unfinished:

1. **Dataset text is outdated.** Sec. V-B (draft AMTP (15)) describes arXiv version 308 with domains cs, math,
   physics, stat, 50,000 initial + 5,000 insert-pool documents per domain, RAKE κ = 10 and
   `N ∈ {10⁴, 5·10⁴, 10⁵, 2·10⁵}`. The repo now uses dataset-v4: domains cs, math, astro-hep,
   condmat-quant, 125,000 initial + 12,500 insert-pool documents per domain (500,000 + 50,000), RAKE κ = 20
   (`datasets/README.md`). The domains, sizes, κ ("at most ten keywords per document") and the N values of
   every experiment must follow the advisor's plan on dataset-v4.
2. **Setup text describes the test machine.** Draft AMTP (15) fills in the setup (Python 3.12, MacBook Pro M3,
   cryptography v50.0.2, θ_max = 64, θ_min = 16, 30 runs + 3 warm-up). It must be rewritten for the cloud
   machine and the Python and library versions the final results are measured with.
3. Figure references in Sec. III-A and III-C are fixed in draft AMTP (15) (Fig. 1, Fig. 2).
4. Theorem 1 statement (86) repeats the definition of `Bad_Q` instead of stating the bound
   `Pr[Bad_Q] ≤ Adv^CR_H(B, λ)` (the bound appears only at the end of the proof, (94)).
5. The demo in `amtp_code/` uses `θ_min = 1, θ_max = 4` to show splits on little data (so a merge only
   happens when a partition empties). It runs the full Phase 2 protocol (signed requests, Validator, Δ);
   CP-ABE and ABS are stand-ins there (see `amtp_code/README_TH.md`).
6. **Exp. 3 update latency.** The draft says "DO transition validation is not included in the update
   latency". The code reports `update_ms = server_ms + validate_ms + anchor_ms` and each part separately
   (`amtp_exp3_dynamic_update.csv`). Decide which column the figure uses and make the text say the same.
7. **Rejected candidates.** A candidate rejected by the owner's Validator or the Root Anchor is discarded
   (`CloudServer.abort_update`, undo log in `Engine`) and the Cloud Server returns to the finalized
   predecessor, as Phase 2, Step 5 requires ("obsolete proposals must be regenerated against the current
   predecessor"). The CS keeps an undo log of the working successor; writing it is part of every update,
   so its cost is included in the reported update latency (`server_ms`, about 5% at N = 10k). Discarding
   a candidate is not part of the measured updates (they are never rejected). Suggested paper sentence:
   "The CS records an undo log while preparing a candidate, so a rejected candidate is discarded and the
   CS returns to the finalized predecessor; the cost of this log is included in the update latency."
   Tests: `amtp_code/tests/test_abort_update.py` (Validator and anchor rejections, roots unchanged by
   the log, queries after an abort).