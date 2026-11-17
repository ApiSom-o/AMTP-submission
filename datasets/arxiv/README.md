# AMTP Dataset: arXiv, 4 domains × 125,000 files (dataset-v4, primary dataset)

Plaintext dataset shared by **AMTP and every baseline** in the Section V experiments.

| Domain | arXiv archives (primary category) | Initial files | Insert-pool files |
|---|---|---|---|
| D1 | cs (cs, cmp-lg) | 125,000 | 12,500 |
| D2 | math (math, alg-geom, dg-ga, funct-an, q-alg) | 125,000 | 12,500 |
| D3 | astro-hep (astro-ph, gr-qc, hep-*, nucl-*) | 125,000 | 12,500 |
| D4 | condmat-quant (cond-mat, quant-ph, physics, math-ph, nlin, …) | 125,000 | 12,500 |

500,000 initial files + 50,000 insert-pool files. Each file = title + abstract of one real arXiv paper
(Kaggle `Cornell-University/arxiv`, seed 42, abstract ≥ 30 words, no replicas). doc_id order is
chronological, so the first n doc_ids of a domain ARE the database of size n (nested prefixes).
Source snapshot and MD5: `data_v4/download_info.txt`.

**Keywords W(d) (v4):** extracted once with AMTP's Phase 1 code (`amtp_code/amtp/nlp.py`):
RAKE, top-20 per file (**κ = 20**), Θ_doc = 30,000, L_ch = 400, L_ov = 80, tokenise + lowercase +
possessive 's removed + stop-words + light lemmatisation, **vocabulary not limited**. Norm is idempotent,
so every keyword in `documents.csv` can be used directly as a query (multi-word keywords in double quotes).

**Numbers (from `summary.json`, initial files, 125,000 per domain)**

| Domain | Distinct keywords | in ≥ 2 files | Keyword–file pairs | Keywords / file (mean) | Max doc freq |
|---|---|---|---|---|---|
| D1 cs | 1,393,164 | 199,160 | 2,490,822 | 19.93 | 7,944 |
| D2 math | 785,551 | 163,282 | 2,335,873 | 18.69 | 11,075 |
| D3 astro-hep | 987,381 | 197,318 | 2,445,291 | 19.56 | 4,134 |
| D4 condmat-quant | 1,157,189 | 194,678 | 2,458,815 | 19.67 | 2,972 |

4,253,734 distinct keywords over all domains (including the insert pool); 2 of the 550,000 files have no
keyword (D2_014323, D3_021820: French titles / long runs of non-stop-words, so RAKE's 1–3-word
limit leaves no candidate phrase; kept as-is, they are never a query result). Extraction cost: 0.27 ms per file (CPU time, one core).

**How the schemes use it**
- Every scheme (AMTP, Chen [40], Du [7], SE-COLLAB [37]) reads documents and W(d) from `documents.csv`
  through the same loader `baselines/amtp_dataset.py`; nobody re-extracts keywords, so all schemes index
  identical keyword sets. Extraction time is not part of any search/update measurement; AMTP's
  extraction cost is reported separately with `cd amtp_code && python -m bench.extraction`.

## Get the dataset (do NOT rebuild it yourself)

The whole dataset is committed in small parts under `datasets/arxiv/data_v4/`
(`D?_<domain>.NNN.jsonl.gz`, 25,000 documents each, every part well under 100 MB). After `git pull`,
run once from the repo root:

```bash
python3 datasets/arxiv/unpack.py      # a few minutes, standard library only -> data/amtp_file_db_v4/
python3 baselines/amtp_dataset.py     # check: D1..D4 initial 125000 pool 12500
```
`unpack.py` checks every part's SHA-256 and that the rebuilt `documents.csv`, `domain_keywords.csv` and
experiment files are byte-identical to the published dataset-v4. `data/` is git-ignored, so the unpacked
files are never committed. Disk needed: about 5 GB. Use `--out <path>` and then `--data <path>` /
`AMTP_DATA=<path>` to keep it elsewhere.

```
amtp_file_db_v4/
├── files/D1_cs/0000/D1_000001.txt …        500,000 .txt files (10,000 per subfolder)
├── insert_pool/D1_cs/0000/D1_I00001.txt …   50,000 .txt files (insert / split-merge experiments)
├── documents.csv                doc_id, domain_id, domain_name, is_initial, file_path, arxiv_id,
│                                n_keywords, keywords            <- used by every scheme (same columns as v3)
├── domain_keywords.csv          keyword document frequency per domain
├── amtp_plaintext.db            same data as SQLite (documents, keywords, postings; schema of v3)
├── summary.json                 numbers for the paper (vocabulary / keyword-file pairs per database size, …)
├── download_info.txt            source snapshot + MD5
├── queries_search_single.jsonl  Search 1.1/1.2: AND queries in one domain, exact result size per size
├── queries_boolean_multi.jsonl  Search 2.1: AND / OR / (A OR B) AND (C OR D) / (A AND B) OR (C AND D)
├── domain_groups.csv            Search 2.2 / Verify 2.2: arXiv category -> group for D = 1, 2, 4, 8, 16, 32
├── verify_keywords.csv          Verify 1.1/2.1: real keywords with ~10 / 100 / 1,000 / 10,000 results
├── tamper_sets.jsonl            Verify 1.2: which returned files to tamper (nested, seeded)
└── delete_order.csv             seeded deletion order (update / split-merge)
```
`README.txt` inside the folder describes every file in detail.

## Rebuild (maintainer only)

Identical output requires the exact same arXiv snapshot (MD5 in `data_v4/download_info.txt`).

```
python3 datasets/arxiv/select_files_v4.py arxiv-metadata-oai-snapshot.json --out ~/amtp_dataset           # 1) pick 550,000 papers, write .txt
python3 datasets/arxiv/build_v4.py --src ~/amtp_dataset --out ~/amtp_file_db_v4 \
        --arxiv-json arxiv-metadata-oai-snapshot.json                                                     # 2) W(d) with nlp.py (kappa=20) + experiment files
python3 datasets/arxiv/pack.py --src ~/amtp_file_db_v4                                                    # 3) git parts -> data_v4/ (deterministic)
```
Never commit `data/`, the arXiv `.json`, or any key file (`*.pem`, `kaggle.json`).

## dataset-v3 (old: 4 × 50,000, cs/math/physics/stat, κ = 10)

Not included in NewAMTP. Its parts remain in the original AMTP repository (`datasets/arxiv/data/`); copy them here to run
`python3 datasets/arxiv/unpack.py --v3` → `data/amtp_file_db/`, then run with `--data data/amtp_file_db`.
Its build scripts are `dataset_forAMTP.py` + `rebuild_keywords.py`, source info in `download_info.txt`.
