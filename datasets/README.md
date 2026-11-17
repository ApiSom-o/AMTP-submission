# Datasets

## Primary: arXiv, 4 domains × 125,000 files (`arxiv/`, dataset-v4)

The Section V experiments use the arXiv dataset: D1 = cs, D2 = math, D3 = astro-hep, D4 = condmat-quant,
125,000 initial files + 12,500 insert-pool files per domain (500,000 + 50,000), with keywords W(d)
pre-extracted by AMTP's Phase 1 code (κ = 20). The old dataset-v3 (4 × 50,000, κ = 10) is not included
in NewAMTP (see `arxiv/README.md`). **All schemes (AMTP + baselines) load it through `baselines/amtp_dataset.py` and use the same
W(d) from `documents.csv`.** Download / usage / rebuild: see [`arxiv/README.md`](arxiv/README.md).
