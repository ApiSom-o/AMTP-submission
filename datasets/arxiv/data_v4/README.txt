AMTP shared plaintext dataset -- dataset-v4  (arXiv on Kaggle, seed 42, every document real)
Domains: D1=cs, D2=math, D3=astro-hep, D4=condmat-quant

files/<domain>/<0000..>/   125000 plaintext files per domain (10,000 per subfolder). File = title + abstract.
                           doc_id order is chronological: the first n doc_ids of a domain ARE the database of
                           size n (smaller databases are prefixes of larger ones, so results are nested).
insert_pool/<domain>/      12500 more real files per domain, NOT in the initial set (insert / split-merge).
documents.csv              every file with its keywords W(d) (opens in Excel) -- what every scheme reads.
domain_keywords.csv        every keyword and how many initial files contain it, per domain.
amtp_plaintext.db          SQLite, NOT encrypted (same schema as dataset-v3):
                             documents(doc_id, domain_id, is_initial, file_path, arxiv_id, title,
                                       primary_category, categories, created, n_keywords, content)
                             keywords(keyword_id, keyword), postings(keyword_id, doc_id) = W(d), domains(...)
                             view domain_keyword_df(domain_id, keyword, doc_freq)
summary.json               numbers for the paper (vocabulary, keyword-file pairs per database size, ...).
download_info.txt          which Kaggle snapshot this was built from (MD5).

Keywords W(d): AMTP Phase 1 code (amtp_code/amtp/nlp.py) - RAKE, top-20 per file (kappa=20), 1-3 words,
  Theta_doc=30000, L_ch=400, L_ov=80; tokenise, lowercase, stop-words, possessive 's removed, light
  lemmatisation (Norm is idempotent). Vocabulary not limited. Extracted ONCE; every scheme uses them as-is.
Ground truth of keyword w in domain Di with n files:
  SELECT p.doc_id FROM postings p JOIN keywords k USING(keyword_id) JOIN documents d USING(doc_id)
  WHERE k.keyword = 'w' AND d.domain_id = 'Di' AND d.is_initial = 1 AND d.doc_id <= 'Di_<n, 6 digits>';

EXPERIMENT FILES (advisor's plan; all computed from the keywords above)
queries_search_single.jsonl  Search 1.1/1.2: AND queries inside one domain; keywords of one anchor file among the
                             first 10000 files (never empty at any size). result_size = exact plaintext result
                             count per files-per-domain (10000, 25000, 50000, 75000, 100000, 125000).
queries_boolean_multi.jsonl  Search 2.1: AND, OR, (A OR B) AND (C OR D), (A AND B) OR (C AND D); keywords from files
                             of different domains. result_size_per_domain = exact counts per domain and size.
                             "text" uses AMTP query syntax (multi-word keywords in double quotes).
domain_groups.csv            Search 2.2 / Verify 2.2: arXiv primary category -> group for D = 1,2,4,8,16,32
                             (D < 4: whole domains merged; D >= 4: categories of each domain split, balanced).
verify_keywords.csv          Verify 1.1/2.1: the 5 real keywords whose result size is closest to 10/100/1,000/10,000,
                             per domain and size; multi_domain = keywords present in every domain.
tamper_sets.jsonl            Verify 1.2: one keyword per domain with ~2,000 results (>= 2 x largest t); tamper the first t doc_ids of
                             tamper_order for t in tamper_counts (nested, seeded).
delete_order.csv             seeded deletion order per domain (update and split/merge experiments).
Total size N over all domains = the first N/4 files of every domain (baselines/amtp_dataset.py sample(N)).
