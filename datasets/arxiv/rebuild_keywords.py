#!/usr/bin/env python3
"""
rebuild_keywords.py
===================
Re-extract W(d) for every file in amtp_file_db/ with AMTP's own Phase 1 code
(amtp_code/amtp/nlp.py with its fixed THETA_DOC / L_CH / L_OV / KAPPA), so that the keyword
sets given to the baselines (documents.csv / amtp_plaintext.db) are exactly the sets
AMTP indexes when the same .txt files are imported with import_folder.py.

Phase 1, Step 3 of the report:  W(d) = { Norm(w) : w in Extract(d) }
  Extract = RAKE, whole document if |d| <= Theta_doc (30,000 words), otherwise chunks of
            L_ch words with overlap L_ov; top-kappa per chunk -> union -> dedup -> re-rank -> top-kappa
  Norm    = tokenise, lowercase, stop-word removal, light lemmatisation

The .txt files are NOT changed; only documents.csv, domain_keywords.csv, amtp_plaintext.db
and summary.json are rebuilt.

Usage (from project400/experiment):
    python3 datasets/arxiv/rebuild_keywords.py --db-dir data/amtp_file_db      (from the repo root)
"""
import argparse
import csv
import json
import os
import sqlite3
import sys
import time
from collections import Counter
from multiprocessing import Pool

P = None


def _init(amtp_dir):
    global P, extract_keywords
    sys.path.insert(0, os.path.abspath(amtp_dir))
    from types import SimpleNamespace
    from amtp import nlp
    P = SimpleNamespace(theta_doc=nlp.THETA_DOC, L_ch=nlp.L_CH, L_ov=nlp.L_OV, kappa=nlp.KAPPA,
                        max_phrase_words=nlp.MAX_WORDS)
    extract_keywords = nlp.extract_keywords


def read_text(path):
    # read the .txt exactly as stored (utf-8, undecodable bytes skipped)
    with open(path, "rb") as f:
        return f.read().decode("utf-8", "ignore")


def work(item):
    doc_id, abs_path = item
    W, _ = extract_keywords(read_text(abs_path), P.theta_doc, P.L_ch, max(1, P.L_ch // 5) if P.L_ov >= P.L_ch else P.L_ov,
                            P.kappa, P.max_phrase_words)
    return doc_id, W


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db-dir", default="amtp_file_db", help="folder with files/, insert_pool/, amtp_plaintext.db")
    ap.add_argument("--amtp", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "amtp_code"),
                    help="folder that contains the amtp/ package (default: <repo>/amtp_code)")
    ap.add_argument("--out", default=None, help="where to write new csv/db/summary (default: --db-dir)")
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 2)
    a = ap.parse_args()
    out = a.out or a.db_dir
    os.makedirs(out, exist_ok=True)
    _init(a.amtp)

    src = sqlite3.connect("file:%s?mode=ro" % os.path.join(a.db_dir, "amtp_plaintext.db"), uri=True)
    domains = src.execute("SELECT domain_id, name, arxiv_group, initial_files, insert_pool_files FROM domains ORDER BY domain_id").fetchall()
    docs = src.execute("SELECT doc_id, domain_id, is_initial, file_path, arxiv_id, title, primary_category, categories, "
                       "created, content FROM documents ORDER BY rowid").fetchall()
    src.close()
    print("documents: %d  params: theta_doc=%d L_ch=%d L_ov=%d kappa=%d max_words=%d"
          % (len(docs), P.theta_doc, P.L_ch, P.L_ov, P.kappa, P.max_phrase_words), flush=True)

    t0 = time.time()
    W = {}
    items = [(d[0], os.path.join(a.db_dir, d[3])) for d in docs]
    with Pool(a.workers, initializer=_init, initargs=(a.amtp,)) as pool:
        for n, (doc_id, kws) in enumerate(pool.imap(work, items, chunksize=500), 1):
            W[doc_id] = kws
            if n % 20000 == 0:
                print("  %d / %d  (%.0fs)" % (n, len(items), time.time() - t0), flush=True)
    print("extraction done in %.0fs" % (time.time() - t0), flush=True)

    db_path = os.path.join(out, "amtp_plaintext.db")
    tmp = db_path + ".building"
    con = sqlite3.connect(tmp)
    con.execute("PRAGMA journal_mode=OFF")
    con.executescript("""
        CREATE TABLE domains  (domain_id TEXT PRIMARY KEY, name TEXT, arxiv_group TEXT, initial_files INTEGER, insert_pool_files INTEGER);
        CREATE TABLE documents(doc_id TEXT PRIMARY KEY, domain_id TEXT, is_initial INTEGER, file_path TEXT,
                               arxiv_id TEXT, title TEXT, primary_category TEXT, categories TEXT, created TEXT,
                               n_keywords INTEGER, content TEXT);
        CREATE TABLE keywords (keyword_id INTEGER PRIMARY KEY, keyword TEXT UNIQUE);
        CREATE TABLE postings (keyword_id INTEGER, doc_id TEXT, PRIMARY KEY (keyword_id, doc_id)) WITHOUT ROWID;
    """)
    con.executemany("INSERT INTO domains VALUES (?,?,?,?,?)", domains)
    kw_id, rows, post, csv_rows = {}, [], [], []
    name_of = {d[0]: d[1] for d in domains}
    df = {d[0]: Counter() for d in domains}
    kpf = {d[0]: [] for d in domains}
    empty = []
    for d in docs:
        doc_id, dom, is_init = d[0], d[1], d[2]
        kws = W[doc_id]
        if not kws:
            empty.append(doc_id)
        for k in kws:
            if k not in kw_id:
                kw_id[k] = len(kw_id) + 1
            post.append((kw_id[k], doc_id))
            if is_init:
                df[dom][k] += 1
        if is_init:
            kpf[dom].append(len(kws))
        rows.append(d[:9] + (len(kws), d[9]))
        csv_rows.append([doc_id, dom, name_of[dom], is_init, d[3], d[4], len(kws), "; ".join(kws)])
    con.executemany("INSERT INTO keywords VALUES (?,?)", [(i, k) for k, i in kw_id.items()])
    con.executemany("INSERT INTO documents VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
    con.executemany("INSERT INTO postings VALUES (?,?)", post)
    con.executescript("""
        CREATE INDEX idx_postings_doc ON postings(doc_id);
        CREATE INDEX idx_documents_domain ON documents(domain_id, is_initial);
        CREATE VIEW domain_keyword_df AS
            SELECT d.domain_id, k.keyword, COUNT(*) AS doc_freq
            FROM postings p JOIN keywords k ON k.keyword_id = p.keyword_id
                            JOIN documents d ON d.doc_id = p.doc_id
            WHERE d.is_initial = 1
            GROUP BY d.domain_id, k.keyword;
    """)
    con.commit()
    con.close()
    os.replace(tmp, db_path) if not os.path.exists(db_path) else None

    with open(os.path.join(out, "documents.csv"), "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["doc_id", "domain_id", "domain_name", "is_initial", "file_path", "arxiv_id", "n_keywords", "keywords"])
        w.writerows(csv_rows)
    with open(os.path.join(out, "domain_keywords.csv"), "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["domain_id", "domain_name", "keyword", "doc_freq"])
        for dom, c in df.items():
            for k, v in sorted(c.items(), key=lambda kv: (-kv[1], kv[0])):
                w.writerow([dom, name_of[dom], k, v])

    sp = os.path.join(a.db_dir, "summary.json")
    summary = json.load(open(sp, encoding="utf-8")) if os.path.exists(sp) else {"domains": {}}
    for dom, c in df.items():
        s = summary["domains"].setdefault(dom, {"name": name_of[dom]})
        k = sorted(kpf[dom])
        s.update({
            "distinct_keywords": len(c), "keyword_postings": sum(c.values()),
            "keywords_per_file": {"mean": round(sum(k) / len(k), 2), "median": k[len(k) // 2], "min": k[0], "max": k[-1]},
            "max_keyword_doc_freq": max(c.values()),
            "keywords_in_2plus_files": sum(1 for v in c.values() if v >= 2),
        })
        s.pop("dropped_no_keyword", None)
    summary["keyword_extraction"] = {
        "version": "v3 - AMTP Phase 1 code (amtp_code/amtp/nlp.py, idempotent Norm: possessive 's removed), identical to what AMTP indexes on import",
        "method": "RAKE, score(p) = sum deg(w)/freq(w); whole document if |d| <= Theta_doc, else chunked",
        "Theta_doc_words": P.theta_doc, "L_ch_words": P.L_ch, "L_ov_words": P.L_ov,
        "kappa_top_k": P.kappa, "max_words_per_phrase": P.max_phrase_words,
        "normalization": "tokenise, lowercase, stop-word removal, rule-based lemmatisation (-ies->y, -s), dedup per file",
        "input_text": "exact .txt file content (title + abstract), as read by import_folder.py",
        "files_with_no_keyword": len(empty),
    }
    with open(os.path.join(out, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print("distinct keywords: %d  postings: %d  files with no keyword: %d" % (len(kw_id), len(post), len(empty)))
    print("written -> %s (db at %s)" % (os.path.abspath(out), tmp if os.path.exists(tmp) else db_path))


if __name__ == "__main__":
    main()
