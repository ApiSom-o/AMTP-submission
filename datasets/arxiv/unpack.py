#!/usr/bin/env python3
"""
unpack.py -- rebuild the shared dataset folder from the parts committed in git.

After `git pull`, run once from the repo root (a few minutes, standard library only):

    python3 datasets/arxiv/unpack.py            # dataset-v4 -> data/amtp_file_db_v4/   (default, current)
    python3 datasets/arxiv/unpack.py --v3       # dataset-v3 -> data/amtp_file_db/      (old; its parts are not in NewAMTP)

dataset-v4 (datasets/arxiv/data_v4/) writes:
    data/amtp_file_db_v4/files/D1_cs ... D4_condmat-quant/<0000..>/*.txt     500,000 initial documents
    data/amtp_file_db_v4/insert_pool/...                                       50,000 insert-pool documents
    data/amtp_file_db_v4/documents.csv            keywords W(d) used by every scheme (kappa = 20)
    data/amtp_file_db_v4/domain_keywords.csv, amtp_plaintext.db, summary.json, README.txt, download_info.txt
    data/amtp_file_db_v4/queries_search_single.jsonl, queries_boolean_multi.jsonl, verify_keywords.csv,
                         tamper_sets.jsonl, domain_groups.csv, delete_order.csv          (experiment files)
and checks the result against manifest.json (documents.csv must match byte for byte).
Use --out to unpack somewhere else (then pass --data <folder> or set AMTP_DATA).
"""
import argparse
import csv
import gzip
import hashlib
import json
import os
import shutil
import sqlite3
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
SCHEMA = """
    CREATE TABLE domains  (domain_id TEXT PRIMARY KEY, name TEXT, arxiv_group TEXT, initial_files INTEGER, insert_pool_files INTEGER);
    CREATE TABLE documents(doc_id TEXT PRIMARY KEY, domain_id TEXT, is_initial INTEGER, file_path TEXT,
                           arxiv_id TEXT, title TEXT, primary_category TEXT, categories TEXT, created TEXT,
                           n_keywords INTEGER, content TEXT);
    CREATE TABLE keywords (keyword_id INTEGER PRIMARY KEY, keyword TEXT UNIQUE);
    CREATE TABLE postings (keyword_id INTEGER, doc_id TEXT, PRIMARY KEY (keyword_id, doc_id)) WITHOUT ROWID;
"""
SCHEMA_INDEXES = """
    CREATE INDEX idx_postings_doc ON postings(doc_id);
    CREATE INDEX idx_documents_domain ON documents(domain_id, is_initial);
    CREATE VIEW domain_keyword_df AS
        SELECT d.domain_id, k.keyword, COUNT(*) AS doc_freq
        FROM postings p JOIN keywords k ON k.keyword_id = p.keyword_id
                        JOIN documents d ON d.doc_id = p.doc_id
        WHERE d.is_initial = 1
        GROUP BY d.domain_id, k.keyword;
"""


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description="Rebuild the shared AMTP dataset folder from the parts in git")
    ap.add_argument("--v3", action="store_true", help="unpack the old dataset-v3 (datasets/arxiv/data/)")
    ap.add_argument("--parts", default=None, help="folder with manifest.json + parts (default: data_v4/)")
    ap.add_argument("--out", default=None, help="target folder (default: from manifest.json)")
    ap.add_argument("--force", action="store_true", help="rebuild even if the target already has documents.csv")
    a = ap.parse_args()
    parts_dir = a.parts or os.path.join(HERE, "data" if a.v3 else "data_v4")
    with open(os.path.join(parts_dir, "manifest.json"), encoding="utf-8") as f:
        man = json.load(f)
    out = os.path.abspath(os.path.expanduser(a.out or os.path.join(REPO, man.get("default_out", "data/amtp_file_db"))))
    tag = man["dataset"]
    print(f"{tag}\n-> {out}", flush=True)

    if os.path.exists(os.path.join(out, "documents.csv")) and not a.force:
        sys.exit(f"{out} already has documents.csv -- nothing to do (use --force to rebuild it)")

    for part, info in man["parts"].items():                       # 1) parts intact?
        p = os.path.join(parts_dir, part)
        if not os.path.exists(p) or sha256(p) != info["sha256"]:
            sys.exit(f"{part} is missing or corrupted -- run `git pull` again (or check Git LFS settings)")

    for sub in ("files", "insert_pool"):                          # 2) start clean (no stale files)
        shutil.rmtree(os.path.join(out, sub), ignore_errors=True)
    os.makedirs(out, exist_ok=True)
    db = os.path.join(out, "amtp_plaintext.db")
    if os.path.exists(db):
        os.remove(db)
    con = sqlite3.connect(db)
    con.execute("PRAGMA journal_mode=OFF")
    con.execute("PRAGMA synchronous=OFF")
    con.executescript(SCHEMA)
    con.executemany("INSERT INTO domains VALUES (?,?,?,?,?)",
                    [(d["domain_id"], d["name"], d["arxiv_group"], d["initial_files"], d["insert_pool_files"])
                     for d in man["domains"]])
    names = {d["domain_id"]: d["name"] for d in man["domains"]}
    df = {d: Counter() for d in names}
    kw_id, rows, post, newk = {}, [], [], []
    made_dirs = set()
    total = sum(info["documents"] for info in man["parts"].values())

    def flush():
        con.executemany("INSERT INTO keywords VALUES (?,?)", newk)
        con.executemany("INSERT INTO documents VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
        con.executemany("INSERT INTO postings VALUES (?,?)", post)
        rows.clear(), post.clear(), newk.clear()

    n, last = 0, -1                                               # 3) one pass: .txt, documents.csv, db
    with open(os.path.join(out, "documents.csv"), "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["doc_id", "domain_id", "domain_name", "is_initial", "file_path", "arxiv_id", "n_keywords", "keywords"])
        for part in man["parts"]:
            with gzip.open(os.path.join(parts_dir, part), "rt", encoding="utf-8") as g:
                for line in g:
                    r = json.loads(line)
                    if r["order"] != last + 1:
                        sys.exit(f"{part}: documents out of order -- please report this")
                    last = r["order"]
                    path = os.path.join(out, r["file_path"])
                    d = os.path.dirname(path)
                    if d not in made_dirs:
                        os.makedirs(d, exist_ok=True)
                        made_dirs.add(d)
                    with open(path, "w", encoding="utf-8", newline="\n") as fh:
                        fh.write(r["content"] + "\n")
                    kws = r["keywords"]
                    w.writerow([r["doc_id"], r["domain_id"], names[r["domain_id"]], r["is_initial"], r["file_path"],
                                r["arxiv_id"], len(kws), "; ".join(kws)])
                    if r["is_initial"]:
                        df[r["domain_id"]].update(kws)
                    for k in kws:
                        if k not in kw_id:
                            kw_id[k] = len(kw_id) + 1
                            newk.append((kw_id[k], k))
                        post.append((kw_id[k], r["doc_id"]))
                    rows.append((r["doc_id"], r["domain_id"], r["is_initial"], r["file_path"], r["arxiv_id"],
                                 r["title"], r["primary_category"], r["categories"], r["created"], len(kws),
                                 r["content"]))
                    if len(rows) >= 20_000:
                        flush()
                    n += 1
                    if n % 50_000 == 0:
                        print(f"  {n} / {total} documents", flush=True)
    flush()
    print("  building database indexes ...", flush=True)
    con.executescript(SCHEMA_INDEXES)
    con.commit()
    con.close()

    with open(os.path.join(out, "domain_keywords.csv"), "w", newline="", encoding="utf-8-sig") as f:   # 4)
        w = csv.writer(f)
        w.writerow(["domain_id", "domain_name", "keyword", "doc_freq"])
        for dom, c in df.items():
            for k, v in sorted(c.items(), key=lambda kv: (-kv[1], kv[0])):
                w.writerow([dom, names[dom], k, v])

    copied = man.get("copied_files")                              # 5) metadata + experiment files
    if copied is None:                                            #    dataset-v3 layout
        copied = {x: {"stored_as": x} for x in ("summary.json", "README.txt")}
        shutil.copyfile(os.path.join(HERE, "download_info.txt"), os.path.join(out, "download_info.txt"))
    for name, info in copied.items():
        src, dst = os.path.join(parts_dir, info["stored_as"]), os.path.join(out, name)
        if info["stored_as"].endswith(".gz") and not name.endswith(".gz"):
            with gzip.open(src, "rb") as g, open(dst, "wb") as fh:
                shutil.copyfileobj(g, fh)
        else:
            shutil.copyfile(src, dst)

    checks = dict(man["rebuilt_files"])                           # 6) verify
    checks.update({k: v["sha256"] for k, v in copied.items() if "sha256" in v})
    bad = [x for x, h in checks.items() if sha256(os.path.join(out, x)) != h]
    if bad:
        sys.exit(f"CHECK FAILED: {bad} differ from the published dataset -- please report this")
    print(f"OK: {n} documents in {out}  ({len(checks)} files match the published checksums)")
    if not a.v3 and a.out is None:
        print("next: python3 baselines/amtp_dataset.py      (reads this folder by default)")
    else:
        print(f"next: python3 baselines/amtp_dataset.py --data {out}")


if __name__ == "__main__":
    main()
