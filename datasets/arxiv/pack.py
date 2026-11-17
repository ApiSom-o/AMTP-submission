#!/usr/bin/env python3
"""
pack.py -- turn a built dataset folder (dataset-v4: ~/amtp_file_db_v4) into small git-friendly parts.

Output (datasets/arxiv/data_v4/, committed to git):
    D1_cs.000.jsonl.gz ...           one JSON record per document (initial + insert pool), at most
                                     --docs-per-part documents per part (every part well under GitHub's 100 MB):
                                     doc_id, domain_id, is_initial, file_path, arxiv_id, title, primary_category,
                                     categories, created, keywords[], content, order
    manifest.json                    part checksums + checksums of every file unpack.py rebuilds
    summary.json, README.txt, download_info.txt, queries_*.jsonl, verify_keywords.csv, tamper_sets.jsonl,
    domain_groups.csv                copied as-is;  delete_order.csv.gz  (gzip of delete_order.csv)

Deterministic (gzip mtime = 0, fixed order): packing the same dataset twice gives identical bytes.
Only the maintainer runs this; everybody else runs unpack.py.

    python3 datasets/arxiv/pack.py --src ~/amtp_file_db_v4
(dataset-v3 parts in datasets/arxiv/data/ are kept unchanged.)
"""
import argparse
import csv
import gzip
import hashlib
import json
import os
import shutil
import sqlite3

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
COLS = ["doc_id", "domain_id", "is_initial", "file_path", "arxiv_id", "title",
        "primary_category", "categories", "created", "content"]
TAG = "amtp_file_db dataset-v4 (arXiv Kaggle, 4 x 125,000 + 10% insert pool, seed 42, AMTP Phase 1 keywords kappa=20)"
COPY = ["summary.json", "README.txt", "download_info.txt", "queries_search_single.jsonl",
        "queries_boolean_multi.jsonl", "verify_keywords.csv", "tamper_sets.jsonl", "domain_groups.csv"]
GZIP = ["delete_order.csv"]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def gz_open(path):
    raw = open(path, "wb")
    return raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, compresslevel=9, filename="")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=os.path.expanduser("~/amtp_file_db_v4"))
    ap.add_argument("--out", default=os.path.join(HERE, "data_v4"))
    ap.add_argument("--docs-per-part", type=int, default=25_000)
    ap.add_argument("--tag", default=TAG)
    ap.add_argument("--unpack-to", default="data/amtp_file_db_v4", help="default unpack folder (repo-relative)")
    a = ap.parse_args()
    if os.path.isdir(a.out):
        shutil.rmtree(a.out)
    os.makedirs(a.out)

    kw = {}
    with open(os.path.join(a.src, "documents.csv"), encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            kw[r["doc_id"]] = [k for k in r["keywords"].split("; ") if k]

    con = sqlite3.connect("file:%s?mode=ro" % os.path.join(a.src, "amtp_plaintext.db"), uri=True)
    domains = con.execute("SELECT domain_id, name, arxiv_group, initial_files, insert_pool_files "
                          "FROM domains ORDER BY domain_id").fetchall()
    manifest = {"dataset": a.tag, "default_out": a.unpack_to, "domains": [], "parts": {},
                "rebuilt_files": {}, "copied_files": {}}
    order = 0
    with open(os.path.join(a.src, "documents.csv"), encoding="utf-8-sig", newline="") as f:
        csv_order = [r["doc_id"] for r in csv.DictReader(f)]
    pos = {d: i for i, d in enumerate(csv_order)}
    for did, name, group, n_init, n_pool in domains:
        rows = con.execute(f"SELECT {', '.join(COLS)} FROM documents WHERE domain_id = ?", (did,)).fetchall()
        rows.sort(key=lambda r: pos[r[0]])                 # row order of documents.csv
        for pi, start in enumerate(range(0, len(rows), a.docs_per_part)):
            part = f"{did}_{name}.{pi:03d}.jsonl.gz"
            path = os.path.join(a.out, part)
            raw, g = gz_open(path)
            for row in rows[start:start + a.docs_per_part]:
                rec = dict(zip(COLS, row))
                rec["keywords"] = kw[rec["doc_id"]]
                rec["order"] = pos[rec["doc_id"]]
                assert rec["order"] == order, "documents.csv must be grouped by domain"
                order += 1
                g.write((json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8"))
            g.close()
            raw.close()
            n = min(a.docs_per_part, len(rows) - start)
            manifest["parts"][part] = {"documents": n, "bytes": os.path.getsize(path), "sha256": sha256(path)}
            print(f"{part}: {n} documents, {os.path.getsize(path) / 1e6:.1f} MB", flush=True)
        manifest["domains"].append({"domain_id": did, "name": name, "arxiv_group": group,
                                    "initial_files": n_init, "insert_pool_files": n_pool})
    con.close()
    assert order == len(csv_order)

    for name in ("documents.csv", "domain_keywords.csv"):
        manifest["rebuilt_files"][name] = sha256(os.path.join(a.src, name))
    for name in COPY:
        shutil.copyfile(os.path.join(a.src, name), os.path.join(a.out, name))
        manifest["copied_files"][name] = {"stored_as": name, "sha256": sha256(os.path.join(a.src, name))}
    for name in GZIP:
        raw, g = gz_open(os.path.join(a.out, name + ".gz"))
        with open(os.path.join(a.src, name), "rb") as f:
            shutil.copyfileobj(f, g)
        g.close()
        raw.close()
        manifest["copied_files"][name] = {"stored_as": name + ".gz", "sha256": sha256(os.path.join(a.src, name))}
    with open(os.path.join(a.out, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    total = sum(os.path.getsize(os.path.join(a.out, x)) for x in os.listdir(a.out))
    print(f"-> {a.out}  ({len(manifest['parts'])} parts, {total / 1e6:.0f} MB in total)")


if __name__ == "__main__":
    main()
