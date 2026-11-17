#!/usr/bin/env python3
"""
build_v4.py -- dataset-v4 keywords + experiment files
=====================================================
dataset-v4 = 4 domains x 125,000 real arXiv files (+ 12,500 insert-pool files per domain), seed 42.
W(d) is extracted ONCE with AMTP's own Phase 1 code (amtp_code/amtp/nlp.py, KAPPA = 20) and shared
as-is by every scheme (AMTP, Du et al., SE-COLLAB, Chen et al.).

Pipeline (only the maintainer runs steps 1-3, on the cloud machine):
  1) select_files_v4.py  arxiv-metadata-oai-snapshot.json --out ~/amtp_dataset
         picks the 550,000 papers (seeded) and writes the .txt files (title + abstract)
  2) build_v4.py --src ~/amtp_dataset --out ~/amtp_file_db_v4 --arxiv-json <snapshot>
         re-extracts W(d) from every .txt with nlp.extract_keywords (kappa = 20) and writes the
         v3-compatible layout (documents.csv, domain_keywords.csv, amtp_plaintext.db, summary.json, ...)
         plus the experiment files generated from the NEW keywords (queries, verify, tamper, domain groups)
  3) pack.py --src ~/amtp_file_db_v4                      -> datasets/arxiv/data_v4/  (committed to git)
Everybody else:  python3 datasets/arxiv/unpack.py      -> data/amtp_file_db_v4/

Output layout (same columns/schema as dataset-v3, so baselines/amtp_dataset.py reads it unchanged):
  files/D1_cs/0000/D1_000001.txt ...              initial files, doc_id order = chronological
  insert_pool/D1_cs/0000/D1_I00001.txt ...        insert pool (not in the initial set)
  documents.csv        doc_id, domain_id, domain_name, is_initial, file_path, arxiv_id, n_keywords, keywords
  domain_keywords.csv  domain_id, domain_name, keyword, doc_freq   (initial files only)
  amtp_plaintext.db    domains / documents / keywords / postings (+ view domain_keyword_df), schema of v3
  summary.json, README.txt, download_info.txt
  queries_search_single.jsonl, queries_boolean_multi.jsonl, verify_keywords.csv, tamper_sets.jsonl,
  domain_groups.csv, delete_order.csv

Standard library only.
"""
import argparse
import csv
import hashlib
import heapq
import json
import os
import random
import re
import shutil
import sqlite3
import sys
import time
from array import array
from bisect import bisect_left
from collections import Counter, defaultdict
from multiprocessing import Pool

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
DATASET_TAG = "amtp_file_db dataset-v4 (arXiv Kaggle, 4 x 125,000 + 10% insert pool, seed 42, AMTP Phase 1 keywords kappa=20)"
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
CSV_HEADER = ["doc_id", "domain_id", "domain_name", "is_initial", "file_path", "arxiv_id", "n_keywords", "keywords"]

# ----------------------------------------------------------------------------
# keyword extraction workers (AMTP Phase 1 code)
# ----------------------------------------------------------------------------
P = None


def _init(amtp_dir, kappa):
    global P
    sys.path.insert(0, os.path.abspath(amtp_dir))
    from amtp import nlp
    P = (nlp.extract_keywords, nlp.THETA_DOC, nlp.L_CH, nlp.L_OV, kappa, nlp.MAX_WORDS)


def _work(item):
    doc_id, path = item
    extract, theta, L_ch, L_ov, kappa, max_words = P
    with open(path, "rb") as f:                       # exactly as rebuild_keywords.py / import_folder.py read it
        text = f.read().decode("utf-8", "ignore")
    t0 = time.perf_counter()
    W, _ = extract(text, theta, L_ch, L_ov, kappa, max_words)
    return doc_id, W, time.perf_counter() - t0


# ----------------------------------------------------------------------------
# plaintext index per domain (position = 0-based chronological index of initial files)
# ----------------------------------------------------------------------------
class DomainIndex:
    def __init__(self, dom, name, doc_ids, doc_kws, cats):
        self.dom, self.name = dom, name
        self.doc_ids = doc_ids
        self.doc_kws = doc_kws
        self.cats = cats
        post = defaultdict(lambda: array("i"))
        for p, kws in enumerate(doc_kws):
            for k in kws:
                post[k].append(p)                     # increasing p -> sorted
        self.post = dict(post)
        self.n = len(doc_kws)

    def df_at(self, k, N):
        a = self.post.get(k)
        return 0 if a is None else bisect_left(a, N)

    def positions(self, k):
        return set(self.post.get(k, ()))


def build_expr(shape, kw):
    if shape == "single":
        return kw[0]
    if shape in ("AND", "OR"):
        return {"op": shape, "args": list(kw)}
    pairs = [kw[i:i + 2] for i in range(0, len(kw), 2)]
    if shape == "AND_of_OR":
        return {"op": "AND", "args": [{"op": "OR", "args": p} for p in pairs]}
    if shape == "OR_of_AND":
        return {"op": "OR", "args": [{"op": "AND", "args": p} for p in pairs]}
    raise ValueError(shape)


def expr_text(e, top=True):
    """AMTP query syntax: multi-word keywords in double quotes (boolean.parse reads them as one leaf)"""
    if isinstance(e, str):
        return '"%s"' % e
    s = (" AND " if e["op"] == "AND" else " OR ").join(expr_text(a, False) for a in e["args"])
    return s if top else "(" + s + ")"


def evaluate(e, idx):
    if isinstance(e, str):
        return idx.positions(e)
    sets = [evaluate(a, idx) for a in e["args"]]
    return set.intersection(*sets) if e["op"] == "AND" else set.union(*sets)


def counts_at(positions, points):
    s = sorted(positions)
    return {str(N): bisect_left(s, N) for N in points}


def greedy_bins(items, k):
    """items: (name, weight) -> bin index per name, balanced by weight"""
    load = [0] * k
    out = {}
    for name, w in sorted(items, key=lambda x: (-x[1], x[0])):
        j = min(range(k), key=lambda b: (load[b], b))
        out[name] = j
        load[j] += w
    return out, load


def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def snapshot_info(path):
    """md5, size, number of records and newest update_date of the Kaggle snapshot (one pass)"""
    md5, n, newest = hashlib.md5(), 0, ""
    pat = re.compile(rb'"update_date"\s*:\s*"(\d{4}-\d{2}-\d{2})"')
    with open(path, "rb") as f:
        for line in f:
            md5.update(line)
            n += 1
            m = pat.search(line)
            if m and m.group(1).decode() > newest:
                newest = m.group(1).decode()
    st = os.stat(path)
    return {"md5": md5.hexdigest(), "bytes": st.st_size, "records": n, "newest": newest,
            "file_date": time.strftime("%Y-%m-%d", time.gmtime(st.st_mtime))}


# ----------------------------------------------------------------------------
# experiment files (advisor's plan), all computed from the v4 keywords
# ----------------------------------------------------------------------------
def tamper_sets(indexes, a, points):
    """Verify 1.2: per domain, one real keyword whose result at 100,000 files per domain has at least twice the
    largest tamper count (closest to 2 x max t, i.e. ~2,000 results for t up to 1,000), so every t tampers at most
    half of the result and every domain gets the same t values; plus a seeded order of its result files."""
    tN = 100_000 if 100_000 in points else max(points)
    need = 2 * max(a.tamper)
    rows, trng = [], random.Random("%d-tamper" % a.seed)
    for dom in indexes:
        idx = indexes[dom]
        cand = [(idx.df_at(k, tN) - need, k) for k in idx.post if idx.df_at(k, tN) >= need]
        if not cand:
            sys.exit("%s: no keyword with >= %d results at %d files" % (dom, need, tN))
        _, k = min(cand)
        res = [idx.doc_ids[p] for p in idx.post[k] if p < tN]
        perm = res[:]
        trng.shuffle(perm)
        rows.append({"domain": dom, "files_per_domain": tN, "query_keyword": k, "result_size": len(res),
                     "tamper_counts": list(a.tamper), "tamper_order": perm,
                     "note": "tamper the first t doc_ids of tamper_order for t in tamper_counts "
                             "(t <= half of result_size)"})
    return rows


def experiment_files(out, indexes, a, points):
    doms = list(indexes)
    D = len(doms)
    anchor_n = min(a.anchor_n, min(ix.n for ix in indexes.values()))
    qrng = random.Random("%d-queries" % a.seed)
    stats = {}

    # Search 1.1 / 1.2: AND queries inside one domain (keywords of one anchor file -> never empty)
    q_single, qid = [], 0
    for dom in doms:
        idx = indexes[dom]
        for k in a.kq_single:
            ok = [p for p in range(anchor_n) if len(idx.doc_kws[p]) >= k]
            if not ok:
                print("  warning: no anchor file with >= %d keywords in %s" % (k, dom))
                continue
            for _ in range(a.queries_per_k):
                p = ok[qrng.randrange(len(ok))]
                kw = qrng.sample(sorted(idx.doc_kws[p]), k)
                shape = "single" if k == 1 else "AND"
                e = build_expr(shape, kw)
                qid += 1
                q_single.append({"query_id": "S1_%05d" % qid, "domain": dom, "kQ": k, "shape": shape,
                                 "expression": e, "text": expr_text(e), "keywords": kw,
                                 "source_doc": idx.doc_ids[p], "result_size": counts_at(evaluate(e, idx), points)})
    write_jsonl(os.path.join(out, "queries_search_single.jsonl"), q_single)

    # Search 2.1: Boolean queries, keywords from files of several domains
    q_bool, qid = [], 0

    def anchor(dom, need_k):
        idx = indexes[dom]
        for _ in range(500):
            p = qrng.randrange(anchor_n)
            if len(idx.doc_kws[p]) >= need_k:
                return p, sorted(idx.doc_kws[p])
        return None, None

    for k in a.kq_boolean:
        for shape in ["AND", "OR", "AND_of_OR", "OR_of_AND"]:
            made = 0
            for _ in range(a.queries_per_k * 20):
                if made == a.queries_per_k:
                    break
                ds = qrng.sample(doms, min(2, D))
                if shape == "AND":                      # all keys from one file -> non-empty in that domain
                    p, ks = anchor(ds[0], k)
                    if p is None:
                        continue
                    kw, src = qrng.sample(ks, k), [indexes[ds[0]].doc_ids[p]]
                elif shape == "OR":                     # one key from a file of each domain in turn
                    kw, src, ok = [], [], True
                    for j in range(k):
                        d = doms[(doms.index(ds[0]) + j) % D]
                        p, ks = anchor(d, 1)
                        cand = [x for x in (ks or []) if x not in kw]
                        if p is None or not cand:
                            ok = False
                            break
                        kw.append(qrng.choice(cand))
                        src.append(indexes[d].doc_ids[p])
                    if not ok:
                        continue
                elif shape == "AND_of_OR":              # (A OR B) AND (C OR D): A, C from file X; B, D from file Y
                    h = k // 2
                    px, kx = anchor(ds[0], h)
                    py, ky = anchor(ds[-1], h)
                    if px is None or py is None:
                        continue
                    x = qrng.sample(kx, h)
                    y = [w for w in qrng.sample(ky, len(ky)) if w not in x][:h]
                    if len(y) < h:
                        continue
                    kw = [w for pair in zip(x, y) for w in pair]
                    src = [indexes[ds[0]].doc_ids[px], indexes[ds[-1]].doc_ids[py]]
                else:                                   # (A AND B) OR (C AND D): each pair from one file
                    kw, src, ok = [], [], True
                    for j in range(k // 2):
                        d = doms[(doms.index(ds[0]) + j) % D]
                        p, ks = anchor(d, 2)
                        pair = [w for w in qrng.sample(ks, len(ks)) if w not in kw][:2] if ks else []
                        if p is None or len(pair) < 2:
                            ok = False
                            break
                        kw += pair
                        src.append(indexes[d].doc_ids[p])
                    if not ok:
                        continue
                if len(set(kw)) != len(kw):
                    continue
                e = build_expr(shape, kw)
                qid += 1
                made += 1
                q_bool.append({"query_id": "S2_%05d" % qid, "kQ": k, "shape": shape, "expression": e,
                               "text": expr_text(e), "keywords": kw, "source_docs": src,
                               "result_size_per_domain": {d: counts_at(evaluate(e, indexes[d]), points) for d in doms}})
    write_jsonl(os.path.join(out, "queries_boolean_multi.jsonl"), q_bool)

    # Verify 1.1 / 2.1: real keywords whose result size is closest to the targets
    vrows = []
    common = set.intersection(*(set(indexes[d].post) for d in doms))
    for N in points:
        for dom in doms:
            idx = indexes[dom]
            for t in a.targets:
                best = heapq.nsmallest(5, ((abs(bisect_left(arr, N) - t), k, bisect_left(arr, N))
                                           for k, arr in idx.post.items()))
                for rank, (_, k, df) in enumerate(best, 1):
                    vrows.append(["single_domain", dom, N, t, rank, k, df, df])
        tot = [(k, [indexes[d].df_at(k, N) for d in doms]) for k in common]
        for t in a.targets:
            best = heapq.nsmallest(5, ((abs(sum(per) - t), k, per) for k, per in tot))
            for rank, (_, k, per) in enumerate(best, 1):
                vrows.append(["multi_domain", "+".join(doms), N, t, rank, k, sum(per), " ".join(map(str, per))])
    with open(os.path.join(out, "verify_keywords.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["setting", "domain", "files_per_domain", "target_results", "rank", "keyword",
                    "result_size", "result_size_per_domain"])
        w.writerows(vrows)

    # Verify 1.2: files to tamper (nested, seeded)
    write_jsonl(os.path.join(out, "tamper_sets.jsonl"), tamper_sets(indexes, a, points))

    # Search 2.2 / Verify 2.2: arXiv primary categories -> D = 1..32 groups
    cat_count = {dom: Counter(indexes[dom].cats) for dom in doms}
    d_values = [1, 2, 4, 8, 16, 32]
    assign = {(dom, c): {} for dom in doms for c in cat_count[dom]}
    gsizes = {}
    for Dv in d_values:
        if Dv < D:
            per_top, _ = greedy_bins([(dom, indexes[dom].n) for dom in doms], Dv)
            for (dom, c) in assign:
                assign[(dom, c)][Dv] = "G%02d" % (per_top[dom] + 1)
        else:
            k = Dv // D
            for ti, dom in enumerate(doms):
                bins, _ = greedy_bins(list(cat_count[dom].items()), k)
                for c, b in bins.items():
                    assign[(dom, c)][Dv] = "G%02d" % (ti * k + b + 1)
        sz = Counter()
        for (dom, c), g in assign.items():
            sz[g[Dv]] += cat_count[dom][c]
        gsizes[str(Dv)] = dict(sorted(sz.items()))
    with open(os.path.join(out, "domain_groups.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["domain_id", "domain_name", "primary_category", "initial_files"] + ["D%d" % x for x in d_values])
        for (dom, c) in sorted(assign):
            w.writerow([dom, indexes[dom].name, c, cat_count[dom][c]] + [assign[(dom, c)][x] for x in d_values])

    # deletion order (update / split-merge experiments)
    drng = random.Random("%d-delete" % a.seed)
    with open(os.path.join(out, "delete_order.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["domain_id", "order", "doc_id"])
        for dom in doms:
            ids = list(indexes[dom].doc_ids)
            drng.shuffle(ids)
            w.writerows([dom, i + 1, x] for i, x in enumerate(ids))

    stats["queries"] = {"search_single": len(q_single), "boolean_multi": len(q_bool),
                        "empty_search_single_at_max_size":
                            sum(1 for q in q_single if q["result_size"][str(max(points))] == 0)}
    stats["domain_group_sizes"] = gsizes
    return stats


# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="dataset-v4: AMTP Phase 1 keywords (kappa=20) + experiment files")
    ap.add_argument("--src", default=os.path.expanduser("~/amtp_dataset"),
                    help="output of select_files_v4.py (files/, insert_pool/, amtp_plaintext.db)")
    ap.add_argument("--out", default=os.path.expanduser("~/amtp_file_db_v4"))
    ap.add_argument("--amtp", default=os.path.join(REPO, "amtp_code"), help="folder containing the amtp/ package")
    ap.add_argument("--kappa", type=int, default=None, help="keywords per file (default: amtp/nlp.py KAPPA)")
    ap.add_argument("--arxiv-json", default=None, help="Kaggle snapshot, to record its MD5 in download_info.txt")
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 2)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--points", default="10000,25000,50000,75000,100000,125000",
                    help="per-domain database sizes for ground truth / stats")
    ap.add_argument("--kq-single", default="1,2,5,10,15,20")
    ap.add_argument("--kq-boolean", default="2,4,8,16")
    ap.add_argument("--queries-per-k", type=int, default=20)
    ap.add_argument("--anchor-n", type=int, default=10_000)
    ap.add_argument("--targets", default="10,100,1000,10000")
    ap.add_argument("--tamper", default="5,10,20,40,100,1000")
    a = ap.parse_args()
    for name in ("kq_single", "kq_boolean", "targets", "tamper"):
        setattr(a, name, [int(x) for x in getattr(a, name).split(",") if x.strip()])
    t_start = time.time()

    sys.path.insert(0, os.path.abspath(a.amtp))
    from amtp import nlp
    kappa = a.kappa or nlp.KAPPA
    print("AMTP Phase 1 parameters: theta_doc=%d L_ch=%d L_ov=%d kappa=%d max_words=%d"
          % (nlp.THETA_DOC, nlp.L_CH, nlp.L_OV, kappa, nlp.MAX_WORDS), flush=True)

    src_db = os.path.join(a.src, "amtp_plaintext.db")
    if os.path.abspath(a.src) == os.path.abspath(a.out):
        sys.exit("--out must differ from --src")
    if os.path.exists(a.out):
        sys.exit("%s already exists -- remove it first" % a.out)
    src = sqlite3.connect("file:%s?mode=ro" % src_db, uri=True)
    domains = src.execute("SELECT domain_id, name, arxiv_archives, initial_files, insert_pool_files "
                          "FROM domains ORDER BY domain_id").fetchall()
    ORDER = "ORDER BY domain_id, is_initial DESC, doc_id"
    meta = src.execute("SELECT doc_id, domain_id, is_initial, file_path, arxiv_id, primary_category, created "
                       "FROM documents " + ORDER).fetchall()
    name_of = {d[0]: d[1] for d in domains}
    print("source: %s  (%d documents, domains: %s)" % (a.src, len(meta),
          ", ".join("%s=%s %d+%d" % (d[0], d[1], d[3], d[4]) for d in domains)), flush=True)

    # 1) extract W(d) from every .txt (parallel)
    t0 = time.time()
    canon, W, ext_time = {}, {}, 0.0
    items = [(m[0], os.path.join(a.src, m[3])) for m in meta]
    with Pool(a.workers, initializer=_init, initargs=(a.amtp, kappa)) as pool:
        for n, (doc_id, kws, dt) in enumerate(pool.imap(_work, items, chunksize=500), 1):
            W[doc_id] = [canon.setdefault(k, k) for k in kws]   # share equal strings (memory)
            ext_time += dt
            if n % 50_000 == 0:
                print("  extracted %d / %d  (%.0fs)" % (n, len(items), time.time() - t0), flush=True)
    del canon
    print("extraction done in %.0fs (%.3f ms/file of CPU time)" % (time.time() - t0, 1000 * ext_time / len(items)),
          flush=True)

    # 2) .txt files: hard links to the source files (same bytes, no extra disk), copy if links are impossible
    os.makedirs(a.out)
    made_dirs = set()
    for n, m in enumerate(meta, 1):
        s, d = os.path.join(a.src, m[3]), os.path.join(a.out, m[3])
        dd = os.path.dirname(d)
        if dd not in made_dirs:
            os.makedirs(dd, exist_ok=True)
            made_dirs.add(dd)
        try:
            os.link(s, d)
        except OSError:
            shutil.copyfile(s, d)
        if n % 100_000 == 0:
            print("  files %d / %d" % (n, len(meta)), flush=True)

    # 3) documents.csv + amtp_plaintext.db (dataset-v3 schema)
    con = sqlite3.connect(os.path.join(a.out, "amtp_plaintext.db"))
    con.execute("PRAGMA journal_mode=OFF")
    con.execute("PRAGMA synchronous=OFF")
    con.execute("PRAGMA cache_size=-2000000")
    con.executescript(SCHEMA)
    con.executemany("INSERT INTO domains VALUES (?,?,?,?,?)", domains)
    kw_id = {}
    df = {d[0]: Counter() for d in domains}
    kpf = {d[0]: [] for d in domains}
    empty = []
    rows, post, newk = [], [], []

    def flush():
        con.executemany("INSERT INTO keywords VALUES (?,?)", newk)
        con.executemany("INSERT INTO documents VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
        con.executemany("INSERT INTO postings VALUES (?,?)", post)
        rows.clear(), post.clear(), newk.clear()

    with open(os.path.join(a.out, "documents.csv"), "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(CSV_HEADER)
        cur = src.execute("SELECT doc_id, domain_id, is_initial, file_path, arxiv_id, title, primary_category, "
                          "categories, created, content FROM documents " + ORDER)
        for r in cur:
            doc_id, dom, is_init = r[0], r[1], r[2]
            kws = W[doc_id]
            if not kws:
                empty.append(doc_id)
            for k in kws:
                if k not in kw_id:
                    kw_id[k] = len(kw_id) + 1
                    newk.append((kw_id[k], k))
                post.append((kw_id[k], doc_id))
            if is_init:
                df[dom].update(kws)
                kpf[dom].append(len(kws))
            rows.append(r[:9] + (len(kws), r[9]))
            w.writerow([doc_id, dom, name_of[dom], is_init, r[3], r[4], len(kws), "; ".join(kws)])
            if len(rows) >= 20_000:
                flush()
        flush()
    src.close()
    print("building database indexes ...", flush=True)
    con.executescript(SCHEMA_INDEXES)
    con.commit()
    con.close()

    with open(os.path.join(a.out, "domain_keywords.csv"), "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["domain_id", "domain_name", "keyword", "doc_freq"])
        for dom, c in df.items():
            for k, v in sorted(c.items(), key=lambda kv: (-kv[1], kv[0])):
                w.writerow([dom, name_of[dom], k, v])

    # 4) experiment files from the new keywords
    print("experiment files (queries, verify, tamper, domain groups) ...", flush=True)
    by_dom = defaultdict(list)
    for m in meta:
        if m[2]:
            by_dom[m[1]].append(m)
    per_domain = min(len(v) for v in by_dom.values())
    points = sorted({min(int(x), per_domain) for x in a.points.split(",") if x.strip()} | {per_domain})
    indexes = {dom: DomainIndex(dom, name_of[dom], [m[0] for m in ms], [W[m[0]] for m in ms], [m[5] for m in ms])
               for dom, ms in sorted(by_dom.items())}
    exp = experiment_files(a.out, indexes, a, points)

    # 5) summary.json (same keys as dataset-v3, plus sizes per database size)
    summary = {"dataset": DATASET_TAG,
               "source": "arXiv metadata (Kaggle: Cornell-University/arxiv), one file = title + abstract, all real",
               "seed": a.seed, "total_initial_files": sum(d[3] for d in domains),
               "total_insert_pool_files": sum(d[4] for d in domains), "domains": {}}
    for dom, name, group, n_init, n_pool in domains:
        idx, c, k = indexes[dom], df[dom], sorted(kpf[dom])
        by_size = {}
        for N in points:
            dfs = [x for x in (bisect_left(arr, N) for arr in idx.post.values()) if x > 0]
            by_size[str(N)] = {"files": N, "vocabulary": len(dfs), "vocabulary_df_ge_2": sum(1 for x in dfs if x >= 2),
                               "keyword_file_pairs": sum(dfs), "max_doc_freq": max(dfs)}
        summary["domains"][dom] = {
            "name": name, "arxiv_group": group, "initial_files": n_init, "insert_pool_files": n_pool,
            "distinct_keywords": len(c), "keyword_postings": sum(c.values()),
            "keywords_per_file": {"mean": round(sum(k) / len(k), 2), "median": k[len(k) // 2], "min": k[0],
                                  "max": k[-1], "files_with_kappa": sum(1 for x in k if x == kappa)},
            "max_keyword_doc_freq": max(c.values()),
            "keywords_in_2plus_files": sum(1 for v in c.values() if v >= 2),
            "by_database_size": by_size,
            "created_range": [by_dom[dom][0][6], by_dom[dom][-1][6]],
            "primary_categories": len(set(idx.cats)),
        }
    summary["distinct_keywords_all_domains"] = len(kw_id)
    summary["keyword_extraction"] = {
        "version": "v4 - AMTP Phase 1 code (amtp_code/amtp/nlp.py), kappa=20, identical to what AMTP indexes on import",
        "method": "RAKE, score(p) = sum deg(w)/freq(w); whole document if |d| <= Theta_doc, else chunked",
        "Theta_doc_words": nlp.THETA_DOC, "L_ch_words": nlp.L_CH, "L_ov_words": nlp.L_OV,
        "kappa_top_k": kappa, "max_words_per_phrase": nlp.MAX_WORDS,
        "normalization": "tokenise, lowercase, stop-word removal, rule-based lemmatisation (-ies->y, -s), dedup per file",
        "input_text": "exact .txt file content (title + abstract), as read by import_folder.py",
        "vocabulary_limit": "none", "files_with_no_keyword": len(empty),
        "mean_ms_per_file_cpu": round(1000 * ext_time / len(items), 4),
        "note": "extracted once; every scheme reads documents.csv; extraction time is not part of any experiment",
    }
    summary.update(exp)
    summary["database_sizes_per_domain"] = points
    summary["build_minutes"] = round((time.time() - t_start) / 60, 1)
    with open(os.path.join(a.out, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    # 6) README.txt + download_info.txt
    doms = ", ".join("%s=%s" % (d[0], d[1]) for d in domains)
    n_pool = domains[0][4]
    with open(os.path.join(a.out, "README.txt"), "w", encoding="utf-8") as f:
        f.write(README.format(doms=doms, n=per_domain, pool=n_pool, kappa=kappa, theta=nlp.THETA_DOC, lch=nlp.L_CH,
                              lov=nlp.L_OV, points=", ".join(map(str, points)), anchor=min(a.anchor_n, per_domain),
                              D=len(domains), seed=a.seed))
    info = snapshot_info(a.arxiv_json) if a.arxiv_json else None
    with open(os.path.join(a.out, "download_info.txt"), "w", encoding="utf-8") as f:
        f.write(DOWNLOAD_INFO.format(
            md5=info["md5"] if info else "(not recorded)", size="{:,}".format(info["bytes"]) if info else "?",
            records="{:,}".format(info["records"]) if info else "?", newest=info["newest"] if info else "?",
            file_date=info["file_date"] if info else "?", n=per_domain, pool=n_pool, kappa=kappa, doms=doms))

    print("distinct keywords: %d   files with no keyword: %d" % (len(kw_id), len(empty)))
    for dom in summary["domains"]:
        s = summary["domains"][dom]
        print("  %s %-14s vocabulary %d (df>=2: %d)  keywords/file mean %.2f" % (
            dom, s["name"], s["distinct_keywords"], s["keywords_in_2plus_files"], s["keywords_per_file"]["mean"]))
    print("done in %.1f min -> %s" % ((time.time() - t_start) / 60, os.path.abspath(a.out)))


README = """AMTP shared plaintext dataset -- dataset-v4  (arXiv on Kaggle, seed {seed}, every document real)
Domains: {doms}

files/<domain>/<0000..>/   {n} plaintext files per domain (10,000 per subfolder). File = title + abstract.
                           doc_id order is chronological: the first n doc_ids of a domain ARE the database of
                           size n (smaller databases are prefixes of larger ones, so results are nested).
insert_pool/<domain>/      {pool} more real files per domain, NOT in the initial set (insert / split-merge).
documents.csv              every file with its keywords W(d) (opens in Excel) -- what every scheme reads.
domain_keywords.csv        every keyword and how many initial files contain it, per domain.
amtp_plaintext.db          SQLite, NOT encrypted (same schema as dataset-v3):
                             documents(doc_id, domain_id, is_initial, file_path, arxiv_id, title,
                                       primary_category, categories, created, n_keywords, content)
                             keywords(keyword_id, keyword), postings(keyword_id, doc_id) = W(d), domains(...)
                             view domain_keyword_df(domain_id, keyword, doc_freq)
summary.json               numbers for the paper (vocabulary, keyword-file pairs per database size, ...).
download_info.txt          which Kaggle snapshot this was built from (MD5).

Keywords W(d): AMTP Phase 1 code (amtp_code/amtp/nlp.py) - RAKE, top-{kappa} per file (kappa={kappa}), 1-3 words,
  Theta_doc={theta}, L_ch={lch}, L_ov={lov}; tokenise, lowercase, stop-words, possessive 's removed, light
  lemmatisation (Norm is idempotent). Vocabulary not limited. Extracted ONCE; every scheme uses them as-is.
Ground truth of keyword w in domain Di with n files:
  SELECT p.doc_id FROM postings p JOIN keywords k USING(keyword_id) JOIN documents d USING(doc_id)
  WHERE k.keyword = 'w' AND d.domain_id = 'Di' AND d.is_initial = 1 AND d.doc_id <= 'Di_<n, 6 digits>';

EXPERIMENT FILES (advisor's plan; all computed from the keywords above)
queries_search_single.jsonl  Search 1.1/1.2: AND queries inside one domain; keywords of one anchor file among the
                             first {anchor} files (never empty at any size). result_size = exact plaintext result
                             count per files-per-domain ({points}).
queries_boolean_multi.jsonl  Search 2.1: AND, OR, (A OR B) AND (C OR D), (A AND B) OR (C AND D); keywords from files
                             of different domains. result_size_per_domain = exact counts per domain and size.
                             "text" uses AMTP query syntax (multi-word keywords in double quotes).
domain_groups.csv            Search 2.2 / Verify 2.2: arXiv primary category -> group for D = 1,2,4,8,16,32
                             (D < {D}: whole domains merged; D >= {D}: categories of each domain split, balanced).
verify_keywords.csv          Verify 1.1/2.1: the 5 real keywords whose result size is closest to 10/100/1,000/10,000,
                             per domain and size; multi_domain = keywords present in every domain.
tamper_sets.jsonl            Verify 1.2: one keyword per domain with ~2,000 results (>= 2 x largest t); tamper the first t doc_ids of
                             tamper_order for t in tamper_counts (nested, seeded).
delete_order.csv             seeded deletion order per domain (update and split/merge experiments).
Total size N over all domains = the first N/{D} files of every domain (baselines/amtp_dataset.py sample(N)).
"""

DOWNLOAD_INFO = """AMTP dataset-v4 - source information
====================================

Source          : Kaggle - Cornell-University/arxiv  (https://www.kaggle.com/datasets/Cornell-University/arxiv)
File            : arxiv-metadata-oai-snapshot.json
File date       : {file_date} (date of the file on disk)
Newest paper    : update_date {newest} (latest record in this snapshot)
Records (papers): {records}
File size       : {size} bytes
MD5             : {md5}

Selection       : datasets/arxiv/select_files_v4.py (seed 42): domains {doms};
                  {n} initial files + {pool} insert-pool files per domain, title + abstract >= 30 words,
                  chronological doc_id order.
Keywords        : v4 = AMTP Phase 1 code (amtp_code/amtp/nlp.py), kappa={kappa} -> datasets/arxiv/build_v4.py

How to check you have the same file:
  Mac/Linux : md5 arxiv-metadata-oai-snapshot.json      (or: md5sum ...)
  Windows   : certutil -hashfile arxiv-metadata-oai-snapshot.json MD5

For the paper (Dataset section):
  "We use the arXiv metadata snapshot from Kaggle (Cornell University; latest record dated {newest};
   {records} papers). We sample {n} papers per domain ({doms}) with seed 42 and extract
   at most {kappa} keywords per paper with RAKE (AMTP Phase 1)."
"""

if __name__ == "__main__":
    main()
