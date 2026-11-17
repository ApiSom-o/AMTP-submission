#!/usr/bin/env python3
"""
select_files_v4.py  (dataset-v4, step 1 of 3)
=============================================
Picks the 550,000 real arXiv papers of dataset-v4 and writes their .txt files (title + abstract):
    4 domains (cs, math, astro-hep, condmat-quant) x 125,000 initial files + 12,500 insert-pool files, seed 42,
    abstract >= 30 words, not withdrawn, chronological doc_id order.

The keywords this script writes (its own simple RAKE, documents_D*.csv) are NOT the dataset-v4 keywords.
Step 2, datasets/arxiv/build_v4.py, re-extracts W(d) of every .txt with AMTP's Phase 1 code
(amtp_code/amtp/nlp.py, kappa = 20) and writes the final documents.csv / experiment files.

    python3 datasets/arxiv/select_files_v4.py arxiv-metadata-oai-snapshot.json --count-only
    python3 datasets/arxiv/select_files_v4.py arxiv-metadata-oai-snapshot.json --out ~/amtp_dataset
    python3 datasets/arxiv/build_v4.py --src ~/amtp_dataset --out ~/amtp_file_db_v4 --arxiv-json arxiv-metadata-oai-snapshot.json
    python3 datasets/arxiv/pack.py --src ~/amtp_file_db_v4

Standard library only. Disk ~15 GB, RAM ~4 GB.

The experiment files below are also rebuilt by build_v4.py from the v4 keywords (use those, not these).
Mapping to the AMTP paper / advisor's experiment plan:
    files/ + amtp_plaintext.db     d, W(d) for every document                (Phase 1)
    first n doc_ids of a domain    database of n documents (chronological prefix, nested)
    queries_search_single.jsonl    Search 1.1 / 1.2   multi-keyword AND, single domain
    queries_boolean_multi.jsonl    Search 2.1         AND / OR / nested, keywords from several domains
    domain_groups.csv              Search 2.2 / Verify 2.2   D = 1, 2, 4, 8, 16, 32 domains
    verify_keywords.csv            Verify 1.1 / 2.1   real keywords whose result size is near 10/100/1k/10k
    tamper_sets.jsonl              Verify 1.2         which returned files to tamper (nested, seeded)
    insert_pool/ + delete_order.csv  Split/merge and update experiments
"""

import argparse
import csv
import json
import os
import random
import re
import sqlite3
import sys
import time
from array import array
from bisect import bisect_left
from collections import Counter, defaultdict
from email.utils import parsedate_to_datetime

# --------------------------------------------------------------------------
# Domains: arXiv primary category (first entry of "categories") -> domain group
# --------------------------------------------------------------------------
ASTRO_HEP = {"astro-ph", "gr-qc", "hep-ex", "hep-lat", "hep-ph", "hep-th", "nucl-ex", "nucl-th"}
CONDMAT_QUANT = {
    "cond-mat", "quant-ph", "physics", "math-ph", "nlin", "acc-phys", "ao-sci", "atom-ph", "chem-ph",
    "plasm-ph", "supr-con", "mtrl-th", "chao-dyn", "patt-sol", "solv-int", "adap-org", "comp-gas",
}
GROUPS = {
    "cs": {"cs", "cmp-lg"},
    "math": {"math", "alg-geom", "dg-ga", "funct-an", "q-alg"},
    "astro-hep": ASTRO_HEP,                  # astrophysics, gravity, high-energy & nuclear physics
    "condmat-quant": CONDMAT_QUANT,          # condensed matter, quantum, general & math physics
    "physics": ASTRO_HEP | CONDMAT_QUANT,    # all physics (old grouping)
    "stat": {"stat"},
    "eess": {"eess"},
    "q-bio": {"q-bio"},
    "q-fin": {"q-fin"},
    "econ": {"econ"},
}


def group_of(primary, wanted):
    archive = primary.split(".")[0]
    for g in wanted:
        if archive in GROUPS[g]:
            return g
    return None


# --------------------------------------------------------------------------
# RAKE keyword extraction (Rose et al., 2010) -- fixed parameters, stdlib only
# --------------------------------------------------------------------------
STOPWORDS = frozenset("""
a about above across after afterwards again against all almost alone along already also although always am among amongst
an and another any anyhow anyone anything anyway anywhere are around as at back be became because become becomes becoming
been before beforehand behind being below beside besides between beyond both but by can cannot could did do does doing done
down due during each eg either else elsewhere enough etc even ever every everyone everything everywhere except few first for
former formerly from further get gets getting give given go going gone got had has have having he hence her here hereafter
hereby herein hereupon hers herself him himself his how however i ie if in inc indeed into is it its itself just keep last
latter latterly least less let lets like likely ltd made make many may me meanwhile might mine more moreover most mostly
much must my myself namely neither never nevertheless next no nobody none noone nor not nothing now nowhere of off often on
once one only onto or other others otherwise our ours ourselves out over own per perhaps please put rather re really said
same see seem seemed seeming seems several she should since so some somehow someone something sometime sometimes somewhere
still such take than that the their theirs them themselves then thence there thereafter thereby therefore therein thereupon
these they thing things this those though through throughout thru thus to together too toward towards under until up upon
us use used using very via want was we well were what whatever when whence whenever where whereafter whereas whereby wherein
whereupon wherever whether which while whither who whoever whole whom whose why will with within without would yet you
your yours yourself yourselves
paper article work propose proposed proposes show shows shown showed present presents presented demonstrate demonstrates
obtain obtained consider considered based new novel recent recently known various different several respectively
study studies studied investigate investigated discuss discussed
""".split())

LATEX_MATH = re.compile(r"\$[^$]*\$|\\\(.*?\\\)|\\\[.*?\\\]", re.S)
LATEX_CMD = re.compile(r"\\[a-zA-Z]+\*?(\{[^}]*\})?")
PHRASE_SPLIT = re.compile(r"[.!?,;:\"()\[\]{}<>|/\\=*_+~`#&%$@^\t]+|\s[-]+\s")
TOKEN = re.compile(r"[a-z0-9']+")


def rake(text, top_k, max_words, min_word_len):
    """Top-k RAKE phrases, normalized (lowercase, single-spaced), deterministic order."""
    text = LATEX_CMD.sub(" , ", LATEX_MATH.sub(" , ", text))
    text = re.sub(r"\s+", " ", text.lower())
    phrases = []
    for frag in PHRASE_SPLIT.split(text):
        cur = []
        for tok in TOKEN.findall(frag) + [None]:
            t = tok.strip("'") if tok else None
            if t is None or t in STOPWORDS or len(t) < min_word_len or not t.isalpha():
                if cur and len(cur) <= max_words:
                    phrases.append(tuple(cur))
                cur = []
            else:
                cur.append(t)
    if not phrases:
        return []
    freq, degree = Counter(), Counter()
    for p in phrases:
        for w in p:
            freq[w] += 1
            degree[w] += len(p)
    score = {w: degree[w] / freq[w] for w in freq}
    ranked = sorted({" ".join(p): sum(score[w] for w in p) for p in set(phrases)}.items(),
                    key=lambda kv: (-kv[1], kv[0]))
    return [k for k, _ in ranked[:top_k]]


def clean(s):
    return re.sub(r"\s+", " ", (s or "")).strip()


def created_date(rec):
    try:
        return parsedate_to_datetime(rec["versions"][0]["created"]).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return (rec.get("update_date") or "") + " 00:00:00"


def eligible(rec, min_words):
    abstract = clean(rec.get("abstract"))
    return len(abstract.split()) >= min_words and "withdrawn" not in abstract.lower()[:200]


def shard_path(sub, dom, g, doc_id, n):
    return "%s/%s_%s/%04d/%s.txt" % (sub, dom, g, (n - 1) // 10_000, doc_id)


def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


# --------------------------------------------------------------------------
# Per-domain plaintext index (positions = 0-based chronological index of initial files)
# --------------------------------------------------------------------------
class DomainIndex:
    def __init__(self, dom, name, doc_kws, cats):
        self.dom, self.name = dom, name
        self.doc_kws = doc_kws          # list[list[str]], position -> keywords
        self.cats = cats                # list[str], position -> primary category
        post = defaultdict(lambda: array("i"))
        for p, kws in enumerate(doc_kws):
            for k in kws:
                post[k].append(p)      # appended in increasing p -> sorted
        self.post = dict(post)
        self.n = len(doc_kws)

    def doc_id(self, p):
        return "%s_%06d" % (self.dom, p + 1)

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
    """items: list of (name, weight) -> list of bin index per name, balanced by weight."""
    load = [0] * k
    out = {}
    for name, w in sorted(items, key=lambda x: (-x[1], x[0])):
        j = min(range(k), key=lambda b: (load[b], b))
        out[name] = j
        load[j] += w
    return out, load


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Build the shared AMTP plaintext dataset from Kaggle arXiv")
    ap.add_argument("arxiv_json", help="arxiv-metadata-oai-snapshot.json")
    ap.add_argument("--out", default="amtp_file_db")
    ap.add_argument("--domains", default="cs,math,astro-hep,condmat-quant",
                    help="comma-separated groups: " + ", ".join(GROUPS))
    ap.add_argument("--per-domain", type=int, default=125_000, help="initial files per domain")
    ap.add_argument("--extra-frac", type=float, default=0.10, help="insert pool size as a fraction of --per-domain")
    ap.add_argument("--points", default="10000,25000,50000,75000,100000,125000",
                    help="per-domain database sizes used for ground truth and stats")
    ap.add_argument("--scales", default="10000,50000,100000,200000,400000,500000",
                    help="total sizes N for scale_N.csv (N / #domains per domain)")
    ap.add_argument("--count-only", action="store_true", help="only count eligible papers per group, then stop")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--top-k", type=int, default=20, help="RAKE: max keywords per file (kappa)")
    ap.add_argument("--max-words", type=int, default=3, help="RAKE: max words per keyword phrase")
    ap.add_argument("--min-word-len", type=int, default=3, help="RAKE: min letters per word")
    ap.add_argument("--min-abstract-words", type=int, default=30)
    ap.add_argument("--queries-per-k", type=int, default=20)
    ap.add_argument("--kq-single", default="1,2,5,10,15,20", help="Search 1.1 keywords per AND query")
    ap.add_argument("--kq-boolean", default="2,4,8,16", help="Search 2.1 keywords per Boolean query")
    ap.add_argument("--anchor-n", type=int, default=10_000,
                    help="queries are anchored on files among the first n of a domain, so they stay valid at every size")
    ap.add_argument("--targets", default="10,100,1000,10000", help="Verify 1.1/2.1 target result sizes")
    ap.add_argument("--tamper", default="5,10,20,40,100,1000", help="Verify 1.2 numbers of tampered files")
    args = ap.parse_args()

    domains = list(GROUPS) if args.count_only else [d.strip() for d in args.domains.split(",") if d.strip()]
    for d in domains:
        if d not in GROUPS:
            sys.exit("Unknown domain group '%s'. Choose from: %s" % (d, ", ".join(GROUPS)))
    if not args.count_only:
        overlap = [(a, b) for i, a in enumerate(domains) for b in domains[i + 1:] if GROUPS[a] & GROUPS[b]]
        if overlap:
            sys.exit("Domain groups overlap: %s" % overlap)
    extra = int(round(args.per_domain * args.extra_frac))
    need = args.per_domain + extra
    points = sorted({min(int(x), args.per_domain) for x in args.points.split(",") if x.strip()})
    if args.per_domain not in points:
        points.append(args.per_domain)
    anchor_n = min(args.anchor_n, args.per_domain)
    t_start = time.time()

    # ---- Pass 1: byte offsets of every eligible paper, per group ----
    print("Pass 1/2: scanning %s (about 2.8M papers) ..." % args.arxiv_json)
    offsets = {g: [] for g in domains}
    lines = 0
    with open(args.arxiv_json, "rb") as f:
        while True:
            pos = f.tell()
            line = f.readline()
            if not line:
                break
            lines += 1
            if lines % 500_000 == 0:
                print("  %d papers scanned" % lines)
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            cats = (rec.get("categories") or "").split()
            if not cats or not eligible(rec, args.min_abstract_words):
                continue
            if args.count_only:
                archive = cats[0].split(".")[0]
                for g in domains:
                    if archive in GROUPS[g]:
                        offsets[g].append(pos)
                continue
            g = group_of(cats[0], domains)
            if g:
                offsets[g].append(pos)
    counts = {g: len(v) for g, v in offsets.items()}
    print("Eligible papers per group (need %d each):" % need)
    for g in domains:
        print("  %-14s %9d %s" % (g, counts[g], "" if counts[g] >= need else "  (not enough)"))
    if args.count_only:
        return
    short = [g for g in domains if counts[g] < need]
    if short:
        sys.exit("Not enough papers in %s. Lower --per-domain or change --domains." % short)

    # ---- Output + database ----
    os.makedirs(args.out, exist_ok=True)
    db_path = os.path.join(args.out, "amtp_plaintext.db")
    if os.path.exists(db_path):
        os.remove(db_path)
    con = sqlite3.connect(db_path)
    con.execute("PRAGMA journal_mode=OFF")
    con.execute("PRAGMA synchronous=OFF")
    con.executescript("""
        CREATE TABLE domains  (domain_id TEXT PRIMARY KEY, name TEXT, arxiv_archives TEXT,
                               initial_files INTEGER, insert_pool_files INTEGER);
        CREATE TABLE documents(doc_id TEXT PRIMARY KEY, domain_id TEXT, is_initial INTEGER, position INTEGER,
                               file_path TEXT, arxiv_id TEXT, title TEXT, primary_category TEXT, categories TEXT,
                               created TEXT, n_keywords INTEGER, content TEXT);
        CREATE TABLE keywords (keyword_id INTEGER PRIMARY KEY, keyword TEXT UNIQUE);
        CREATE TABLE postings (keyword_id INTEGER, doc_id TEXT, PRIMARY KEY (keyword_id, doc_id)) WITHOUT ROWID;
    """)

    kw_id = {}
    stats = {}
    indexes = {}
    rake_time, rake_files = 0.0, 0
    print("Pass 2/2: extracting keywords (RAKE) and writing files ...")
    with open(args.arxiv_json, "rb") as src:
        for di, g in enumerate(domains, 1):
            dom = "D%d" % di
            rng = random.Random("%d-%s" % (args.seed, g))
            cand = offsets[g]
            rng.shuffle(cand)
            chosen, no_kw, start = [], 0, 0
            while len(chosen) < need and start < len(cand):
                batch = cand[start:start + (need - len(chosen)) + 1000]
                start += len(batch)
                order = {p: i for i, p in enumerate(batch)}
                got = []
                for p in sorted(batch):
                    src.seek(p)
                    rec = json.loads(src.readline())
                    title, abstract = clean(rec.get("title")), clean(rec.get("abstract"))
                    text = title + "\n\n" + abstract
                    t0 = time.perf_counter()
                    kws = rake(text, args.top_k, args.max_words, args.min_word_len)
                    rake_time += time.perf_counter() - t0
                    rake_files += 1
                    if not kws:
                        no_kw += 1
                        continue
                    cats = rec["categories"].split()
                    got.append((order[p], (str(rec.get("id")), title, cats[0], " ".join(cats),
                                           created_date(rec), text, kws)))
                got.sort(key=lambda x: x[0])
                chosen.extend(x[1] for x in got[: need - len(chosen)])
            if len(chosen) < need:
                sys.exit("%s: only %d papers with keywords (need %d)." % (g, len(chosen), need))
            offsets[g] = None

            initial, pool = chosen[:args.per_domain], chosen[args.per_domain:]
            del chosen
            initial.sort(key=lambda x: (x[4], x[0]))     # chronological = insertion order = prefix order
            pool.sort(key=lambda x: (x[4], x[0]))

            for is_init, group, prefix, sub, width in [(1, initial, dom + "_", "files", 6),
                                                       (0, pool, dom + "_I", "insert_pool", 5)]:
                rows, post, new_kw = [], [], []
                csv_path = os.path.join(args.out, "documents_%s.csv" % dom)
                with open(csv_path, "w" if is_init else "a", newline="", encoding="utf-8-sig") as cf:
                    cw = csv.writer(cf)
                    if is_init:
                        cw.writerow(["doc_id", "domain_id", "domain_name", "is_initial", "position",
                                     "primary_category", "file_path", "arxiv_id", "n_keywords", "keywords"])
                    for n, (aid, title, prim, cats, created, text, kws) in enumerate(group, 1):
                        doc_id = "%s%0*d" % (prefix, width, n)
                        rel = shard_path(sub, dom, g, doc_id, n)
                        full = os.path.join(args.out, rel)
                        if n % 10_000 == 1:
                            os.makedirs(os.path.dirname(full), exist_ok=True)
                        with open(full, "w", encoding="utf-8", newline="\n") as fh:
                            fh.write(text + "\n")
                        for k in kws:
                            if k not in kw_id:
                                kw_id[k] = len(kw_id) + 1
                                new_kw.append((kw_id[k], k))
                            post.append((kw_id[k], doc_id))
                        posn = n if is_init else None
                        rows.append((doc_id, dom, is_init, posn, rel, aid, title, prim, cats, created, len(kws), text))
                        cw.writerow([doc_id, dom, g, is_init, posn or "", prim, rel, aid, len(kws), "; ".join(kws)])
                        if len(rows) >= 20_000:
                            con.executemany("INSERT INTO keywords VALUES (?,?)", new_kw)
                            con.executemany("INSERT INTO documents VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)
                            con.executemany("INSERT INTO postings VALUES (?,?)", post)
                            rows, post, new_kw = [], [], []
                    con.executemany("INSERT INTO keywords VALUES (?,?)", new_kw)
                    con.executemany("INSERT INTO documents VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)
                    con.executemany("INSERT INTO postings VALUES (?,?)", post)
            con.execute("INSERT INTO domains VALUES (?,?,?,?,?)",
                        (dom, g, ",".join(sorted(GROUPS[g])), len(initial), len(pool)))
            con.commit()

            idx = DomainIndex(dom, g, [x[6] for x in initial], [x[2] for x in initial])
            indexes[dom] = idx
            kpf = sorted(len(k) for k in idx.doc_kws)
            vocab_at = {}
            for N in points:
                dfs = [bisect_left(a, N) for a in idx.post.values()]
                dfs = [x for x in dfs if x > 0]
                vocab_at[str(N)] = {
                    "files": N,
                    "vocabulary": len(dfs),
                    "vocabulary_df_ge_2": sum(1 for x in dfs if x >= 2),
                    "keyword_file_pairs": sum(dfs),
                    "pairs_if_df1_removed": sum(x for x in dfs if x >= 2),
                    "max_doc_freq": max(dfs),
                }
            stats[dom] = {
                "name": g, "initial_files": len(initial), "insert_pool_files": len(pool),
                "eligible_papers_in_arxiv": counts[g], "skipped_no_keyword": no_kw,
                "keywords_per_file": {"mean": round(sum(kpf) / len(kpf), 2), "median": kpf[len(kpf) // 2],
                                      "min": kpf[0], "max": kpf[-1],
                                      "files_with_max_kappa": sum(1 for x in kpf if x == args.top_k)},
                "by_database_size": vocab_at,
                "created_range": [initial[0][4], initial[-1][4]],
                "primary_categories": len(set(idx.cats)),
            }
            v = vocab_at[str(args.per_domain)]
            print("  %s (%s): %d files + %d pool, vocabulary %d (%d with df>=2), %d keyword-file pairs"
                  % (dom, g, len(initial), len(pool), v["vocabulary"], v["vocabulary_df_ge_2"],
                     v["keyword_file_pairs"]))
            del initial, pool

    print("Building database indexes ...")
    con.executescript("""
        CREATE INDEX idx_postings_doc ON postings(doc_id);
        CREATE INDEX idx_documents_domain ON documents(domain_id, is_initial, position);
    """)
    con.commit()

    D = len(domains)
    doms = list(indexes)
    qrng = random.Random("%d-queries" % args.seed)

    # ---- Search 1.1 / 1.2: AND queries inside one domain ----
    kq_single = [int(x) for x in args.kq_single.split(",") if x.strip()]
    q_single, qid = [], 0
    for dom in doms:
        idx = indexes[dom]
        anchors = list(range(anchor_n))
        for k in kq_single:
            ok = [p for p in anchors if len(idx.doc_kws[p]) >= k]
            if not ok:
                print("  warning: no anchor file with >= %d keywords in %s" % (k, dom))
                continue
            for _ in range(args.queries_per_k):
                p = ok[qrng.randrange(len(ok))]
                kw = qrng.sample(sorted(idx.doc_kws[p]), k)
                e = build_expr("single" if k == 1 else "AND", kw)
                qid += 1
                q_single.append({
                    "query_id": "S1_%05d" % qid, "domain": dom, "kQ": k,
                    "shape": "single" if k == 1 else "AND", "expression": e, "text": expr_text(e),
                    "keywords": kw, "source_doc": idx.doc_id(p),
                    "result_size": counts_at(evaluate(e, idx), points),
                })
    write_jsonl(os.path.join(args.out, "queries_search_single.jsonl"), q_single)

    # ---- Search 2.1: Boolean queries whose keywords come from several domains ----
    kq_bool = [int(x) for x in args.kq_boolean.split(",") if x.strip()]
    q_bool, qid = [], 0

    def anchor(dom, need_k):
        idx = indexes[dom]
        for _ in range(500):
            p = qrng.randrange(anchor_n)
            if len(idx.doc_kws[p]) >= need_k:
                return p, sorted(idx.doc_kws[p])
        return None, None

    for k in kq_bool:
        for shape in ["AND", "OR", "AND_of_OR", "OR_of_AND"]:
            made = 0
            for _ in range(args.queries_per_k * 20):
                if made == args.queries_per_k:
                    break
                ds = qrng.sample(doms, min(2, D))
                if shape == "AND":
                    p, ks = anchor(ds[0], k)            # all keys from one file -> non-empty in that domain
                    if p is None:
                        continue
                    kw, src_docs = qrng.sample(ks, k), [indexes[ds[0]].doc_id(p)]
                elif shape == "OR":
                    kw, src_docs, ok = [], [], True     # keys spread over several domains
                    for j in range(k):
                        d = doms[(doms.index(ds[0]) + j) % D]
                        p, ks = anchor(d, 1)
                        if p is None:
                            ok = False
                            break
                        cand_k = [x for x in ks if x not in kw]
                        if not cand_k:
                            ok = False
                            break
                        kw.append(qrng.choice(cand_k))
                        src_docs.append(indexes[d].doc_id(p))
                    if not ok:
                        continue
                elif shape == "AND_of_OR":              # (A or B) and (C or D): A,C from file X, B,D from file Y
                    h = k // 2
                    px, kx = anchor(ds[0], h)
                    py, ky = anchor(ds[-1], h)
                    if px is None or py is None:
                        continue
                    a = qrng.sample(kx, h)
                    b = [x for x in qrng.sample(ky, len(ky)) if x not in a][:h]
                    if len(b) < h:
                        continue
                    kw = [x for pair in zip(a, b) for x in pair]
                    src_docs = [indexes[ds[0]].doc_id(px), indexes[ds[-1]].doc_id(py)]
                else:                                   # (A and B) or (C and D): each pair from one file
                    kw, src_docs, ok = [], [], True
                    for j in range(k // 2):
                        d = doms[(doms.index(ds[0]) + j) % D]
                        p, ks = anchor(d, 2)
                        if p is None:
                            ok = False
                            break
                        pair = [x for x in qrng.sample(ks, len(ks)) if x not in kw][:2]
                        if len(pair) < 2:
                            ok = False
                            break
                        kw += pair
                        src_docs.append(indexes[d].doc_id(p))
                    if not ok:
                        continue
                if len(set(kw)) != len(kw):
                    continue
                e = build_expr(shape, kw)
                qid += 1
                made += 1
                q_bool.append({
                    "query_id": "S2_%05d" % qid, "kQ": k, "shape": shape, "expression": e,
                    "text": expr_text(e), "keywords": kw, "source_docs": src_docs,
                    "result_size_per_domain": {d: counts_at(evaluate(e, indexes[d]), points) for d in doms},
                })
    write_jsonl(os.path.join(args.out, "queries_boolean_multi.jsonl"), q_bool)

    # ---- Verify 1.1 / 2.1: real keywords whose result size is near the targets ----
    targets = [int(x) for x in args.targets.split(",") if x.strip()]
    vrows = []
    for N in points:
        for dom in doms:
            idx = indexes[dom]
            dfl = [(k, bisect_left(a, N)) for k, a in idx.post.items()]
            for t in targets:
                best = sorted(dfl, key=lambda x: (abs(x[1] - t), x[0]))[:5]
                for rank, (k, df) in enumerate(best, 1):
                    vrows.append(["single_domain", dom, N, t, rank, k, df, df])
        common = set.intersection(*(set(indexes[d].post) for d in doms))
        tot = [(k, [indexes[d].df_at(k, N) for d in doms]) for k in common]
        for t in targets:
            best = sorted(tot, key=lambda x: (abs(sum(x[1]) - t), x[0]))[:5]
            for rank, (k, per) in enumerate(best, 1):
                vrows.append(["multi_domain", "+".join(doms), N, t, rank, k, sum(per), " ".join(map(str, per))])
    with open(os.path.join(args.out, "verify_keywords.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["setting", "domain", "files_per_domain", "target_results", "rank", "keyword",
                    "result_size", "result_size_per_domain"])
        w.writerows(vrows)

    # ---- Verify 1.2: files to tamper (nested, seeded) inside a ~1,000-result query ----
    tamper_k = [int(x) for x in args.tamper.split(",") if x.strip()]
    tN = 100_000 if 100_000 in points else max(points)
    trows = []
    trng = random.Random("%d-tamper" % args.seed)
    for dom in doms:
        idx = indexes[dom]
        k, df = min(((k, idx.df_at(k, tN)) for k in idx.post), key=lambda x: (abs(x[1] - 1000), x[0]))
        res = [idx.doc_id(p) for p in idx.post[k] if p < tN]
        perm = res[:]
        trng.shuffle(perm)
        trows.append({"domain": dom, "files_per_domain": tN, "query_keyword": k, "result_size": len(res),
                      "tamper_counts": [x for x in tamper_k if x <= len(res)],
                      "tamper_order": perm,
                      "note": "tamper the first t doc_ids of tamper_order for t in tamper_counts"})
    write_jsonl(os.path.join(args.out, "tamper_sets.jsonl"), trows)

    # ---- Search 2.2 / Verify 2.2: group arXiv categories into D = 1..32 domains ----
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
        for (dom, c), a in assign.items():
            sz[a[Dv]] += cat_count[dom][c]
        gsizes[str(Dv)] = dict(sorted(sz.items()))
    with open(os.path.join(args.out, "domain_groups.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["domain_id", "domain_name", "primary_category", "initial_files"] + ["D%d" % x for x in d_values])
        for (dom, c) in sorted(assign):
            w.writerow([dom, indexes[dom].name, c, cat_count[dom][c]] + [assign[(dom, c)][x] for x in d_values])
    con.execute("CREATE TABLE domain_groups (domain_id TEXT, primary_category TEXT, %s)"
                % ", ".join("D%d TEXT" % x for x in d_values))
    con.executemany("INSERT INTO domain_groups VALUES (%s)" % ",".join("?" * (2 + len(d_values))),
                    [[dom, c] + [assign[(dom, c)][x] for x in d_values] for (dom, c) in sorted(assign)])
    con.commit()
    con.close()

    # ---- Total-size manifests + deletion order ----
    scale_info = {}
    for N in sorted(int(x) for x in args.scales.split(",") if x.strip()):
        per = N // D
        if per > args.per_domain:
            continue
        with open(os.path.join(args.out, "scale_%d.csv" % N), "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["doc_id", "domain_id"])
            for dom in doms:
                w.writerows([indexes[dom].doc_id(p), dom] for p in range(per))
        scale_info[str(N)] = {"files": per * D, "per_domain": per}
    drng = random.Random("%d-delete" % args.seed)
    with open(os.path.join(args.out, "delete_order.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["domain_id", "order", "doc_id"])
        for dom in doms:
            ids = [indexes[dom].doc_id(p) for p in range(indexes[dom].n)]
            drng.shuffle(ids)
            w.writerows([dom, i + 1, x] for i, x in enumerate(ids))

    summary = {
        "source": "arXiv metadata snapshot (Kaggle: Cornell-University/arxiv); one file = title + abstract; all real",
        "seed": args.seed, "papers_scanned": lines,
        "total_initial_files": sum(s["initial_files"] for s in stats.values()),
        "total_insert_pool_files": sum(s["insert_pool_files"] for s in stats.values()),
        "distinct_keywords_all_domains": len(kw_id),
        "domains": stats,
        "keyword_extraction": {
            "method": "RAKE (run once; shared as-is by every scheme)", "top_k_per_file": args.top_k,
            "max_words_per_keyword": args.max_words, "min_word_len": args.min_word_len,
            "normalization": "LaTeX removed, lowercase, single-spaced, deduplicated per file; no stemming",
            "vocabulary_limit": "none",
            "mean_ms_per_file": round(1000 * rake_time / max(rake_files, 1), 4),
            "files_processed": rake_files,
        },
        "queries": {"search_single": len(q_single), "boolean_multi": len(q_bool),
                    "empty_search_single_at_max_size": sum(
                        1 for q in q_single if q["result_size"][str(max(points))] == 0)},
        "domain_group_sizes": gsizes,
        "scales": scale_info,
        "build_minutes": round((time.time() - t_start) / 60, 1),
    }
    with open(os.path.join(args.out, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    with open(os.path.join(args.out, "README.txt"), "w", encoding="utf-8") as f:
        f.write(README.format(n=args.per_domain, extra=extra, seed=args.seed, k=args.top_k, D=D,
                              doms=", ".join("%s=%s" % (d, indexes[d].name) for d in doms),
                              points=", ".join(map(str, points)), anchor=anchor_n))
    print("\nAll done in %.1f min -> %s" % ((time.time() - t_start) / 60, os.path.abspath(args.out)))


README = """AMTP shared plaintext dataset  (arXiv on Kaggle, seed {seed}, all documents real)
Domains: {doms}

FILES AND KEYWORDS
files/<domain>/<0000..>/   {n} plaintext files per domain (10,000 per subfolder). File = title + abstract.
                           doc_id order is chronological: the first n doc_ids of a domain ARE the database of size n
                           (D1_000001 .. D1_0n). Smaller databases are prefixes of larger ones, so results are nested.
insert_pool/<domain>/      {extra} more real files per domain, NOT in the initial set (insertions, split/merge).
documents_D*.csv           every file with its keywords (opens in Excel).
amtp_plaintext.db          SQLite, NOT encrypted: documents, keywords, postings (= W(d)), domains, domain_groups.
                           Ground truth for keyword w in domain Di with n files:
                           SELECT d.doc_id FROM postings p JOIN keywords k USING(keyword_id) JOIN documents d USING(doc_id)
                           WHERE k.keyword='w' AND d.domain_id='Di' AND d.is_initial=1 AND d.position<=n;
Keywords W(d): RAKE run once, at most {k} phrases per file (1-3 words), lowercase, LaTeX removed, no stemming,
vocabulary not limited. EVERY scheme uses these keywords as-is; extraction time is not part of any measurement.

EXPERIMENT FILES (advisor's plan)
queries_search_single.jsonl  Search 1.1/1.2: AND queries inside one domain, kQ in the file, anchored on one of the
                             first {anchor} files (so every query is valid at every size). result_size = exact plaintext
                             result count at each per-domain size ({points}).
queries_boolean_multi.jsonl  Search 2.1: AND, OR, (A OR B) AND (C OR D), (A AND B) OR (C AND D); keywords drawn from
                             files of different domains. result_size_per_domain = exact counts per domain and size.
domain_groups.csv            Search 2.2 / Verify 2.2: each arXiv primary category -> group for D = 1,2,4,8,16,32
                             (D < {D}: whole domains merged; D >= {D}: categories of each domain split, balanced by size;
                             groups can be uneven when one category is very large).
verify_keywords.csv          Verify 1.1/2.1: the 5 real keywords whose result size is closest to 10/100/1,000/10,000,
                             per domain and per size; multi_domain rows = keywords present in every domain (total + per domain).
tamper_sets.jsonl            Verify 1.2: one query keyword per domain with ~1,000 results; tamper the first t doc_ids of
                             tamper_order for each t in tamper_counts (nested, seeded).
delete_order.csv             seeded deletion order per domain (update and split/merge experiments).
scale_N.csv                  total size N = N/{D} first files of every domain.
summary.json                 numbers for the paper: files, vocabulary (and with df>=2), keyword-file pairs per size,
                             keywords per file, RAKE time per file, group sizes.
"""

if __name__ == "__main__":
    main()
