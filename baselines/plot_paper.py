"""
plot_paper.py
============================================================================
Figures of the paper's experiment plan (dataset-v4) from ONE run folder of scripts/aws_run_all.sh:

  python3 baselines/plot_paper.py baselines/results/runs/<run>        # -> <run>/figures/
  python3 baselines/plot_paper.py <run> --out <dir>

Input  <run>/<scheme>/<scheme>_<suite>.csv (scheme = amtp, chen, du, secollab) and <run>/amtp/splitmerge_*/.
Output png only, one folder per experiment:

  ex1_search/Search_1.1   x = keywords k_Q        (single domain)      y = server time | end-to-end time
  ex1_search/Search_1.2   x = files per domain    (single domain)      y = server time | end-to-end time
  ex1_search/Search_2.1   x = k_Q, one figure per query shape (multi-domain)  y = server | end-to-end
  ex1_search/Search_2.2   x = number of domains   (same files)         y = server time | end-to-end time
  ex2_verify/Verify_1.1   x = returned files      (single domain)      y = user verification time
  ex2_verify/Verify_1.2   x = tampered files t, one figure per attack  y = user verification time
  ex2_verify/Verify_2.1   x = returned files      (multi-domain)       y = user verification time
  ex2_verify/Verify_2.2   x = number of domains                        y = user verification time
  ex3_update              x = batch b (requests per epoch), insert | delete   y = update time per epoch
  ex4_split_merge         AMTP vs Static-MT vs Global-MT, per θ_max and across θ_max
  ex5_multidomain         x = number of domains, AMTP vs SE-COLLAB     y = end-to-end query time | update time

Each figure's subtitle states only the values held fixed. Each point = median over the queries (or keywords,
domains) of that point, each already the median of the run's reps; error bars = 25th-75th percentile across them.
Every plotted number is also written to <out>/figure_points.csv.
============================================================================
"""
import argparse
import csv
import glob
import json
import os
import statistics
import sys
import textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from matplotlib.ticker import FuncFormatter  # noqa: E402
from plot_results import (EXP4_STYLE, INK, INK2, NAME, STYLE, SURFACE, new_fig, ok, paper_line,  # noqa: E402
                          plt, rq_axis)

SCHEMES = ["amtp", "chen", "du", "secollab"]
SHAPES = {"AND": "A ∧ B ∧ …", "OR": "A ∨ B ∨ …", "AND_of_OR": "(A ∨ B) ∧ (C ∨ D) …",
          "OR_of_AND": "(A ∧ B) ∨ (C ∧ D) …"}
KINDS = {"modify": "modified files", "hide": "hidden files", "inject": "injected files",
         "old_version": "old versions of files"}
VARIANTS = ["AMTP", "Static-MT", "Global-MT", "Global-MT(v)"]   # a variant without rows is skipped
SEARCH_Y = [("server_total", "server", "Server time: search + proof (ms)"),
            ("end_to_end", "end_to_end", "End-to-end search time (ms)")]
POINTS = []


# ---------------------------------------------------------------- helpers
def load(run, scheme, suite):
    path = os.path.join(run, scheme, f"{scheme}_{suite}.csv")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load_all(run, suite, schemes=SCHEMES):
    return {s: rows for s in schemes if (rows := ok(load(run, s, suite)))}


def agg(rows, key, metric):
    """{x: (median, (down, up))} of float(metric) over the rows of each x = key(row)"""
    groups = {}
    for r in rows:
        if r.get(metric) not in (None, ""):
            groups.setdefault(key(r), []).append(float(r[metric]))
    out = {}
    for x, v in groups.items():
        m = statistics.median(v)
        if len(v) > 1:
            q1, _, q3 = statistics.quantiles(v, n=4, method="inclusive")
            out[x] = (m, (m - q1, q3 - m))
        else:
            out[x] = (m, (0.0, 0.0))
    return out


def line(ax, fig_id, pts, label, color, marker, ls="-"):
    """pts = {x: (y, (down, up))}"""
    if not pts:
        return False
    xs = sorted(pts)
    paper_line(ax, xs, [pts[x][0] for x in xs], [pts[x][1] for x in xs], color, marker, label, ls)
    for x in xs:
        y, (lo, hi) = pts[x]
        POINTS.append({"figure": fig_id, "series": label, "x": x, "y": round(y, 6),
                       "err_down": round(lo, 6), "err_up": round(hi, 6)})
    return True


def scheme_line(ax, fig_id, scheme, pts, label=None, ls="-"):
    color, marker = STYLE[scheme]
    return line(ax, fig_id, pts, label or NAME[scheme], color, marker, ls)


def fmt_int(v):
    return f"{int(v):,}"


def save(fig, ax, path, title, fixed, xlabel, ylabel, log_y=True, log_x=False, ticks=None):
    """title + one subtitle line with the fixed values only; png only"""
    if not ax.get_legend_handles_labels()[0]:
        plt.close(fig)
        return
    if log_x:
        rq_axis(ax, ticks)
        if ticks and min(ticks) >= 1000:                    # 10k, 25k, ... : large sizes never overlap
            ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v / 1000:g}k"))
    elif ticks:
        ax.set_xticks(ticks)
    if log_y:
        ax.set_yscale("log")
    sub = textwrap.wrap("fixed: " + fixed, 84)              # the fixed values only, wrapped to the plot width
    ax.set_title(title + "\n" * len(sub), fontsize=12.5, color=INK, loc="left")
    ax.text(0, 1.02, "\n".join(sub), transform=ax.transAxes, fontsize=9, color=INK2, va="bottom",
            in_layout=False)                               # never squeezes the axes
    ax.set_xlabel(xlabel, color=INK2, fontsize=11.5)
    ax.set_ylabel(ylabel, color=INK2, fontsize=11.5)
    ax.legend(frameon=False, fontsize=9, loc="best")
    fig.tight_layout()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fig.savefig(path + ".png", facecolor=SURFACE, dpi=200)
    plt.close(fig)
    print("->", os.path.relpath(path + ".png"))


def fig():
    f, ax = new_fig(6.4, 4.6)
    ax.tick_params(labelsize=10.5)
    return f, ax


def one(values, name):
    """the single value of a fixed parameter in the data (or 'a, b' if several)"""
    values = sorted(set(values))
    return ", ".join(fmt_int(v) if isinstance(v, int) else str(v) for v in values) or "?"


# ---------------------------------------------------------------- ex1 / ex2
def search1(run, out):
    data = load_all(run, "search_single")
    if not data:
        return
    rows = [r for rs in data.values() for r in rs]
    ns = sorted({int(r["N"]) for r in rows})
    by_n = {n: {int(r["kQ"]) for r in rows if int(r["N"]) == n} for n in ns}
    n_fix = max(ns, key=lambda n: (len(by_n[n]), n))                 # the size where every k_Q was run
    kqs_all = sorted({int(r["kQ"]) for r in rows})
    kq_fix = max(kqs_all, key=lambda k: (sum(1 for n in ns if k in by_n[n]), -k))  # the k_Q run at every size
    doms = one([r["domain"] for r in rows], "domain")
    for col, tag, ylabel in SEARCH_Y:
        f, ax = fig()
        for s, rs in data.items():
            scheme_line(ax, f"S1.1_{tag}", s, agg([r for r in rs if int(r["N"]) == n_fix],
                                                    lambda r: int(r["kQ"]), f"{col}_ms_median"))
        save(f, ax, os.path.join(out, "ex1_search", "Search_1.1", f"{tag}_vs_kQ"),
             "Search 1.1 · single domain · vary keywords",
             f"{n_fix:,} files per domain · AND query · median over domains {doms}",
             "Keywords in the AND query $k_Q$", ylabel, ticks=sorted(by_n[n_fix]))
        f, ax = fig()
        for s, rs in data.items():
            scheme_line(ax, f"S1.2_{tag}", s, agg([r for r in rs if int(r["kQ"]) == kq_fix],
                                                    lambda r: int(r["N"]), f"{col}_ms_median"))
        save(f, ax, os.path.join(out, "ex1_search", "Search_1.2", f"{tag}_vs_files"),
             "Search 1.2 · single domain · vary files",
             f"$k_Q$ = {kq_fix} · AND query · median over domains {doms}",
             "Files in the domain", ylabel, log_x=True, ticks=ns)


def search21(run, out):
    data = load_all(run, "search_multi", ["amtp", "secollab"])
    if not data:
        return
    rows = [r for rs in data.values() for r in rs]
    nfix = one([int(r["N_per_domain"]) for r in rows], "N")
    dcount = one([int(r["domains"]) for r in rows], "D")
    for shape in [s for s in SHAPES if any(r["shape"] == s for r in rows)]:
        kqs = sorted({int(r["kQ"]) for r in rows if r["shape"] == shape})
        for col, tag, ylabel in SEARCH_Y:
            f, ax = fig()
            for s, rs in data.items():
                scheme_line(ax, f"S2.1_{shape}_{tag}", s, agg([r for r in rs if r["shape"] == shape],
                                                               lambda r: int(r["kQ"]), f"{col}_ms_median"))
            save(f, ax, os.path.join(out, "ex1_search", "Search_2.1", f"{tag}_vs_kQ_{shape}"),
                 f"Search 2.1 · multi-domain · {SHAPES[shape]}",
                 f"{dcount} domains · {nfix} files per domain · query shape {shape}",
                 "Keywords in the query $k_Q$", ylabel, ticks=kqs)


def xdomains(run, out):
    """Search 2.2 (server, end-to-end) and Verify 2.2 (verification) from domains_scaling"""
    data = load_all(run, "domains_scaling", ["amtp", "secollab"])
    if not data:
        return
    rows = [r for rs in data.values() for r in rs]
    ds = sorted({int(r["domains"]) for r in rows})
    fixed = (f"{one([int(r['N_total']) for r in rows], 'N')} files in total · "
             f"$k_Q$ = {one([int(r['kQ']) for r in rows], 'kQ')} · shape {one([r['shape'] for r in rows], 's')}")
    for col, tag, ylabel, item, folder in SEARCH_Y_X:
        f, ax = fig()
        for s, rs in data.items():
            scheme_line(ax, f"{item}_{tag}", s, agg(rs, lambda r: int(r["domains"]), f"{col}_ms_median"))
        save(f, ax, os.path.join(out, folder, tag + "_vs_domains"),
             f"{item} · multi-domain · vary domains", fixed, "Number of domains D", ylabel, log_x=True, ticks=ds)


SEARCH_Y_X = [("server_total", "server", "Server time: search + proof (ms)", "Search 2.2", "ex1_search/Search_2.2"),
              ("end_to_end", "end_to_end", "End-to-end search time (ms)", "Search 2.2", "ex1_search/Search_2.2"),
              ("verify_total", "verify", "User verification time (ms)", "Verify 2.2", "ex2_verify/Verify_2.2")]


def verify_rq(run, out, multi):
    suite, item, ncol = ("verify_multi", "Verify 2.1", "N_per_domain") if multi else \
        ("verify_single", "Verify 1.1", "N")
    data = load_all(run, suite, ["amtp", "secollab"] if multi else SCHEMES)
    if not data:
        return
    rows = [r for rs in data.values() for r in rs]
    # x = the real result size: median r_Q of the keywords of each target group
    real = {t: statistics.median(int(r["rQ"]) for r in rows if int(r["target_results"]) == t and r.get("rQ"))
            for t in {int(r["target_results"]) for r in rows}}
    f, ax = fig()
    for s, rs in data.items():
        scheme_line(ax, f"{item}_verify", s, agg(rs, lambda r: real[int(r["target_results"])],
                                                  "verify_total_ms_median"))
    where = (f"{one([int(r['domains']) for r in rows], 'D')} domains · "
             f"{one([int(r[ncol]) for r in rows], 'N')} files per domain") if multi else \
        f"one domain · {one([int(r[ncol]) for r in rows], 'N')} files · median over domains " \
        f"{one([r['domain'] for r in rows], 'd')}"
    save(f, ax, os.path.join(out, "ex2_verify", item.replace(" ", "_"), "verify_vs_results"),
         f"{item} · {'multi-domain' if multi else 'single domain'} · vary returned files", where,
         "Returned files $r_Q$ (median per target group)", "User verification time (ms)",
         log_x=True, ticks=sorted(real.values()))


def tamper(run, out):
    data = {s: load(run, s, "tamper_detection") for s in SCHEMES}
    data = {s: rs for s, rs in data.items() if rs}
    if not data:
        return
    rows = [r for rs in data.values() for r in ok(rs)]
    fixed_base = (f"one domain · {one([int(r['N']) for r in rows], 'N')} files · one keyword with "
                  f"~{statistics.median(int(r['rQ']) for r in rows if r.get('rQ')):,.0f} results · "
                  f"median over domains {one([r['domain'] for r in rows], 'd')}")
    for kind, label in KINDS.items():
        f, ax = fig()
        ts, na = set(), []
        for s, rs in data.items():
            rk = [r for r in rs if r["tamper"] == kind and int(r["tampered"]) > 0]
            if s == "secollab":
                rk = [r for r in rk if r.get("check_mode", "early") == "early"]
            good = ok(rk)
            if not good:
                if rk:
                    na.append(NAME[s])
                continue
            pts = agg(good, lambda r: int(r["tampered"]), "verify_total_ms_median")
            ts |= set(pts)
            missed = sum(int(r["detected_runs"]) for r in good) == 0
            scheme_line(ax, f"V1.2_{kind}", s, pts, NAME[s] + (" (not detected)" if missed else ""))
        save(f, ax, os.path.join(out, "ex2_verify", "Verify_1.2", f"verify_vs_t_{kind}"),
             f"Verify 1.2 · single domain · t {label}",
             fixed_base + (f" · N/A: {', '.join(na)}" if na else ""),
             f"Tampered files t ({label})", "User verification time (ms)", log_x=True, ticks=sorted(ts))


# ---------------------------------------------------------------- ex3
def update(run, out):
    data = {"amtp": ok(load(run, "amtp", "exp3_dynamic_update")), "chen": ok(load(run, "chen", "exp3_dynamic_update"))}
    data = {s: rs for s, rs in data.items() if rs}
    if not data:
        return
    rows = [r for rs in data.values() for r in rs]
    bs = sorted({int(r["batch"]) for r in rows})
    for op in ("insert", "delete"):
        f, ax = fig()
        for s, rs in data.items():
            scheme_line(ax, f"ex3_{op}", s, agg([r for r in rs if r["op"] == op], lambda r: int(r["batch"]),
                                                "update_ms_median"))
        save(f, ax, os.path.join(out, "ex3_update", f"update_vs_b_{op}"),
             f"Update cost · {op} b files in one epoch",
             f"N = {one([int(r['N']) for r in rows], 'N')} files · {op}",
             "Requests per epoch b", "Update time per epoch (ms)", log_x=True, ticks=bs)


# ---------------------------------------------------------------- ex4
def read_csv(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def splitmerge(run, out):
    # several folders may hold the same θ (e.g. splitmerge_n100000_t64 and splitmerge_n100000_t64_gmtv, a variant
    # run on another machine with the same seed): their rows are drawn together
    groups = {}
    for d in sorted(glob.glob(os.path.join(run, "amtp", "splitmerge_*"))):
        man = {}
        if os.path.exists(os.path.join(d, "manifest.json")):
            with open(os.path.join(d, "manifest.json"), encoding="utf-8") as f:
                man = json.load(f)
        args = man.get("args", man)
        theta = int(args.get("theta_max") or os.path.basename(d).split("_t", 1)[-1].split("_")[0])
        rows = [read_csv(os.path.join(d, n)) for n in ("updates.csv", "layout.csv", "queries.csv")]
        if not rows[0]:
            continue
        g = groups.setdefault(theta, {"args": args, "rows": [[], [], []]})
        for acc, r in zip(g["rows"], rows):
            acc += r
    per_theta = {}
    for theta, g in sorted(groups.items()):
        args, (upd, lay, qry) = g["args"], g["rows"]
        per_theta[theta] = (upd, qry)
        fixed = (f"θ_max = {theta}, θ_min = {args.get('theta_min', theta // 4)} · start "
                 f"{fmt_int(args['n']) if 'n' in args else '?'} files · b = {args.get('batch_size', '?')} · "
                 f"skew {args.get('skews', '?')} · then delete {args.get('hot_delete_frac', '?')} of the hot group")
        sub = os.path.join(out, "ex4_split_merge", f"theta_{theta}")
        nb = max(int(r["batch"]) for r in upd) + 1
        width = max(1, nb // 50)                                 # 50 points: median over runs and `width` batches
        f, ax = fig()
        for v in VARIANTS:
            c, m, ls = EXP4_STYLE[v]
            line(ax, f"ex4_t{theta}_update", agg([r for r in upd if r["variant"] == v],
                                                 lambda r: int(r["batch"]) // width * width, "update_ms"), v, c, m, ls)
        save(f, ax, os.path.join(sub, "update_vs_batch"), "Split / merge · update cost per batch (Cloud Server)",
             fixed, "Batch (one epoch of b updates" + (f"; median of {width} batches)" if width > 1 else ")"),
             "Update time per batch (ms)")
        for metric, tag, ylabel in (("server_ms", "query_server", "Server time: search + proof (ms)"),
                                    ("verify_ms", "query_verify", "User verification time (ms)")):
            f, ax = fig()
            for v in VARIANTS:
                c, m, ls = EXP4_STYLE[v]
                line(ax, f"ex4_t{theta}_{tag}", agg([r for r in qry if r["variant"] == v],
                                                    lambda r: int(r["batch"]), metric), v, c, m, ls)
            save(f, ax, os.path.join(sub, f"{tag}_vs_batch"), "Split / merge · query cost during the updates",
                 fixed, "Batch", ylabel)
        f, ax = fig()
        for v in VARIANTS:
            c, m, ls = EXP4_STYLE[v]
            line(ax, f"ex4_t{theta}_maxpart", agg([r for r in lay if r["variant"] == v],
                                                  lambda r: int(r["batch"]), "max_partition"), v, c, m, ls)
        save(f, ax, os.path.join(sub, "max_partition_vs_batch"), "Split / merge · largest partition",
             fixed, "Batch", "Files in the largest partition")
    if len(per_theta) > 1:
        thetas = sorted(per_theta)
        for tag, src, metric, ylabel in (("update", 0, "update_ms", "Update time per batch (ms)"),
                                         ("query_server", 1, "server_ms", "Server time: search + proof (ms)")):
            f, ax = fig()
            for v in VARIANTS:
                c, m, ls = EXP4_STYLE[v]
                pts = {}
                for t in thetas:
                    a = agg([r for r in per_theta[t][src] if r["variant"] == v], lambda r: t, metric)
                    pts.update(a)
                line(ax, f"ex4_{tag}_vs_theta", pts, v, c, m, ls)
            save(f, ax, os.path.join(out, "ex4_split_merge", f"{tag}_vs_theta"),
                 "Split / merge · vary θ_max", "θ_min = θ_max / 4 · same workload for every θ_max",
                 "θ_max (files per partition)", ylabel, log_x=True, ticks=thetas)


# ---------------------------------------------------------------- ex5
def exp5(run, out):
    data = load_all(run, "exp5_domains", ["amtp", "secollab"])
    if not data:
        return
    rows = [r for rs in data.values() for r in rs]
    ds = sorted({int(r["domains"]) for r in rows})
    nt = one([int(r["N_target"]) for r in rows], "N")
    f, ax = fig()
    for s, rs in data.items():
        scheme_line(ax, "ex5_query", s, agg([r for r in rs if r["op"] == "query"], lambda r: int(r["domains"]),
                                            "end_to_end_ms_median"))
    save(f, ax, os.path.join(out, "ex5_multidomain", "query_vs_domains"), "Multi-domain scalability · query",
         f"target domain of {nt} files · same queries at every D", "Number of domains D",
         "End-to-end query time (ms)", log_x=True, ticks=ds)
    f, ax = fig()
    for s, rs in data.items():
        scheme_line(ax, "ex5_update", s, agg([r for r in rs if r["op"] == "update_one_domain"],
                                             lambda r: int(r["domains"]), "update_ms_median"))
    na = [NAME[s] for s in ("amtp", "secollab")                     # rows marked N/A (SE-COLLAB has no update)
          if any(r.get("op") == "update_one_domain" and r.get("status") == "N/A" for r in load(run, s, "exp5_domains"))]
    save(f, ax, os.path.join(out, "ex5_multidomain", "update_vs_domains"),
         "Multi-domain scalability · update one domain",
         f"target domain of {nt} files · b = 1" + (f" · N/A: {', '.join(na)}" if na else ""),
         "Number of domains D", "Update time per epoch (ms)", log_x=True, ticks=ds)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run", help="one run folder of scripts/aws_run_all.sh (baselines/results/runs/<run>)")
    ap.add_argument("--out", default=None, help="figure folder (default <run>/figures)")
    a = ap.parse_args()
    out = a.out or os.path.join(a.run, "figures")
    search1(a.run, out)
    search21(a.run, out)
    xdomains(a.run, out)
    verify_rq(a.run, out, multi=False)
    tamper(a.run, out)
    verify_rq(a.run, out, multi=True)
    update(a.run, out)
    splitmerge(a.run, out)
    exp5(a.run, out)
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "figure_points.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, ["figure", "series", "x", "y", "err_down", "err_up"])
        w.writeheader()
        w.writerows(POINTS)
    print(f"{len(POINTS)} points -> {os.path.relpath(os.path.join(out, 'figure_points.csv'))}")


if __name__ == "__main__":
    main()
