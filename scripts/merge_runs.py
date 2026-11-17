"""Merge the run folders of several machines into one, for baselines/plot_paper.py.

    python3 scripts/merge_runs.py OUT IN1 IN2 ...
    e.g. python3 scripts/merge_runs.py baselines/results/runs/paper_v from_cloud/w*/paper_v

Every machine writes the same file names (amtp/amtp_tamper_detection.csv for D1, D2 on one machine and D3, D4 on
another), so the folders cannot simply be copied together. For every CSV path found in any input:
  * the rows of all inputs are concatenated (columns = union, in first-seen order); a row that appears in two
    inputs exactly is kept once and reported (the same job run twice)
  * every input's manifest of that CSV is kept, as <name>.manifest.json = {"merged_from": [...]}
Other files (summary.md, figures) are copied with the machine folder name as a prefix when names collide;
logs go to OUT/logs/<input name>/.
Checks: every manifest must have the same git_commit, git_dirty false and the same amtp_gamma_v, otherwise
the merge stops (use --force to merge anyway and see the warnings).
"""
import argparse
import csv
import json
import os
import shutil
import sys


def label(path):
    """a short name for an input folder: its parent folder (w3 in from_cloud/w3/paper_v), else its own name"""
    path = os.path.abspath(path)
    return os.path.basename(os.path.dirname(path)) or os.path.basename(path)


def walk(root):
    for d, _, files in os.walk(root):
        for f in files:
            yield os.path.relpath(os.path.join(d, f), root)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out")
    ap.add_argument("inputs", nargs="+")
    ap.add_argument("--force", action="store_true", help="merge even if the manifests disagree")
    a = ap.parse_args()
    if os.path.exists(a.out) and os.listdir(a.out):
        sys.exit(f"{a.out} exists and is not empty")
    names = [label(p) for p in a.inputs]
    if len(set(names)) != len(names):
        names = [f"in{i + 1}" for i in range(len(a.inputs))]

    csvs, manifests, other = {}, {}, {}
    for name, root in zip(names, a.inputs):
        if not os.path.isdir(root):
            sys.exit(f"not a folder: {root}")
        for rel in walk(root):
            src = os.path.join(root, rel)
            if rel.split(os.sep)[0] == "logs" or rel.split(os.sep)[0] == "figures":
                if rel.split(os.sep)[0] == "logs":
                    other.setdefault(os.path.join("logs", name, *rel.split(os.sep)[1:]), []).append((name, src))
                continue
            if rel.endswith(".manifest.json") or os.path.basename(rel) == "manifest.json":
                manifests.setdefault(rel, []).append((name, src))
            elif rel.endswith(".csv"):
                csvs.setdefault(rel, []).append((name, src))
            else:
                other.setdefault(rel, []).append((name, src))

    # the same code and settings everywhere
    seen, problems = {}, []
    for rel, items in manifests.items():
        for name, src in items:
            with open(src, encoding="utf-8") as f:
                m = json.load(f)
            commit = m.get("git_commit")
            gamma = m.get("amtp_gamma_v", m.get("gamma_v"))
            if m.get("git_dirty"):
                problems.append(f"{name}/{rel}: git_dirty = true")
            seen.setdefault("commit", set()).add(commit)
            seen.setdefault("gamma_v", set()).add(gamma)
    for k, v in seen.items():
        if len(v) > 1:
            problems.append(f"different {k} across inputs: {sorted(map(str, v))}")
    for p in problems:
        print("WARNING:", p)
    if problems and not a.force:
        sys.exit("manifests disagree; fix the run or pass --force")

    os.makedirs(a.out, exist_ok=True)
    total = 0
    for rel, items in sorted(csvs.items()):
        cols, rows, keys, dups = [], [], set(), 0
        for name, src in items:
            with open(src, encoding="utf-8", newline="") as f:
                r = csv.DictReader(f)
                for c in r.fieldnames or []:
                    if c not in cols:
                        cols.append(c)
                for row in r:
                    key = tuple(sorted(row.items()))
                    if key in keys:
                        dups += 1
                        continue
                    keys.add(key)
                    rows.append(row)
        dst = os.path.join(a.out, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, cols, restval="")
            w.writeheader()
            w.writerows(rows)
        total += len(rows)
        print(f"{rel}: {len(rows)} rows from {', '.join(n for n, _ in items)}"
              + (f"  ({dups} duplicate rows dropped: the same job ran twice?)" if dups else ""))
    for rel, items in manifests.items():
        merged = []
        for name, src in items:
            with open(src, encoding="utf-8") as f:
                merged.append({"input": name, **json.load(f)})
        dst = os.path.join(a.out, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "w", encoding="utf-8") as f:
            json.dump(merged[0] if len(merged) == 1 else {"merged_from": merged}, f, indent=1, ensure_ascii=False)
    for rel, srcs in other.items():
        for name, src in srcs:
            d, b = os.path.split(rel)
            dst = os.path.join(a.out, d, b if len(srcs) == 1 else f"{name}_{b}")
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
    print(f"{len(csvs)} CSV files, {total} rows -> {a.out}")


if __name__ == "__main__":
    main()
