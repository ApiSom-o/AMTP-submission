#!/usr/bin/env bash
# Search-only run of AMTP (bench_split): search1, xsearch, xdomains with every query flag on (as plan "prune"),
# placement fill, reps 15 / warmup 3, then the search-only figures. One machine, ~3.5 h on r7i.
#
#   RUN_NAME=paper_split bash amtp_code/bench_split/run_cloud.sh          # results: baselines/results/runs/paper_split/
#   SMOKE=1 RUN_NAME=smoke_split bash amtp_code/bench_split/run_cloud.sh  # 1 run per point, no warm-up (check only)
#   DRY_RUN=1 bash amtp_code/bench_split/run_cloud.sh                      # print the commands only
#
# Writes only under baselines/results/runs/<RUN_NAME>/: amtp/ (CSV + manifests + search_index_<suite>.json), logs/, graphs/.
# The log lines "done <step>" / "FAIL <step>" / "worker done" / "failed:" are what the Mac watcher looks for.
set -u
cd "$(dirname "$0")/.."                               # amtp_code
PY=${PY:-../.venv/bin/python}
RUN=${RUN_NAME:-paper_split}
if [ -n "${SMOKE:-}" ]; then REPS=1; WARMUP=0; fi
REPS=${REPS:-15}
WARMUP=${WARMUP:-3}
ROOT=../baselines/results/runs/$RUN
OUT=$ROOT/amtp
LOGS=$ROOT/logs
export AMTP_PLACEMENT=fill AMTP_AND_PRUNE=1 AMTP_PART_RESULTS=1 AMTP_AND_GREEDY=1
echo "commit $(git rev-parse --short HEAD), uncommitted changes: $(git status --porcelain --untracked-files=no | wc -l | tr -d ' ')"
echo "run $RUN  reps $REPS  warmup $WARMUP  flags: placement fill, and_prune, part_results, and_greedy"
mkdir -p "$OUT" "$LOGS"

FAILED=()
step() {
  local name=$1; shift
  if [ -n "${DRY_RUN:-}" ]; then echo "[dry] $name: $*"; return; fi
  local t0=$SECONDS
  echo "[$(date -u '+%F %T')] start $name"
  if "$@" > "$LOGS/$name.log" 2>&1; then
    echo "[$(date -u '+%F %T')] done  $name ($((SECONDS - t0)) s)"
  else
    echo "[$(date -u '+%F %T')] FAIL  $name (see $LOGS/$name.log)"
    FAILED+=("$name")
  fi
}

step pytest   "$PY" -m pytest -q
if [ ${#FAILED[@]} -gt 0 ]; then echo "failed: pytest (nothing was measured)"; exit 1; fi
step search1  "$PY" -m bench_split.run search1  --reps "$REPS" --warmup "$WARMUP" --out "$OUT"
step xsearch  "$PY" -m bench_split.run xsearch  --reps "$REPS" --warmup "$WARMUP" --out "$OUT"
step xdomains "$PY" -m bench_split.run xdomains --reps "$REPS" --warmup "$WARMUP" --x-kq 4 --shapes AND --out "$OUT"
# figures: not a measurement; a failure here (e.g. no matplotlib on the machine) does not fail the run
if [ ${#FAILED[@]} -eq 0 ] && [ -z "${DRY_RUN:-}" ]; then
  "$PY" -m bench_split.plot_search --amtp "$OUT" --out "$ROOT/graphs" > "$LOGS/plot.log" 2>&1 \
    && echo "figures -> $ROOT/graphs" || echo "figures not made (see $LOGS/plot.log); plot later with bench_split.plot_search"
fi

if [ ${#FAILED[@]} -eq 0 ]; then
  echo "worker done: split"
else
  echo "failed: ${FAILED[*]}"
  exit 1
fi
