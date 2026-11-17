#!/usr/bin/env bash
# The 10-machine plan (10 x r7i.4xlarge, one job at a time per machine, rule R4).
#
#   bash scripts/cloud_worker.sh 3             # everything worker 3 runs, in order
#   bash scripts/cloud_worker.sh job sm128     # one or more named jobs (to move work between machines)
#   bash scripts/cloud_worker.sh list          # the plan
#   CALIB=1 bash scripts/cloud_worker.sh 3     # calibration: REPS=1 WARMUP=0, short split/merge, run <name>_calib
#   DRY_RUN=1 bash scripts/cloud_worker.sh 3   # print the commands only
#
# Two rounds, each its own run folder (same name on every machine, merged later with scripts/merge_runs.py):
#   paper_v     AMTP's γ with the version v (the paper): every experiment, every scheme
#   paper_nov   AMTP's γ without v (study B4, AMTP_GAMMA_V=0): only the AMTP update experiments
# Every machine must be on the same commit. Results: baselines/results/runs/<run>/ (logs in <run>/logs/).
# Placement rule of AMTP / Static-MT (amtp/variants.py): AMTP_PLACEMENT=fill|least (default fill, the paper's rule), read by
# bench.experiments and bench.ablation and recorded in every manifest, e.g.
#   AMTP_PLACEMENT=fill RUN_NAME=paper_fill bash scripts/cloud_worker.sh 3
set -u
cd "$(dirname "$0")/.."
NAME=${RUN_NAME:-paper}
if [ -n "${CALIB:-}" ]; then
  # full sizes, 1 run per point; split / merge: 1 run of 100 insert batches (x ~16.5 batches x 3 runs for the real one)
  export REPS=1 WARMUP=0 SM_RUNS=1 SM_BATCHES=100
  NAME=${NAME}_calib
fi

# job name -> environment + steps of scripts/aws_run_all.sh
job_env() {
  case $1 in
    tamper-amtp-a)   echo 'SCHEMES=amtp X_TAMPER="--s-domains D1 D2"|tamper' ;;
    tamper-amtp-b)   echo 'SCHEMES=amtp X_TAMPER="--s-domains D3 D4"|tamper' ;;
    tamper-chen-a)   echo 'SCHEMES=chen X_TAMPER="--s-domains D1 D2"|tamper' ;;
    tamper-chen-b)   echo 'SCHEMES=chen X_TAMPER="--s-domains D3 D4"|tamper' ;;
    tamper-du-se)    echo 'SCHEMES="du secollab"|tamper' ;;
    verify1)         echo '|verify1' ;;
    search1-amtp-chen) echo 'SCHEMES="amtp chen"|search1' ;;
    search1-du-se)   echo 'SCHEMES="du secollab"|search1' ;;
    multi-amtp)      echo 'SCHEMES=amtp|xsearch xverify xdomains' ;;
    multi-se)        echo 'SCHEMES=secollab|xsearch xverify xdomains' ;;
    update)          echo '|update' ;;
    exp5)            echo '|exp5' ;;
    sm64|sm128|sm256) echo "SM_RUNS=1 SM_THETAS=${1#sm}|splitmerge" ;;   # with v: 1 run (Static-MT is slow); run 0 pairs with nov run 0
    nov-update)      echo 'AMTP_GAMMA_V=0 SCHEMES=amtp|update' ;;
    nov-exp5)        echo 'AMTP_GAMMA_V=0 SCHEMES=amtp|exp5' ;;
    nov-sm64|nov-sm128|nov-sm256) echo "AMTP_GAMMA_V=0 SM_THETAS=${1#nov-sm}|splitmerge" ;;
    # plan "fill" (15 Nov): AMTP only, placement fill, engine with batched Merkle updates; baselines are not re-run
    fill-sm64|fill-sm128|fill-sm256)
      echo "AMTP_PLACEMENT=fill SM_RUNS=1 SM_THETAS=${1#fill-sm} SM_VARIANTS=AMTP,Static-MT|splitmerge" ;;
    fill-gmtv)       echo 'AMTP_PLACEMENT=fill SM_RUNS=1 SM_THETAS=64 SM_VARIANTS="Global-MT(v)" SM_TAG=_gmtv|splitmerge' ;;
    fill-amtp)       echo 'AMTP_PLACEMENT=fill SCHEMES=amtp|search1 verify1 tamper xsearch xverify xdomains update exp5' ;;
    # plan "prune" (16 Nov): AMTP query suites with every query flag on (AND pruning, result-only partition check,
    # greedy planner), placement fill; update code is unchanged since "fill", so ex3 / ex4 and the baselines are not re-run
    prune-amtp)      echo 'AMTP_PLACEMENT=fill AMTP_AND_PRUNE=1 AMTP_PART_RESULTS=1 AMTP_AND_GREEDY=1 SCHEMES=amtp|search1 verify1 tamper xsearch xverify xdomains exp5' ;;
    # ex4 again with the query flags on for every variant (same server / user code): updates are unchanged since
    # "fill", the per-batch queries change
    prune-sm64|prune-sm128|prune-sm256)
      echo "AMTP_PLACEMENT=fill AMTP_AND_PRUNE=1 AMTP_PART_RESULTS=1 AMTP_AND_GREEDY=1 SM_RUNS=1 SM_THETAS=${1#prune-sm} SM_VARIANTS=AMTP,Static-MT|splitmerge" ;;
    prune-gmtv)      echo 'AMTP_PLACEMENT=fill AMTP_AND_PRUNE=1 AMTP_PART_RESULTS=1 AMTP_AND_GREEDY=1 SM_RUNS=1 SM_THETAS=64 SM_VARIANTS="Global-MT(v)" SM_TAG=_gmtv|splitmerge' ;;
    *) return 1 ;;
  esac
}

# worker -> jobs (estimated from the smoke run, REPS = 15; re-balance after the calibration run).
# The six split / merge jobs (not shortened by REPS) go to six different machines.
# PLAN=fill: the 5-machine re-run of AMTP (15 Nov), e.g.  PLAN=fill RUN_NAME=paper_fill bash scripts/cloud_worker.sh 1
# PLAN=prune: 5 machines, every query flag on: 1 = AMTP query suites, 2-4 = ex4 AMTP + Static-MT θ 64/128/256, 5 = Global-MT(v), e.g.  PLAN=prune RUN_NAME=paper_prune bash scripts/cloud_worker.sh 1
plan() {
  if [ "${PLAN:-}" = prune ]; then
    case $1 in
      1) echo "prune-amtp" ;;
      2) echo "prune-sm64" ;;
      3) echo "prune-sm128" ;;
      4) echo "prune-sm256" ;;
      5) echo "prune-gmtv" ;;
      *) return 1 ;;
    esac
    return 0
  fi
  if [ "${PLAN:-}" = fill ]; then
    case $1 in
      1) echo "fill-sm64" ;;
      2) echo "fill-sm128" ;;
      3) echo "fill-sm256" ;;
      4) echo "fill-amtp" ;;
      5) echo "fill-gmtv" ;;
      *) return 1 ;;
    esac
    return 0
  fi
  case $1 in
    1)  echo "tamper-amtp-a sm64" ;;
    2)  echo "tamper-amtp-b sm128" ;;
    3)  echo "tamper-chen-a nov-sm64" ;;
    4)  echo "tamper-chen-b nov-sm128" ;;
    5)  echo "tamper-du-se verify1 nov-update" ;;
    6)  echo "search1-amtp-chen update nov-exp5" ;;
    7)  echo "search1-du-se exp5" ;;
    8)  echo "multi-amtp nov-sm256" ;;
    9)  echo "multi-se" ;;
    10) echo "sm256" ;;
    *) return 1 ;;
  esac
}

FAILED=()
run_job() {
  local spec envs steps run
  spec=$(job_env "$1") || { echo "unknown job: $1"; exit 2; }
  envs=${spec%%|*}
  steps=${spec#*|}
  case $1 in nov-*) run=${NAME}_nov ;; *) run=${NAME}_v ;; esac
  echo "=== job $1 -> run $run: $envs steps: $steps"
  if ! eval "env $envs RUN_ID=$run bash scripts/aws_run_all.sh $steps"; then
    FAILED+=("$1")
  fi
}

case ${1:-} in
  list)
    for w in 1 2 3 4 5 6 7 8 9 10; do p=$(plan $w) && echo "worker $w: $p"; done
    exit 0 ;;
  job)
    shift
    [ $# -gt 0 ] || { echo "usage: $0 job <name>..."; exit 2; }
    JOBS=("$@") ;;
  [0-9]*)
    read -r -a JOBS <<< "$(plan "$1")" || true
    [ ${#JOBS[@]} -gt 0 ] || { echo "no worker $1 (1..10)"; exit 2; } ;;
  *)
    sed -n '2,16p' "$0"
    exit 2 ;;
esac

eval "RUN_ID=${NAME}_v bash scripts/aws_run_all.sh check" || FAILED+=("check")   # dataset, tests, selftests once
for j in "${JOBS[@]}"; do
  run_job "$j"
done
if [ ${#FAILED[@]} -eq 0 ]; then
  echo "worker done: ${JOBS[*]}"
else
  echo "failed: ${FAILED[*]}"
  exit 1
fi
