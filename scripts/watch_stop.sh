#!/usr/bin/env bash
# Power the machine off (results stay on the disk) when
#   1. scripts/cloud_worker.sh has finished: after a grace period (GRACE_MIN, default 10) so the results can be
#      copied off first, or
#   2. the machine has done no work for IDLE_MIN minutes in a row (default 30): total CPU busy below
#      IDLE_PCT % (default 2; one benchmark job keeps one of 16 vCPUs busy, about 6 %), which also catches a
#      job that hangs.
#   nohup setsid bash scripts/watch_stop.sh > ~/watch_stop.out 2>&1 < /dev/null &
# Status: ~/watch_stop.status (one line per minute), reason of the shutdown: ~/watch_stop.log
GRACE_MIN=${GRACE_MIN:-10}
IDLE_MIN=${IDLE_MIN:-30}
IDLE_PCT=${IDLE_PCT:-2}

cpu() { awk '/^cpu /{print $2 + $3 + $4 + $7 + $8, $5 + $6}' /proc/stat; }   # busy, idle jiffies

stop() {
  echo "$(date '+%F %T') shutting down: $1" >> ~/watch_stop.log
  sudo shutdown -h now
  exit 0
}

read -r b0 i0 < <(cpu)
idle=0 done_for=0
while true; do
  sleep 60
  read -r b1 i1 < <(cpu)
  busy=$(( (b1 - b0) * 100 / ((b1 - b0) + (i1 - i0) + 1) ))
  b0=$b1 i0=$i1
  if [ "$busy" -lt "$IDLE_PCT" ]; then idle=$((idle + 1)); else idle=0; fi
  if pgrep -f "cloud_worker[.]sh" > /dev/null; then done_for=0; else done_for=$((done_for + 1)); fi
  echo "$(date '+%F %T') cpu_busy=${busy}% idle_min=$idle finished_min=$done_for" > ~/watch_stop.status
  [ "$done_for" -ge "$GRACE_MIN" ] && stop "cloud_worker.sh finished $done_for min ago"
  [ "$idle" -ge "$IDLE_MIN" ] && stop "no work for $idle min (cpu busy < ${IDLE_PCT}%)"
done
