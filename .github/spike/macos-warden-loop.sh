#!/bin/bash
# Spike: run the real sandbox integration test N times; keep profile + output + Sandbox log on failure.
N=${1:-50}
OUT=${OUT:-spike-out}
mkdir -p "$OUT" /tmp/warden-spike
sudo log stream --predicate 'sender=="Sandbox"' --style compact > "$OUT/warden-sandbox-stream.log" 2>&1 &
sleep 2
cargo test -p warden-cli --test sandbox --no-run 2>&1 | tail -2
fails=0
for i in $(seq 1 "$N"); do
  rm -f /tmp/warden-spike/*
  if ! cargo test -p warden-cli --test sandbox sandbox_blocks_read_write_and_connect > "$OUT/iter.out" 2>&1; then
    fails=$((fails+1))
    {
      echo "=== iter=$i time=$(date '+%Y-%m-%d %H:%M:%S')"
      grep -E 'proxy=|direct=|read=|write=|panicked|blocked' "$OUT/iter.out" | head -20
      for f in /tmp/warden-spike/*.sbpl; do echo "--- $f"; cat "$f"; done
    } >> "$OUT/warden-failures.log"
  fi
done
sleep 3; sudo pkill -f 'log stream' || true
echo "warden test loop: failures=$fails/$N on $(sw_vers -productVersion)" | tee "$OUT/warden-summary.txt"
