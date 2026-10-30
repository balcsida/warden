#!/bin/bash
# Spike: capture the full unified log while looping; print log lines +-400ms around every first-connect EPERM.
SECS=${1:-240}
OUT=${OUT:-spike-out}
P=crates/warden-sandbox/profiles
mkdir -p "$OUT"
cc -o "$OUT/client5" .github/spike/client5.c || exit 1
mkprof() { { cat $P/seatbelt_base.sbpl; printf '\n(allow file-read*)\n(allow system-socket (socket-domain AF_UNIX))\n%s\n' "$1"; cat $P/seatbelt_network.sbpl; }; }
sudo log stream --style compact --level debug > "$OUT/full.log" 2>&1 &
sleep 3
end=$(( $(date +%s) + SECS ))
: > "$OUT/results8.txt"
n=0
while [ "$(date +%s)" -lt "$end" ]; do
  for d in 0 400 800 3200; do
    read port bound < <(python3 - <<'PY'
import socket,os,sys,time
s=socket.socket(); s.bind(("127.0.0.1",0)); s.listen(128)
print(s.getsockname()[1], time.time_ns()); sys.stdout.flush()
if os.fork():
    os._exit(0)
os.setsid()
fd=os.open('/dev/null',os.O_RDWR); os.dup2(fd,1); os.dup2(fd,2)
import signal; signal.alarm(20)
while True:
    c,_=s.accept(); c.close()
PY
)
    res=$(sandbox-exec -p "$(mkprof "(allow network-outbound (remote ip \"localhost:$port\"))")" "$OUT/client5" $port $d 3 $bound 2>&1)
    n=$((n+1))
    case $res in "..."*) ;; *) echo "run=$n delay=$d port=$port $res" >> "$OUT/results8.txt";; esac
  done
done
sleep 3; sudo pkill -f 'log stream' || true
echo "runs=$n failures=$(wc -l < "$OUT/results8.txt")" | tee "$OUT/summary8.txt"
cat "$OUT/results8.txt"
while read -r line; do
  ns=${line##*failns=}
  [ "$ns" = 0 ] && continue
  sec=$((ns / 1000000000)); ms=$(( (ns / 1000000) % 1000 ))
  lo=$(( ns / 1000000 - 400 )); hi=$(( ns / 1000000 + 400 ))
  echo "=== failure at $(date -u -r $sec '+%H:%M:%S').$(printf %03d $ms) UTC: $line" | tee -a "$OUT/around.txt"
  for off in $(seq -1 1); do
    s2=$(date -u -r $((sec+off)) '+%H:%M:%S')
    grep -a " $s2\." "$OUT/full.log"
  done | awk -v lo="$lo" -v hi="$hi" '{split($2,t,/[:.]/); v=((t[1]*3600+t[2]*60+t[3])*1000+t[4]); if (v>=(lo%86400000) && v<=(hi%86400000)) print}' | cut -c1-260 | tee -a "$OUT/around.txt"
done < "$OUT/results8.txt"
