#!/bin/bash
# Spike: tight connect loops under different rules, run concurrently against one fresh listener; look at EPERM timing.
N=${1:-10}
T=${2:-10}
OUT=${OUT:-spike-out}
P=crates/warden-sandbox/profiles
mkdir -p "$OUT"
cc -o "$OUT/client4" .github/spike/client4.c || exit 1
mkprof() { # rule
  { cat $P/seatbelt_base.sbpl; printf '\n(allow file-read*)\n(allow system-socket (socket-domain AF_UNIX))\n%s\n' "$1"; cat $P/seatbelt_network.sbpl; }
}
: > "$OUT/results4.txt"
for i in $(seq 1 "$N"); do
  read port bound < <(python3 - <<'PY'
import socket,os,sys,time
s=socket.socket(); s.bind(("127.0.0.1",0)); s.listen(128)
print(s.getsockname()[1], time.time_ns()); sys.stdout.flush()
if os.fork():
    os._exit(0)
os.setsid()
fd=os.open('/dev/null',os.O_RDWR); os.dup2(fd,1); os.dup2(fd,2)
import signal; signal.alarm(40)
while True:
    c,_=s.accept(); c.close()
PY
)
  declare_rules="current|(allow network-outbound (remote ip \"localhost:$port\"))
wild|(allow network-outbound (remote ip \"localhost:*\"))
anyhost|(allow network-outbound (remote ip \"*:$port\"))"
  while IFS='|' read name rule; do
    ( sandbox-exec -p "$(mkprof "$rule")" "$OUT/client4" $port $T > "$OUT/c4.$name" 2>&1 ) &
  done <<< "$declare_rules"
  wait
  for name in current wild anyhost; do
    st=$(awk '/^start/{print $2}' "$OUT/c4.$name")
    echo "iter=$i port=$port variant=$name $(grep '^total' "$OUT/c4.$name") bind_to_start_ms=$(( (st - bound) / 1000000 ))" | tee -a "$OUT/results4.txt"
    grep '^fail' "$OUT/c4.$name" | head -5 | awk -v s="$st" -v b="$bound" '{printf "   fail +%dms since process start (+%dms since bind) %s %s %s\n", ($2-s)/1000000, ($2-b)/1000000, $3,$4,$5}' | tee -a "$OUT/results4.txt"
  done
done
