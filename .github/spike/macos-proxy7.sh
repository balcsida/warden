#!/bin/bash
# Spike: is the first-connect EPERM driven by run count, time, port, or profile text? Fast sequential runs, modes A/B/C.
N=${1:-600}
OUT=${OUT:-spike-out}
P=crates/warden-sandbox/profiles
mkdir -p "$OUT"
cc -o "$OUT/client5" .github/spike/client5.c || exit 1
mkprof() { { cat $P/seatbelt_base.sbpl; printf '\n(allow file-read*)\n(allow system-socket (socket-domain AF_UNIX))\n%s\n' "$1"; cat $P/seatbelt_network.sbpl; }; }
newlistener() {
  read port bound < <(python3 - <<'PY'
import socket,os,sys,time
s=socket.socket(); s.bind(("127.0.0.1",0)); s.listen(128)
print(s.getsockname()[1], time.time_ns()); sys.stdout.flush()
if os.fork():
    os._exit(0)
os.setsid()
fd=os.open('/dev/null',os.O_RDWR); os.dup2(fd,1); os.dup2(fd,2)
import signal; signal.alarm(int(os.environ.get("LIFE","40")))
while True:
    c,_=s.accept(); c.close()
PY
)
}
t0=$(python3 -c 'import time;print(time.time_ns())')
: > "$OUT/results7.txt"
LIFE=200 newlistener; fixed_port=$port
for mode in A B C; do
  for i in $(seq 1 "$N"); do
    case $mode in
      A) newlistener; p=$port; rule="(allow network-outbound (remote ip \"localhost:$p\"))";;
      B) p=$fixed_port; rule="(allow network-outbound (remote ip \"localhost:$p\"))";;
      C) p=$fixed_port; rule="(allow network-outbound (remote ip \"localhost:$p\"))
; run $i";;
    esac
    now=$(python3 -c 'import time;print(time.time_ns())')
    res=$(sandbox-exec -p "$(mkprof "$rule")" "$OUT/client5" $p 0 3 $now 2>&1)
    case $res in "..."*) ;; *) echo "mode=$mode run=$i t_ms=$(( (now - t0) / 1000000 )) port=$p $res" >> "$OUT/results7.txt";; esac
  done
  echo "mode=$mode failures=$(grep -c "^mode=$mode " "$OUT/results7.txt")/$N"
done | tee "$OUT/summary7.txt"
