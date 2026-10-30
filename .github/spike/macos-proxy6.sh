#!/bin/bash
# Spike: does the age of the listener (time since bind) at the first sandboxed connect matter?
N=${1:-40}
OUT=${OUT:-spike-out}
P=crates/warden-sandbox/profiles
mkdir -p "$OUT"
cc -o "$OUT/client5" .github/spike/client5.c || exit 1
mkprof() { { cat $P/seatbelt_base.sbpl; printf '\n(allow file-read*)\n(allow system-socket (socket-domain AF_UNIX))\n%s\n' "$1"; cat $P/seatbelt_network.sbpl; }; }
: > "$OUT/results6.txt"
newlistener() {
  read port bound < <(python3 - <<'PY'
import socket,os,sys,time
s=socket.socket(); s.bind(("127.0.0.1",0)); s.listen(128)
print(s.getsockname()[1], time.time_ns()); sys.stdout.flush()
if os.fork():
    os._exit(0)
os.setsid()
fd=os.open('/dev/null',os.O_RDWR); os.dup2(fd,1); os.dup2(fd,2)
import signal; signal.alarm(30)
while True:
    c,_=s.accept(); c.close()
PY
)
}
for i in $(seq 1 "$N"); do
  for spec in current:0 current:25 current:50 current:100 current:200 current:400 current:800 current:1600 current:3200 anyhost:0 anyhost:50; do
    v=${spec%%:*}; d=${spec##*:}
    newlistener
    case $v in
      current) rule="(allow network-outbound (remote ip \"localhost:$port\"))";;
      anyhost) rule="(allow network-outbound (remote ip \"*:$port\"))";;
    esac
    res=$(sandbox-exec -p "$(mkprof "$rule")" "$OUT/client5" $port $d 3 $bound 2>&1)
    echo "iter=$i variant=$v delay_ms=$d port=$port $res" >> "$OUT/results6.txt"
  done
done
for spec in current:0 current:25 current:50 current:100 current:200 current:400 current:800 current:1600 current:3200 anyhost:0 anyhost:50; do
  v=${spec%%:*}; d=${spec##*:}
  grep "variant=$v delay_ms=$d " "$OUT/results6.txt" | awk -v v="$v" -v d="$d" '{t++; if($5 !~ /^\.\.\.$/) f++} END{printf "variant=%s delay_ms=%s runs-with-failure=%d/%d\n", v, d, f, t}'
done | tee "$OUT/summary6.txt"
