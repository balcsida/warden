#!/bin/bash
# Spike: 4 sandboxed clients launched concurrently against one fresh listener, variant order shuffled each iteration.
N=${1:-100}
OUT=${OUT:-spike-out}
P=crates/warden-sandbox/profiles
mkdir -p "$OUT/c9"
cc -o "$OUT/client5" .github/spike/client5.c || exit 1
mkprof() { { cat $P/seatbelt_base.sbpl; printf '\n(allow file-read*)\n(allow system-socket (socket-domain AF_UNIX))\n%s\n' "$1"; cat $P/seatbelt_network.sbpl; }; }
: > "$OUT/results9.txt"
for i in $(seq 1 "$N"); do
  read port bound < <(python3 - <<'PY'
import socket,os,sys,time
s=socket.socket(); s.bind(("127.0.0.1",0)); s.listen(128)
print(s.getsockname()[1], time.time_ns()); sys.stdout.flush()
if os.fork():
    os._exit(0)
os.setsid()
fd=os.open('/dev/null',os.O_RDWR); os.dup2(fd,1); os.dup2(fd,2)
import signal; signal.alarm(10)
while True:
    c,_=s.accept(); c.close()
PY
)
  order=$(python3 -c 'import random;v=["current","anyhost","tcp","wild"];random.shuffle(v);print(*v)')
  pos=0
  for v in $order; do
    pos=$((pos+1))
    case $v in
      current) rule="(allow network-outbound (remote ip \"localhost:$port\"))";;
      anyhost) rule="(allow network-outbound (remote ip \"*:$port\"))";;
      tcp) rule="(allow network-outbound (remote tcp \"localhost:$port\"))";;
      wild) rule="(allow network-outbound (remote ip \"localhost:*\"))";;
    esac
    prof=$(mkprof "$rule")
    ( res=$(sandbox-exec -p "$prof" "$OUT/client5" $port 0 3 $bound 2>&1); echo "iter=$i pos=$pos variant=$v port=$port $res" > "$OUT/c9/$i.$v" ) &
  done
  wait
  cat "$OUT"/c9/$i.* >> "$OUT/results9.txt"
done
for v in current anyhost tcp wild; do
  grep "variant=$v " "$OUT/results9.txt" | awk -v v="$v" '{t++; if($5 !~ /^\.\.\./) f++} END{printf "variant=%s first-connect-or-any failures=%d/%d\n", v, f, t}'
done | tee "$OUT/summary9.txt"
for p in 1 2 3 4; do grep "pos=$p " "$OUT/results9.txt" | awk -v p="$p" '{t++; if($5 !~ /^\.\.\./) f++} END{printf "launch position %s failures=%d/%d\n", p, f, t}'; done | tee -a "$OUT/summary9.txt"
grep -v ' \.\.\. ' "$OUT/results9.txt" | head -40
