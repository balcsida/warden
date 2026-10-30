#!/bin/bash
# Spike: sequential runs for SECS seconds, rule variant chosen at random per run, fresh listener each run.
SECS=${1:-360}
OUT=${OUT:-spike-out}
P=crates/warden-sandbox/profiles
mkdir -p "$OUT"
cc -o "$OUT/client5" .github/spike/client5.c || exit 1
mkprof() { { cat $P/seatbelt_base.sbpl; printf '\n(allow file-read*)\n(allow system-socket (socket-domain AF_UNIX))\n%s\n' "$1"; cat $P/seatbelt_network.sbpl; }; }
: > "$OUT/results10.txt"
end=$(( $(date +%s) + SECS ))
while [ "$(date +%s)" -lt "$end" ]; do
  read port bound < <(python3 - <<'PY'
import socket,os,sys,time
s=socket.socket(); s.bind(("127.0.0.1",0)); s.listen(128)
print(s.getsockname()[1], time.time_ns()); sys.stdout.flush()
if os.fork():
    os._exit(0)
os.setsid()
fd=os.open('/dev/null',os.O_RDWR); os.dup2(fd,1); os.dup2(fd,2)
import signal; signal.alarm(8)
while True:
    c,_=s.accept(); c.close()
PY
)
  v=$(python3 -c 'import random;print(random.choice(["current","anyhost","tcp","wild"]))')
  case $v in
    current) rule="(allow network-outbound (remote ip \"localhost:$port\"))";;
    anyhost) rule="(allow network-outbound (remote ip \"*:$port\"))";;
    tcp) rule="(allow network-outbound (remote tcp \"localhost:$port\"))";;
    wild) rule="(allow network-outbound (remote ip \"localhost:*\"))";;
  esac
  res=$(sandbox-exec -p "$(mkprof "$rule")" "$OUT/client5" $port 300 3 $bound 2>&1)
  echo "t=$(date -u +%H:%M:%S) variant=$v port=$port $res" >> "$OUT/results10.txt"
done
for v in current anyhost tcp wild; do
  grep "variant=$v " "$OUT/results10.txt" | awk -v v="$v" '{t++; if($4 !~ /^\.\.\./) f++} END{printf "variant=%s runs-with-failure=%d/%d\n", v, f, t}'
done | tee "$OUT/summary10.txt"
grep -v ' \.\.\. ' "$OUT/results10.txt" | head -40
