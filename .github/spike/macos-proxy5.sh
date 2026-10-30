#!/bin/bash
# Spike: sequential single-process runs; vary idle gap before launch, delay before first connect, and the rule.
N=${1:-12}
GAP=${2:-20}
OUT=${OUT:-spike-out}
P=crates/warden-sandbox/profiles
mkdir -p "$OUT"
cc -o "$OUT/client5" .github/spike/client5.c || exit 1
mkprof() { { cat $P/seatbelt_base.sbpl; printf '\n(allow file-read*)\n(allow system-socket (socket-domain AF_UNIX))\n%s\n' "$1"; cat $P/seatbelt_network.sbpl; }; }
: > "$OUT/results5.txt"
run() { # label variant delay_ms
  case $2 in
    current) rule="(allow network-outbound (remote ip \"localhost:$port\"))";;
    anyhost) rule="(allow network-outbound (remote ip \"*:$port\"))";;
  esac
  res=$(sandbox-exec -p "$(mkprof "$rule")" "$OUT/client5" $port $3 20 2>&1)
  echo "iter=$i $1 variant=$2 delay_ms=$3 first_connects=$res" | tee -a "$OUT/results5.txt"
}
for i in $(seq 1 "$N"); do
  read port < <(python3 - <<'PY'
import socket,os,sys
s=socket.socket(); s.bind(("127.0.0.1",0)); s.listen(128)
print(s.getsockname()[1]); sys.stdout.flush()
if os.fork():
    os._exit(0)
os.setsid()
fd=os.open('/dev/null',os.O_RDWR); os.dup2(fd,1); os.dup2(fd,2)
import signal; signal.alarm(100)
while True:
    c,_=s.accept(); c.close()
PY
)
  if [ $((i%2)) -eq 0 ]; then first=current; second=anyhost; else first=anyhost; second=current; fi
  sleep "$GAP"; run "after-idle" $first 0
  run "no-idle" $second 0
  run "no-idle" current 0
  run "no-idle" current 300
  sleep "$GAP"; run "after-idle" current 300
done
