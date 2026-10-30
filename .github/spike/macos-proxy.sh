#!/bin/bash
# Spike: reproduce Seatbelt EPERM on connect to localhost:<port>. Usage: macos-proxy.sh <iterations>
# Each iteration starts a listener; every variant runs nc under sandbox-exec with a different network rule.
N=${1:-100}
OUT=${OUT:-spike-out}
P=crates/warden-sandbox/profiles
mkdir -p "$OUT"
sudo log stream --predicate 'sender=="Sandbox"' --style compact > "$OUT/sandbox-stream.log" 2>&1 &
sleep 2
variants="current wildcard tcp literal127 minimal"
rule() { # variant port
  case $1 in
    current) echo "(allow network-outbound (remote ip \"localhost:$2\"))";;
    wildcard) echo '(allow network-outbound (remote ip "localhost:*"))';;
    tcp) echo "(allow network-outbound (remote tcp \"localhost:$2\"))";;
    literal127) echo "(allow network-outbound (remote ip \"127.0.0.1:$2\"))";;
  esac
}
profile() { # variant port
  if [ "$1" = minimal ]; then
    printf '(version 1)\n(allow default)\n(deny network*)\n(allow network-outbound (remote ip "localhost:%s"))\n' "$2"
  else
    { cat $P/seatbelt_base.sbpl; printf '\n(allow file-read*)\n(allow system-socket (socket-domain AF_UNIX))\n'; rule "$1" "$2"; cat $P/seatbelt_network.sbpl; }
  fi
}
: > "$OUT/results.txt"
for i in $(seq 1 "$N"); do
  port=$(python3 - <<'PY'
import socket,os,sys
s=socket.socket(); s.bind(("127.0.0.1",0)); s.listen(64)
print(s.getsockname()[1]); sys.stdout.flush()
if os.fork():
    os._exit(0)
os.setsid()
import signal; signal.alarm(30)
while True:
    c,_=s.accept(); c.close()
PY
)
  for v in $variants; do
    prof=$(profile "$v" "$port")
    res=$(sandbox-exec -p "$prof" /usr/bin/nc -z -w 2 127.0.0.1 "$port" 2>&1); rc=$?
    echo "$v $rc $port" >> "$OUT/results.txt"
    if [ $rc -ne 0 ]; then
      {
        echo "=== iter=$i variant=$v port=$port rc=$rc time=$(date '+%Y-%m-%d %H:%M:%S')"
        echo "nc/sandbox-exec output: $res"
        echo "--- profile rules:"; echo "$prof" | grep -n 'remote' | head
      } >> "$OUT/failures.log"
    fi
  done
done
sleep 3; sudo pkill -f 'log stream' || true
{
  echo "sw_vers: $(sw_vers -productVersion) $(sw_vers -buildVersion)  arch: $(uname -m)"
  for v in $variants; do
    awk -v v="$v" '$1==v{t++; if($2!=0)f++} END{printf "variant=%s failures=%d/%d\n", v, f, t}' "$OUT/results.txt"
  done
} | tee "$OUT/summary.txt"
