#!/bin/bash
# Spike: C client under the real-shaped profile. Layout mirrors the integration test:
# A (allowed listener), O (other listener), P (stand-in for the proxy, the only port in the profile).
N=${1:-200}
OUT=${OUT:-spike-out}
P=crates/warden-sandbox/profiles
mkdir -p "$OUT"
cc -o "$OUT/client" .github/spike/client.c || exit 1
: > "$OUT/results2.txt"
for i in $(seq 1 "$N"); do
  ports=$(python3 - <<'PY'
import socket,os,sys
ls=[]
for _ in range(3):
    s=socket.socket(); s.bind(("127.0.0.1",0)); s.listen(64); ls.append(s)
print(*[s.getsockname()[1] for s in ls]); sys.stdout.flush()
if os.fork():
    os._exit(0)
os.setsid()
fd=os.open('/dev/null',os.O_RDWR); os.dup2(fd,1); os.dup2(fd,2)
import signal, select; signal.alarm(30)
while True:
    r,_,_=select.select(ls,[],[])
    for s in r:
        c,_=s.accept(); c.close()
PY
)
  set -- $ports; A=$1; O=$2; PP=$3
  prof=$( { cat $P/seatbelt_base.sbpl; printf '\n(allow file-read*)\n(allow system-socket (socket-domain AF_UNIX))\n(allow network-outbound (remote ip "localhost:%s"))\n' "$PP"; cat $P/seatbelt_network.sbpl; } )
  run() { # name mode ports...
    name=$1; shift
    out=$(sandbox-exec -p "$prof" "$OUT/client" "$@" 2>&1); rc=$?
    echo "$name $rc A=$A O=$O P=$PP" >> "$OUT/results2.txt"
    if [ $rc -ne 0 ]; then { echo "=== iter=$i $name rc=$rc A=$A O=$O P=$PP $(date '+%H:%M:%S.000')"; echo "$out"; } >> "$OUT/failures2.log"; fi
  }
  run P_only      b $PP
  run O_then_P_nb n $O $PP
  run O_then_P_b  b $O $PP
  run P_x3        b $PP $PP $PP
  run P_O_P       b $PP $O $PP
done
{
  echo "sw_vers: $(sw_vers -productVersion) $(sw_vers -buildVersion)"
  for v in P_only O_then_P_nb O_then_P_b P_x3 P_O_P; do
    awk -v v="$v" '$1==v{t++; if($2!=0)f++} END{printf "client variant=%s failures=%d/%d\n", v, f, t}' "$OUT/results2.txt"
  done
} | tee "$OUT/summary2.txt"
