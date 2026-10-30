#!/bin/bash
# Spike: does a denied connect to port O make a later allowed connect to P (= O+d) fail, within one process?
N=${1:-60}
OUT=${OUT:-spike-out}
P=crates/warden-sandbox/profiles
mkdir -p "$OUT"
cc -o "$OUT/client3" .github/spike/client3.c || exit 1
: > "$OUT/results3.txt"
for i in $(seq 1 "$N"); do
  read base lpid < <(python3 - <<'PY'
import socket,os,sys,random
while True:
    b=random.randrange(49600,64000)
    ls=[]
    try:
        for k in range(-300,300):
            s=socket.socket(); s.bind(("127.0.0.1",b+k)); s.listen(64); ls.append(s)
        break
    except OSError:
        for s in ls: s.close()
print(b, os.getpid()); sys.stdout.flush()
if os.fork():
    os._exit(0)
os.setsid()
fd=os.open('/dev/null',os.O_RDWR); os.dup2(fd,1); os.dup2(fd,2)
import signal, select; signal.alarm(60)
while True:
    r,_,_=select.select(ls,[],[])
    for s in r:
        c,_=s.accept(); c.close()
PY
)
  for d in 1 -1 2 7 8 255 256; do
    O=$base; PP=$((base+d))
    prof=$( { cat $P/seatbelt_base.sbpl; printf '\n(allow file-read*)\n(allow system-socket (socket-domain AF_UNIX))\n(allow network-outbound (remote ip "localhost:%s"))\n' "$PP"; cat $P/seatbelt_network.sbpl; } )
    out=$(sandbox-exec -p "$prof" "$OUT/client3" $PP $O 100 127.0.0.1 2>&1); rc=$?
    echo "d=$d rc=$rc iter=$i O=$O P=$PP" >> "$OUT/results3.txt"
    [ $rc -ne 0 ] && { echo "=== iter=$i d=$d O=$O P=$PP"; echo "$out" | cut -c1-200; } >> "$OUT/failures3.log"
  done
  # control: no denied connect at all, 400 P connects in one process
  prof=$( { cat $P/seatbelt_base.sbpl; printf '\n(allow file-read*)\n(allow system-socket (socket-domain AF_UNIX))\n(allow network-outbound (remote ip "localhost:%s"))\n' "$((base+1))"; cat $P/seatbelt_network.sbpl; } )
  out=$(sandbox-exec -p "$prof" "$OUT/client3" $((base+1)) 0 400 2>&1); rc=$?
  echo "control rc=$rc iter=$i" >> "$OUT/results3.txt"
  [ $rc -ne 0 ] && { echo "=== iter=$i control"; echo "$out" | cut -c1-200; } >> "$OUT/failures3.log"
done
for v in d=1 d=-1 d=2 d=7 d=8 d=255 d=256 control; do
  awk -v v="$v" '$1==v{t++; if($2!="rc=0")f++} END{printf "variant %s failing-runs=%d/%d\n", v, f, t}' "$OUT/results3.txt"
done | tee "$OUT/summary3.txt"
