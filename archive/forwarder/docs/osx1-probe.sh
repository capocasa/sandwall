#!/bin/sh
# osx-1 probe: pf group match + gid drop. Run as root on macOS.
# Installs a main-ruleset anchor call, restores the main ruleset on exit.
set -u
GID=42499
U=$(id -u carlo)
ANCHOR=probe.sandwall
TARGET=1.1.1.1

pfctl -sr > /tmp/osx1.main.bak 2>/dev/null
pfctl -sn > /tmp/osx1.nat.bak 2>/dev/null
cleanup() {
  pfctl -F all >/dev/null 2>&1
  { cat /tmp/osx1.nat.bak; cat /tmp/osx1.main.bak; } | pfctl -f - >/dev/null 2>&1
}
trap cleanup EXIT

echo "== main ruleset: Apple anchors + exact-name call into $ANCHOR"
printf 'scrub-anchor "com.apple/*" all fragment reassemble\nnat-anchor "com.apple/*" all\nrdr-anchor "com.apple/*" all\nanchor "com.apple/*" all\nanchor "%s" all\n' "$ANCHOR" | pfctl -f - 2>/dev/null

echo "== anchor rules"
printf 'table <p> {}\npass out quick on lo0 group = %s\nblock return-rst out quick inet proto tcp to ! <p> group = %s\n' "$GID" "$GID" | pfctl -a "$ANCHOR" -f - 2>/dev/null
pfctl -a "$ANCHOR" -sr 2>/dev/null

# run_as MARKER_GID_OR_EMPTY cmd... : drop to uid U with marker as primary gid, exec
run_as() {
  python3 -c '
import os, sys
gid = int(sys.argv[1]) if sys.argv[1] else 20
cmd = sys.argv[3:]
os.setgid(gid); os.setuid(int(sys.argv[2]))
os.execvp(cmd[0], cmd)
' "$1" "$U" "${@:2}"
}
fetch() { curl -m 5 -sI "https://$TARGET" -o /dev/null -w "%{http_code}" 2>/dev/null || echo "FAIL"; }

echo "== marked process (gid $GID), expect FAIL/000"
echo "marked:  $(run_as "$GID" curl -m 5 -sI "https://$TARGET" -o /dev/null -w %{http_code} 2>&1 || echo FAIL)"

echo "== control (uid $U, no marker), expect 200/301"
echo "control: $(run_as "" curl -m 5 -sI "https://$TARGET" -o /dev/null -w %{http_code} 2>&1 || echo FAIL)"

echo "== loopback from marked process, expect 200"
python3 -m http.server 18099 --bind 127.0.0.1 >/dev/null 2>&1 &
LP=$!
sleep 1
echo "lo0 marked: $(run_as "$GID" curl -m 5 -s -o /dev/null -w %{http_code} http://127.0.0.1:18099/ 2>&1 || echo FAIL)"
kill $LP 2>/dev/null

echo "== gid drop sanity: uid $U, HOME intact, home readable, primary gid = marker"
run_as "$GID" python3 -c 'import os; print("cred:", os.getuid(), os.getgid(), os.getegid(), "marker-in-groups:", 42499 in os.getgroups())'
run_as "$GID" sh -c 'id; echo HOME=$HOME; ls ~ >/dev/null && echo home-readable; touch ~/osx1-probe-file && ls -ln ~/osx1-probe-file && rm ~/osx1-probe-file'

echo "== rule counters (Evaluations/Packets on the block rule)"
pfctl -a "$ANCHOR" -vvsr 2>/dev/null | grep -A2 "^@0 block"
