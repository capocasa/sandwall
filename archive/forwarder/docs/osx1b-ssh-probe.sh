#!/bin/sh
# osx-1b: ssh with real keys from inside the pf fence. Run as root on stefani.
set -u
GID=42499
U=$(id -u carlo)
ANCHOR=probe.sandwall
JULES=78.47.197.142

pfctl -sr > /tmp/osx1b.main.bak 2>/dev/null
pfctl -sn > /tmp/osx1b.nat.bak 2>/dev/null
cleanup() {
  pfctl -F all >/dev/null 2>&1
  pfctl -f /etc/pf.conf >/dev/null 2>&1
}
trap cleanup EXIT

printf 'scrub-anchor "com.apple/*" all fragment reassemble\nnat-anchor "com.apple/*" all\nrdr-anchor "com.apple/*" all\nanchor "com.apple/*" all\nanchor "%s" all\n' "$ANCHOR" | pfctl -f - 2>/dev/null
printf 'table <p> { %s }\npass out quick on lo0 group = %s\nblock return-rst out quick inet proto tcp to ! <p> group = %s\n' "$JULES" "$GID" "$GID" | pfctl -a "$ANCHOR" -f - 2>/dev/null
echo "== anchor:"; pfctl -a "$ANCHOR" -sr 2>/dev/null
echo "== table:"; pfctl -a "$ANCHOR" -t p -T show 2>/dev/null

run_as() {
  python3 -c '
import os, sys
os.setgid(int(sys.argv[1])); os.setuid(int(sys.argv[2]))
cmd = sys.argv[3:]
os.execvp(cmd[0], cmd)
' "$GID" "$U" "$@"
}

SSHOPTS="-o BatchMode=yes -o ConnectTimeout=8"

echo "== fenced ssh to jules (permitted), expect FENCED_OK"
run_as ssh $SSHOPTS root@$JULES 'echo FENCED_OK from $(hostname) as $(whoami)' 2>&1 || echo FAIL

echo "== fenced curl to 1.1.1.1 (denied), expect FAIL"
run_as curl -m 5 -sI https://1.1.1.1 -o /dev/null -w "%{http_code}\n" 2>&1 || echo FAIL

echo "== fenced ssh to 1.1.1.1:22 (denied), expect FAIL"
run_as ssh $SSHOPTS -p 22 root@1.1.1.1 'echo SHOULD_NOT' 2>&1 | tail -1 || echo FAIL

echo "== rule counters"
pfctl -a "$ANCHOR" -vvsr 2>/dev/null | grep -A2 "^@0\|^@1" | grep -E "^@|Evaluations"
