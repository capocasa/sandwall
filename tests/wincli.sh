#!/bin/sh
## End-to-end Windows CLI tests against the `beck` VM. Not part of
## `nimble test` (needs a reachable Windows VM with sandwall set up);
## run manually after scp'ing a fresh sandwall.exe:
##
##   nim c -o:sandwall.exe --os:windows --opt:none --debugger:native src/sandwall.nim
##   scp sandwall.exe beck:
##   tests/wincli.sh
##
## Expects ~/sandwallrc on the VM with at least one host rule (the
## tree's own policy: deny /, deny 1.1.1.1) and an elevated
## `sandwall setup` already run (WFP fence + loopback exemption).
set -u
fail=0

t() { # name expected_substr command...
  name=$1; want=$2; shift 2
  out=$(timeout 40 ssh beck "$*" 2>&1 | tr -d '\r')
  case $out in
    *"$want"*) echo "ok   $name" ;;
    *) echo "FAIL $name"; echo "  wanted: $want"; echo "  got: $out" | head -5; fail=1 ;;
  esac
}

# Denied host: the wall proxy refuses immediately (403 through the
# proxy env), no 21s connect timeout.
t "denied host is refused by the proxy" "DENY 1.1.1.1" \
  "sandwall sandwallrc curl --max-time 10 -s -o nul 1.1.1.1"

# Unlisted host with a deny-only policy: allowed, fast, real response.
t "unlisted host passes the proxy" "301" \
  "sandwall sandwallrc curl --max-time 10 -s -o nul -w %{http_code} google.com"

# Bare name with no PATH hit: a clean not-found (2), not a hang.
t "missing exe fails as not found" "failed: 2" \
  "sandwall sandwallrc ls"

# Bare name on PATH resolves and runs inside the container (xcopy
# complains about its own args, which proves CreateProcess worked).
t "bare exe on PATH resolves and runs" "Invalid number of parameters" \
  "sandwall sandwallrc xcopy"

exit $fail
