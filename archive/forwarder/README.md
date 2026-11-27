# Archive: the forwarder (raw egress) approach

Shipped in 0.6.0 to 0.6.2, reverted on 2026-11-27. Sandwall is back on
the socks proxy path of 0.5.19.

What this was: instead of a proxy the client talks to, the fence
resolves allowed names to synthetic 198.18.0.0/15 addresses, an nft
redirect (Linux), WFP permit filters (Windows) or pf anchors keyed on a
marker gid (macOS, the `sandwallpf` daemon) push every connection onto a
raw forwarder that maps the fake address back to its name and checks the
rule again at connect time.

## Where things are

- Code: branch `forwarder` (tip `ee6e1af`, the state of `main` before
  the revert). `git switch forwarder` to build it; `sandwall.nimble`
  there also builds `sandwallpf`.
- `CHANGELOG.md`, `README-0.6.2.md`: as they were at `ee6e1af`.
- `docs/`: the implementation plan and its chunks, the macOS plan, and
  the two pf probe scripts, as last edited in the working tree (these
  were never committed).

## Known state at the time of the revert

Linux raw fence ran green in the tests; the Windows raw path ran on a
host; the macOS daemon had unit-tested rules but had never run as root
on a Mac. Details in the changelog and `docs/`.
