## sandwallpf - the privileged broker of the macOS pf egress fence.
##
## A LaunchDaemon root runs (`sudo sandwall setup` installs it). It
## enables pf, keeps the sandwall anchors in the main ruleset, holds one
## child anchor and one marker gid per run, and is the only process that
## drops a child into a marker. See `sandwall/wall/pfdaemon`.

import sandwall/wall/pfdaemon

when isMainModule:
  quit(daemonMain())
