## wall: the network half of sandwall. Public API.
##
##   hosts   - compiled hostname allowlist (matching semantics)
##   proxy   - threaded CONNECT+SOCKS5 proxy enforcing a HostList
##   connect - minimal SOCKS5 client (git ProxyCommand helper)
##   netns   - Linux kernel fence: netns + unix-socket bridge
##   wfp     - Windows kernel fence: WFP filters on the sandwall user
##   winuser - Windows sandwall user: setup, DPAPI creds, spawn

import ./wall/hosts
export hosts

# Proxy port range is a cross-platform constant: consumers reference it
# even when compiling for POSIX (the Windows WFP permit uses it).
import ./wall/wfp
export wfp.FirstProxyPort, wfp.LastProxyPort, wfp.validPortRange,
  wfp.sddlForUserSid, wfp.GUID, wfp.parseGuid, wfp.guidBytes,
  wfp.providerGuidText, wfp.sublayerGuidText, wfp.permitV4GuidText,
  wfp.blockV4GuidText, wfp.permitV6GuidText, wfp.blockV6GuidText

when defined(posix):
  # proxy/connect are POSIX-only today (AF_UNIX bridge, posix poll/
  # splice loops). Windows gets the fence (wfp) and the user (winuser)
  # but no in-library proxy yet; 3code runs the proxy via its own
  # POSIX binary.
  import ./wall/proxy
  export proxy

  import ./wall/connect
  export connect

when defined(linux):
  import ./wall/netns
  export netns

when defined(windows):
  export wfp.installFence, wfp.uninstallFence, wfp.fenceStatus,
    wfp.installAcFence, wfp.uninstallAcFence, wfp.acFenceStatus,
    wfp.exemptAcLoopback, wfp.unexemptAcLoopback,
    wfp.wfpProbeMain
  import ./wall/winuser
  export winuser
