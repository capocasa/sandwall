## wall: the network half of sandwall. Public API.
##
##   hosts   - compiled hostname allowlist (matching semantics)
##   permit  - hostname rules as resolved address sets
##   dns     - the fence DNS codec and the fake-IP pool (Linux raw mode)
##   proxy   - threaded CONNECT+SOCKS5 proxy enforcing a HostList
##   connect - minimal SOCKS5 client (git ProxyCommand helper)
##   netns   - Linux kernel fence: netns + unix-socket bridges, nft
##             redirect, fence DNS relay (raw mode), or env mode
##   wfp     - Windows kernel fence: WFP filters on the sandwall user
##   winuser - Windows sandwall user: setup, DPAPI creds, spawn

import ./wall/hosts
export hosts
import ./wall/dns
export dns

# Proxy port range is a cross-platform constant: consumers reference it
# even when compiling for POSIX (the Windows WFP permit uses it).
import ./wall/wfp
export wfp.FirstProxyPort, wfp.LastProxyPort, wfp.validPortRange,
  wfp.sddlForUserSid, wfp.GUID, wfp.parseGuid, wfp.guidBytes,
  wfp.sublayerGuidText, wfp.permitV4GuidText,
  wfp.blockV4GuidText, wfp.permitV6GuidText, wfp.blockV6GuidText,
  wfp.PermitFilter, wfp.permitFilters, wfp.MaxPermitFilters,
  wfp.PermitStampError

import ./wall/proxy
export proxy

when defined(posix):
  # connect is the SOCKS5 stdio pump for git ProxyCommand; the netns
  # bridge story is POSIX-only, so is this. The proxy itself (above)
  # compiles on Windows too (WSAPoll portability layer).
  import ./wall/connect
  export connect

when defined(linux):
  import ./wall/netns
  export netns

when defined(windows):
  import ./wall/stdio
  export stdio
  export wfp.installFence, wfp.uninstallFence, wfp.fenceStatus,
    wfp.installAcFence, wfp.uninstallAcFence, wfp.acFenceStatus,
    wfp.exemptAcLoopback, wfp.unexemptAcLoopback,
    wfp.wfpProbeMain, wfp.PermitStamp, wfp.stampPermits, wfp.clearPermits,
    wfp.grantPermitStamping, wfp.wfpStampProbeMain, wfp.dnsServers
  import ./wall/winuser
  export winuser
