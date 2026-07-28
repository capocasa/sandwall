## wall: the network half of sandwall. Public API; the Windows fence
## lands in chunk 4.
##
##   hosts   - compiled hostname allowlist (matching semantics)
##   proxy   - threaded CONNECT+SOCKS5 proxy enforcing a HostList
##   connect - minimal SOCKS5 client (git ProxyCommand helper)
##   netns   - Linux kernel fence: netns + unix-socket bridge

import ./wall/hosts
export hosts

import ./wall/proxy
export proxy

import ./wall/connect
export connect

when defined(linux):
  import ./wall/netns
  export netns
