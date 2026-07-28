## wall: the network half of sandwall. Public API; grows with the
## POSIX fences in chunk 3 and the Windows fence in chunk 4.
##
##   hosts  - compiled hostname allowlist (matching semantics)
##   proxy  - threaded CONNECT+SOCKS5 proxy enforcing a HostList

import ./wall/hosts
export hosts

import ./wall/proxy
export proxy
