# Network sandboxing research (sandwall/sandwall "wall")

Goal: per-process network restriction to complement sandwall's filesystem
sandbox, with the same shape: an unprivileged launcher applies OS-native
restrictions to itself, then exec()s; the kernel enforces on every child.
Policy is a list of allowed hosts/IPs (+ ports), deny by default, `*` for
unsandboxed.

## The hard constraint: nobody filters by IP/hostname at the syscall layer

Every platform's native per-process mechanism caps out below
"allow api.stripe.com":

- **Linux Landlock (ABI v4, kernel 6.7+)**: `LANDLOCK_ACCESS_NET_CONNECT_TCP`
  / `BIND_TCP` keyed on **port number only**. No IP, no hostname. (ABI v10
  adds UDP, same shape.) This is the only unprivileged, in-kernel,
  self-applied network restriction on Linux. Codex's linux-sandbox layers
  seccomp-bpf for total network denial, nothing finer.
- **macOS Seatbelt**: `(allow network-outbound (remote ip "HOST:PORT"))`
  where HOST must be `*` or `localhost` (this is enforced by the SBPL
  compiler itself). Per-host filtering is structurally impossible; the
  security.stackexchange verdict and Microsoft's mxc profile_builder both
  confirm allowedHosts degrades to allow-all as best effort.
- **Windows**: WFP (Windows Filtering Platform) filters support
  remote-IP/port conditions, but they are **machine-wide, admin-installed**,
  keyed to a user SID (`ALE_USER_ID`), not to a process tree. Both Codex
  (CodexSandboxOffline user + WFP filters installed by an elevated setup
  helper) and Anthropic's sandbox-runtime (`srt-sandbox` account + 4
  persistent filters) do the same thing: create a dedicated local user at
  elevated setup time, block all egress for that SID except loopback to a
  proxy port range. There is no unprivileged per-process network primitive
  on Windows. Codex's unelevated first attempt fell back to env-var
  poisoning (`HTTPS_PROXY=http://127.0.0.1:9`, PATH stubs) precisely
  because nothing else exists.

## What actually works for hostname policy: the proxy pattern

Both production agent sandboxes (Anthropic sandbox-runtime / Claude Code,
OpenAI Codex) converge on the same architecture for per-domain egress:

1. Kernel fence restricts the sandboxed process to **loopback only**
   (or removes the network namespace entirely on Linux via bwrap
   `--unshare-net` + socat bridges over Unix sockets).
2. A proxy on the host (HTTP CONNECT + SOCKS5) receives all traffic and
   enforces the domain allowlist/denylist per request, returning 403.
3. Proxy env vars (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`,
   `GIT_SSH_COMMAND` etc.) point well-behaved tools at the proxy. The
   kernel fence catches tools that ignore env vars.

Properties that matter for us:

- Hostname filtering lives in the proxy, where DNS names exist. The kernel
  only sees IPs, and by the time a syscall happens the hostname is gone.
- Proxy does not terminate TLS: the allow decision uses the CONNECT
  hostname. Domain fronting remains a known bypass (accepted by both
  vendors; the threat model is "well-behaved tool under policy", not
  "actively malicious binary with arbitrary code execution").
- Allowlist is runtime-reloadable in the proxy without restarting the
  sandboxed process (srt `updateConfig()`), which matches our
  mtime-reload requirement nicely: only the proxy needs fresh rules, the
  kernel fence (loopback-only) never changes.
- IP-literal bypass doesn't work when DNS is also fenced: direct
  `connect()` to a non-loopback IP fails at the kernel, so "curl the IP
  directly" dies. Only traffic through the proxy gets filtered by name.
  For literal IPs in the policy (our `+1.2.3.4`), the proxy can allow
  CONNECT by IP without DNS.

## Recommended design for sandwall

Three tiers, applied in order of preference:

1. **Linux, kernel 6.7+ (Landlock ABI v4)**: Landlock net rules. Policy
   reduces to a set of allowed remote ports. Pure IP policies can't be
   expressed; hostname policies can't either. Two honest sub-modes:
   - policy has no net rules: handle nothing (unchanged, unrestricted).
   - policy has `*` or any host rule: we cannot express "only these hosts"
     in Landlock. Options: (a) handle CONNECT_TCP with the union of ports
     (default 443/80) as a coarse fence, (b) go full proxy mode (below)
     with Landlock denying all non-loopback connect... but Landlock can't
     distinguish loopback either. So Landlock-only mode is a port fence,
     useful but coarse. Deny-all networking (`-` rules only, or an empty
     allow set with fencing requested) IS expressible: handle
     CONNECT_TCP+BIND_TCP with zero rules.
2. **macOS**: Seatbelt profile generation, same as today, extended with
   `(allow network-outbound (remote ip "localhost:*"))` +
   `(deny network-outbound)` otherwise, plus the mDNSResponder literal for
   DNS when policy is non-empty. This is exactly the srt/Claude Code
   backstop. Combined with a wall proxy on localhost for hostname
   filtering. `+localhost` / loopback-only policies are natively
   expressible.
3. **Windows**: restricted-token sandbox already runs the child; extend to
   a dedicated sandbox user + WFP filters (admin setup step, idempotent,
   like Codex/srt). Without elevation, only env-var poisoning is possible,
   document as best effort. Loopback permit to the proxy port range, block
   all other egress for the sandbox SID.

The proxy (`sandwall proxy`) is a single Nim process started on demand by
the parent (3code): HTTP CONNECT + SOCKS5, allowlist checked per CONNECT
host (exact, `*.` suffix wildcard, IP literal). It rereads the policy on
SIGHUP or polls mtime itself, so config edits apply without restarting
anything. The sandboxed env gets `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`/
`NO_PROXY=localhost`.

DNS: when fenced, the sandboxed process can't resolve (macOS: allow only
mDNSResponder; Linux: port 53 closed). Proxy resolves. This kills the
DNS-exfiltration channel too.

## What this means for the rule model

Host rules keep their literal meaning (hostname/IP, optional port suffix
`host:port`), but enforcement granularity differs per tier:

- proxy tier: exact hostname/IP + port (full fidelity)
- Landlock tier: port only (documented degradation)
- Seatbelt tier: loopback-vs-world + proxy (full fidelity via proxy)
- WFP tier: loopback-vs-world + proxy (full fidelity via proxy)

`+host` with no port = 443 + 80 (web default) at the proxy; the proxy
accepts any port for an allowed IP literal.
