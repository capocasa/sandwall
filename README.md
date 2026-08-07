# sandwall

A process sandbox for Nim, backed by OS-native primitives: Linux
[Landlock](https://docs.kernel.org/userspace-api/landlock.html) plus a
network-namespace egress fence, and macOS
[Seatbelt](https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/Articles/Sandboxing.html).
Restrict a process (and every child it spawns) to a fixed set of writable
paths and a fixed set of connectable hosts. No root, no container, no
helper binary, ~no runtime cost.

Both backends use the same mechanism shape: an unprivileged process applies
a restriction to itself, and the kernel enforces it on every syscall from
the thread and all of its descendants. `mv`, `tee`, `rm -rf`, a rogue build
script, it doesn't matter, the kernel checks every write.

## Two layers, one call

```nim
restrict(rules)            # parsed policy: fs rules first, then the net wall
forkNimbox / exec          # fork a child, where you restrict() then exec()
```

`restrict` locks the current thread down: filesystem access per the
policy's path rules, network egress per its host rules. `forkNimbox` +
`exec` run a sandboxed child. The low-level
`restrict(writable, read, denied)` form is still there when you want to
skip the policy layer.

## Platform status

| Platform | Filesystem | Network fence |
|----------|-----------|-------------|
| Linux | Landlock | netns (fresh namespace, loopback only) + allowlist proxy |
| macOS | Seatbelt `sandbox_init_with_parameters` | Seatbelt loopback-only + allowlist proxy |
| Windows | AppContainer (lowbox token) + DACL grants | WFP fence (after `sandwall setup`): loopback-only + allowlist proxy; without setup: open + warning |

The Linux and macOS backends confine the calling thread via kernel hooks
(Landlock domains, Seatbelt profiles). The Windows backend has no single
syscall hook; it runs the child in an **AppContainer** (a lowbox token that
denies filesystem and network by default), stamping ALLOW ACEs and a Low
integrity label for the AppContainer SID on each writable path and a
read+execute grant on each read-only path. The stamps roll back after the
child exits. See `CROSSPLATFORM.md` for the design and
`sandbox-research.md` for the prior-art survey.

Windows notes:
- Network semantics: a policy with **no host rules** leaves the
  network working (the AppContainer child gets the `internetClient`
  capability). A policy **with host rules** requires a one-time
  `sandwall setup` (elevated) to install WFP (Windows Filtering
  Platform) filters that confine the AppContainer child to loopback.
  The per-run wall proxy (in the unrestricted parent) then enforces
  the hostname allowlist. **Without** `sandwall setup`, host rules
  produce a warning and the child has OPEN network access (accepted
  degrade posture). The WFP fence uses ALE_USER_ID conditions keyed
  on the `sandwall.fs` AppContainer SID.
- A `cmd` inside the sandbox can run further executables by **bare name or
  relative path** (`myexe`, `.\myexe`, `sub\myexe`) resolved against the
  current directory, but **not** by drive-letter absolute path:
  `cmd /c C:\path\some.exe` fails "Access is denied" (a cmd/AppContainer
  quirk that affects even System32 exes). Run user-built executables
  directly (`sandwall rules -- myexe`) or `cd` into their directory and
  invoke them by name.

## Requirements

- Linux 5.19+ (Landlock ABI v2, for `REFER`/`TRUNCATE`). 6.2+ covers all
  access rights used here.
- Nim 2.0+.

## As a binary

```
sandwall RULES [--] CMD [ARGS ...]
```

RULES is a policy file (`-` reads it from stdin). The sandbox applies the
file's path rules to the filesystem and its host rules to the network,
then exec()s CMD. System directories (`/usr`, `/bin`, `/lib`, `/etc`) are
made read-only automatically so the command's binaries stay runnable.

```sh
$ sandwall rules.txt -- make test
$ sandwall rules.txt curl https://api.example.com
$ cat rules.txt | sandwall - -- ls -la
```

The same binary is also the library, so a parent program can self-invoke
via `/proc/self/exe` to run a sandboxed child without a separate helper.

## The network wall

Host rules in the policy fence egress. The kernel restricts the process
to loopback (a fresh network namespace on Linux, a loopback-only Seatbelt
profile on macOS); a per-run proxy, forked before the restriction lands,
is the only way off the machine and enforces the hostname allowlist. The
proxy speaks HTTP CONNECT and SOCKS5, and `restrict` points the standard
proxy env vars at it (`http_proxy`, `https_proxy`, `ALL_PROXY` with
`socks5h` so DNS happens at the proxy), so curl, wget, and most HTTP
libraries just work.

```sh
$ cat rules.txt
allow /tmp
allow api.example.com
$ sandwall rules.txt curl https://api.example.com   # works
$ sandwall rules.txt curl https://elsewhere.com     # 403 from the proxy
```

Editing the rules file mid-run takes effect on the next connection: the
proxy watches its policy file's mtime. The proxy dies with the command
tree (death pipe), one proxy per run, never a shared instance.

Two honest limitations:

- **Plain `http://` through `http_proxy` does not work.** A CONNECT
  proxy only tunnels; plain-HTTP proxying is a different protocol
  (GET-forwarding) and gets a 405. Use https (everything should anyway)
  or the SOCKS5 side, which tools pick up from `ALL_PROXY`.
- **UDP is not forwarded.** No QUIC/HTTP3 (clients fall back to TCP),
  no DNS from inside the fence (by design: resolution happens at the
  proxy). Anything hard-requiring UDP fails closed.

ssh does not read proxy env vars, so git-over-ssh needs an adapter:
`sandwall connect HOST PORT` pumps stdio through the proxy, made for
ssh's ProxyCommand:

```sh
export GIT_SSH_COMMAND="ssh -o ProxyCommand='sandwall connect %h %p'"
```

(Setting that variable is the consumer's job, sandwall only provides the
adapter.)

## The policy file

The `rules` module parses a tiny line-based policy DSL, shared by every
consumer so the sandbox subprocess and the host program evaluate paths
with the same code. One rule per line: an access word, arbitrary
whitespace, and a target.

```
deny /              deny everything under root
allow /tmp          writable
allow               writable project dir (bare word = project dir)
readonly /var           read-only
deny ./secrets      deny, relative to the project dir
allow api.example.com   host rule (fenced through the wall proxy)
allow 10.0.0.1:8080 host with port (bare host = all ports)
allow *             no network restrictions
```

The target's first character classifies it: `/` or `C:` absolute path,
`~` home path, `.` project-relative path, alnum host (hostname, IPv4,
IPv6, optional `:port`). Later rules supersede earlier ones for the
targets they name; anything unmentioned is denied. `#` comments and
blank lines are ignored. A line starting with no access word is treated
as a host rule, so hostnames like `deny.corp.internal` still parse.

Host rules fence networking per the previous section: the first host
rule turns egress loopback-only, and the wall proxy enforces the
allowlist. `allow *` allows every host through the proxy (the fence
still applies; direct egress stays blocked).

```nim
let rules = loadPolicy(path, projectDir)  # one file; discovery/cascade is the caller's job
let rules2 = parsePolicy(text, projectDir)
case rules.checkPath(somePath)            # akWritable / akReadOnly / akDeny
let r = rules.resolve()                   # (writable, readonly, denied, hosts)
restrict(rules, projectDir, policyPath = path)   # fs + net, one call
```

A policy is a plain `seq[Rule]`; there is no wrapper object. File
discovery, level cascading, and default rules belong to the consumer
(3code concatenates its system and repo files and parses once; later
text supersedes earlier exactly like rules within one file).

Two backend caveats to know before writing tricky policies:

- **Sub-path narrowing is not kernel-enforced.** The backends consume
  the resolved (writable, readonly) root lists, which are not
  subtractive: a deny or read-only rule for a path *under* a writable
  root has no effect on the sandboxed process (Landlock unions rules
  within a layer; the Seatbelt profile emits allows only). Deny
  overrides work for disjoint roots. `checkPath` (used by host programs
  for in-process gating) does honor nested last-wins exactly, so
  in-process checks are stricter than the kernel boundary.
- **Policy files under a writable root stay writable on Linux.**
  Landlock unions rules within a layer, so force-adding the policy file
  read-only does not subtract write (Seatbelt and Windows ACLs do
  subtract). Put hard boundaries in a policy file outside every
  writable root.

## As a library

```nim
import sandwall

# fork a child, restrict it, exec the untrusted command, wait
let pid = forkNimbox()
if pid == 0:
  restrict(["/tmp", "/home/me/work"], read = ["/usr", "/bin", "/lib"])
  exec(["ls", "-la"])
  exitnow(127)   # only if exec failed
let code = wait(pid)

# the parent never called restrict, so it stays fully privileged
```

Or just call `restrict` on yourself, if you don't need to stay free:

```nim
restrict(["/tmp", "/home/me/work"])          # paths only
restrict(rules, projectDir, policyPath)       # full policy, fs + net
```

## The `restrict` proc

```nim
proc restrict(writable: openArray[string]; read: openArray[string] = [])
```

`writable` paths get full access (read, write, create, delete, rename,
execute). `read` paths get read + execute only; defaults to empty. Everything
else is denied. Each call layers a new Landlock domain; the effective access
is the intersection of all applied domains, so later calls only **narrow**
the window. Drop a path from `writable` and re-call to revoke it.

### Why there's no un-restrict

Landlock is monotonic: once a domain is applied it can only get stricter,
never looser. There is no `unrestrict`, no escape hatch, and `fork`/`exec`
inherit the domain. This is the property that makes a sandbox a sandbox.

The practical consequence: to run a sandboxed command while staying free
yourself, **fork first**, then `restrict` in the child. The parent never
restricts. That's what `forkNimbox` is for.

## What gets caught

Every filesystem mutation Landlock knows: `write`, `creat`, `unlink`,
`rename` (so `mv`), `mkdir`, `rmdir`, `symlink`, `truncate`, `ftruncate`,
`link`, cross-directory reparent. Read and execute are gated too.

Not yet restricted by Landlock (kernel caveats): `chdir`, `stat`, `flock`,
`chmod`, `chown`, `setxattr`, `utime`, `access`. Mostly safe for a coding
agent; the dangerous ops are covered.

## Running the demo

```sh
nim c --path:src -r tests/demo.nim
```

Forks a child that runs `ls` sandboxed, then shows the parent still writing
freely outside the sandbox.

## Tests

```sh
nimble test
```

CLI tests shell out to the binary; library tests fork a child per scenario
(since a Landlock domain is permanent for the thread that applies it).

## Layout

```
src/
  sandwall.nim           # library + CLI (when isMainModule)
  sandwall/
    restrict.nim       # the restrict() procs - paths form and rules form
    process.nim        # forkNimbox / exec / wait (posix fork-exec)
    paths.nim          # path normalisation, shared across backends
    rules.nim          # policy DSL: parsePolicy / loadPolicy / resolve
    landlock.nim       # linux backend: Landlock ruleset
    seatbelt.nim       # macos backend: sandbox_init_with_parameters
    acl.nim            # windows backend: restricted token + ACLs
    mask.nim           # linux userns+mountns for sub-path deny masks
    wall/
      hosts.nim        # hostname allowlist matching
      proxy.nim        # CONNECT+SOCKS5 proxy, spawnWallProxy (forked)
      connect.nim      # SOCKS5 stdio adapter (ssh ProxyCommand)
      netns.nim        # linux fence: netns + unix-socket bridge
      wfp.nim          # windows fence: WFP filters
      winuser.nim      # windows sandwall user + spawn
tests/
  demo.nim
  test_sandbox.nim     # CLI + library fs tests, fenced-network CLI test
  test_rules.nim       # policy DSL
  test_hosts.nim       # host matching
  test_proxy.nim       # CONNECT/SOCKS proxy against a live echo server
  test_connect.nim     # socks client adapter
  test_wall.nim        # netns fence + bridge (linux)
  test_winwall.nim     # wfp pure logic (guids, sddl)
```

See `sandbox-research.md` for the full prior-art survey (sandlock, Codex,
Anthropic sandbox-runtime) and why the OS primitive beats command
whitelisting.

## License

MIT.
