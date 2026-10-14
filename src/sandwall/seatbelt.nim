## macOS Seatbelt backend for sandwall.
##
## Seatbelt is Apple's TrustedBSD MAC framework - the same kernel-enforced
## sandbox that backs the App Sandbox used by every Mac App Store application,
## and that Chromium, Firefox and Nix ship in production. Apple marked the
## in-process `sandbox_init` API deprecated in headers since 10.8 but it
## continues to ship, Apple's own apps use it, and there is no replacement.
##
## We generate a TinyScheme profile per call and apply it via
## `sandbox_init_with_parameters` in libSystem.dylib. The profile text is
## passed directly - no temp files, no helper binary. The restriction binds
## to the calling process and all descendants, matching Landlock's semantics.
##
## Seatbelt evaluates rules with last-match-wins per operation, so the
## `(deny default)` baseline blocks everything, and each emitted `(allow ...)`
## widens the policy for that path/op. Network is blocked by omission: we emit
## no `network-*` allow, so the default deny covers sockets.

import std/[os, sequtils, strutils, sets]
import ./paths
import ./baseline
import ./rules

# Seatbelt's sandbox_init family is private API: the symbols live in
# libSystem.dylib but are not in the public SDK, and `sandbox_free_errorbuf`
# in particular is not exported on every macOS release. Importing it via
# `{.importc, dynlib.}` resolves the symbol at load time, so a binary that
# only ever *calls* it on the rare error path still refuses to launch on a
# host lacking the symbol. Resolve both lazily via dlsym so the binary loads
# everywhere and a missing free-symbol degrades to a harmless one-shot leak.
type
  SandboxInitWithParams = proc(profile: cstring, flags: uint64,
        params: ptr UncheckedArray[cstring], errbuf: ptr cstring): cint {.cdecl.}
  SandboxFreeErrorbuf = proc(buf: cstring) {.cdecl.}

proc dlsym(handle: pointer; symbol: cstring): pointer
    {.importc, header: "<dlfcn.h>".}
var RTLD_DEFAULT {.importc, header: "<dlfcn.h>".}: pointer

proc loadSandboxInit(): SandboxInitWithParams =
  result = cast[SandboxInitWithParams](dlsym(RTLD_DEFAULT,
                                             "sandbox_init_with_parameters"))

proc loadSandboxFree(): SandboxFreeErrorbuf =
  result = cast[SandboxFreeErrorbuf](dlsym(RTLD_DEFAULT,
                                           "sandbox_free_errorbuf"))

# Baseline paths now live in baseline.nim (shared across OS backends).

proc privatize*(p: string): string =
  ## /tmp, /var, and /etc are symlinks into /private on macOS, and
  ## seatbelt subpath filters match the resolved vnode path, not the
  ## spelling the caller used: a rule written `allow /tmp` never fires
  ## (the child's open() lands on /private/tmp/... and misses the
  ## filter), so "writable /tmp" silently EPERMs every write - the
  ## xcrun cache and every TMPDIR compiler temp die. Rewrite the
  ## public prefixes to their /private spelling; rules already using
  ## the private spelling pass through untouched. The prefixes are
  ## disjoint, so first match wins. This module only ever reaches a
  ## macOS link, so the rewrite needs no OS gate (it also lets a
  ## Linux-side profile generator stay byte-faithful).
  for d in ["/etc", "/var", "/tmp"]:
    if p == d: return "/private" & d
    if p.startsWith(d & "/"): return "/private" & p
  return p

proc quote(s: string): string =
  ## TinyScheme string literal: wrap in double quotes, escape backslash and
  ## double quote. Paths from normalize are absolute and clean, so this is
  ## belt-and-braces.
  result = newStringOfCap(s.len + 2)
  result.add('"')
  for c in s:
    if c == '\\' or c == '"': result.add('\\')
    result.add(c)
  result.add('"')

proc buildProfile*(writable, read: openArray[string];
                  denied: openArray[string] = []; egress = true): string =
  ## Assemble the TinyScheme profile. Order is: (deny default), baseline read
  ## allows, caller write allows, caller read allows, then per-policy deny
  ## narrowing. Seatbelt evaluates last-match-wins, so the grammar's own
  ## ordering is compiled directly: a denied subpath under a writable root
  ## first splits its root (file* on the root itself, subpath allows for
  ## the surviving siblings), then takes an explicit deny, then any
  ## narrower later allows reinstate on top.
  result = newStringOfCap(4096)
  result.add("(version 1)\n(deny default)\n")

  # The sandboxed process (and anything it execs) stats `/` during
  # startup path canonicalization; without this the exec'd image
  # aborts before main (observed as SIGABRT on macOS 14+).
  result.add("(allow file-read-data (literal \"/\"))\n")
  # Seatbelt has no implicit traversal: stat'ing any path needs
  # metadata access on every ancestor, and shells die when getcwd
  # fails. Metadata (existence/type/timestamps, not content) stays
  # open globally; content rules below do the real confinement. This
  # is emitted BEFORE the per-policy denies so a `-` rule also
  # hides the denied path's metadata (last match wins).
  result.add("(allow file-read-metadata)\n")

  # Baseline: system dirs and devices the dynamic linker needs. The
  # baseline paths are OS-specific (defined in baseline.nim) and cover
  # /usr, /bin, /System, /Library, /dev/*, etc.
  result.add("(allow file-read*")
  for p in baselineRead:
    result.add("\n  (subpath " & quote(p) & ")")
  result.add(")\n")
  # Fork stays usable: shells fork for pipelines, redirects, and
  # external commands (posix_spawn covers the simple cases, but dash
  # falls back to fork() once a redirect is involved, and fork is a
  # separately gated operation).
  result.add("(allow process-fork)\n")
  # In-sandbox process control: build tools and test harnesses signal
  # the children they spawn (timeout(1), failure cleanup, maven and
  # gradle wrangling compiler daemons) and query them (proc_pidinfo via
  # libproc - what `ps` and wait-status introspection run on). Both
  # filters restrict the target to `same-sandbox`: processes already
  # inside this very profile, i.e. exactly what the command spawned.
  # The user's session and unrelated processes stay unreachable, the
  # same shape Chrome's and Codex's seatbelt profiles ship.
  result.add("(allow signal (target same-sandbox))\n")
  result.add("(allow process-info* (target same-sandbox))\n")
  # Interpreters stat the machine shape at startup (sysconf -> sysctl:
  # NPROCESSORS_ONLN and friends). `(deny default)` makes those reads
  # EPERM, and stock perl dies with `panic: sysconf: Operation not
  # permitted` before user code runs. Informational sysctl reads are
  # harmless; writes stay denied by omission.
  result.add("(allow sysctl-read)\n")
  # One deliberate exception to "writes stay denied": the JVM reads
  # kern.grade_cputype at startup (which CPU grade it runs on - native
  # arm64 or Rosetta - picks JIT code paths), but the kernel registers
  # that sysctl CTL_RW, so Seatbelt classifies every access to it,
  # reads included, as sysctl-write and the sysctl-read allow above
  # never fires. Without this line java/javac die before main, and no
  # path rule can fix it (codex hit the same wall: openai/codex#3978).
  result.add("(allow sysctl-write (sysctl-name \"kern.grade_cputype\"))\n")
  # getpwnam/getpwuid (user name, home dir, shell) are served by
  # opendirectoryd over this mach service; `(deny default)` makes the
  # bootstrap lookup EPERM and every libc-level user lookup fails.
  # The JVM resolves user.home through it at startup. Read-only name
  # resolution only - the service answers lookups, it is not a general
  # directory write path (Chromium ships the same allow: crbug 792228).
  result.add("(allow mach-lookup (global-name \"com.apple.system.opendirectoryd.libinfo\"))\n")
  # Exec follows the readable set, not a hand-picked four directories:
  # python3 on a stock macOS box is an xcrun shim that re-execs the real
  # binary under /Library/Developer/CommandLineTools, and brew lives in
  # /opt - both readable per the baseline above. Linux confers no exec
  # restriction at all, so exec-of-the-readable is parity, not widening.
  result.add("(allow process-exec file-read*\n")
  for p in baselineRead:
    result.add("\n  (subpath " & quote(p) & ")")
  result.add(")\n")
  # Writable baseline devices (/dev/null).
  if baselineWrite.len > 0:
    result.add("(allow file-write* file-read*")
    for p in baselineWrite:
      result.add("\n  (subpath " & quote(p) & ")")
    result.add(")\n")

  # Caller paths. Dedup after normalising so the same dir passed in both
  # writable and read only emits one rule.
  var seen = initHashSet[string]()
  var wpaths: seq[string] = @[]
  var rpaths: seq[string] = @[]
  for p in writable:
    let n = privatize(paths.normalize(p))
    if n.len == 0 or seen.containsOrIncl(n): continue
    wpaths.add(n)
  for p in read:
    let n = privatize(paths.normalize(p))
    if n.len == 0 or seen.containsOrIncl(n): continue
    rpaths.add(n)

  # Denies are matched against the raw caller paths (pre-dedup), then
  # normalised with the same helper.
  var deniedN: seq[string] = @[]
  for p in denied:
    let n = privatize(paths.normalize(p))
    if n.len > 0 and not deniedN.contains(n): deniedN.add(n)

  # Caller paths carry exec with them (the module contract: writable
  # is full access, read-only is read + execute). Without process-exec
  # here a compiled ./a.out in the project dir fails with EPERM on
  # macOS while running fine on Linux.
  for w in wpaths:
    result.add("(allow process-exec file-write* file-read*\n  (subpath " & quote(w) & "))\n")
  for p in rpaths:
    result.add("(allow process-exec file-read*\n  (subpath " & quote(p) & "))\n")
  # A read-only path under a writable root must subtract the write the
  # root just granted: readonly is a narrowing, not an annotation. Emit
  # a write-deny after the allows so last-match-wins punches the hole.
  # Covers the path itself and everything below it.
  for p in rpaths:
    result.add("(deny file-write*\n  (subpath " & quote(p) & ")")
    result.add("\n  (literal " & quote(p) & "))\n")
  # Denies last: Seatbelt is last-match-wins, so a trailing deny
  # reliably punches a hole in the broader allows above. (Putting
  # denies first and splitting the allow around them was tried; the
  # literal+sibling shape cannot express "dir contents minus subpath"
  # and breaks file creation in the writable root.)
  for d in deniedN:
    result.add("(deny process-exec file-write* file-read* file-read-metadata\n  (subpath " & quote(d) & ")")
    result.add("\n  (literal " & quote(d) & "))\n")

  if not egress:
    # Network fence: permit loopback only, so the sandbox can reach the
    # wall proxy on the host's 127.0.0.1 and nothing else. No explicit
    # network deny is emitted: the (deny default) baseline covers the
    # rest by omission. DNS stays fenced - the proxy resolves (impl-plan
    # decision 8).
    result.add("(allow network-outbound (remote ip \"localhost:*\"))\n")
    result.add("(allow network-inbound (local ip \"localhost:*\"))\n")
  else:
    # Open network: a policy without host rules means "no network
    # restriction", but (deny default) covers sockets too, so the open
    # case needs explicit allows or every connect() dies on macOS (on
    # Linux the same policy simply never enters a netns).
    result.add("(allow network-outbound)\n")
    result.add("(allow network-inbound)\n")

proc backendSupported*(): bool = true

proc backendName*(): string = "seatbelt"

proc restrictImpl*(writable, read: openArray[string];
                    denied: openArray[string] = []; egress = true) =
  ## Confine the calling thread via a Seatbelt profile. Writable paths get
  ## full access, read paths get read + execute (via the file-read* allow on
  ## system dirs that makes exec work), everything else is denied. With
  ## `egress = false` the only permitted network is loopback - the wall
  ## proxy listens on the host's 127.0.0.1, which the sandbox reaches
  ## directly (no bridge needed on macOS). The profile is rebuilt from
  ## scratch each call - no state, matching Landlock.
  let init = loadSandboxInit()
  if init.isNil:
    raise newException(OSError,
      "sandwall: seatbelt unavailable (sandbox_init_with_parameters not found)")
  let profile = buildProfile(writable, read, denied, egress)
  var errbuf: cstring = nil
  let r = init(profile.cstring, 0'u64, nil, addr errbuf)
  if r != 0:
    var msg = "seatbelt: profile rejected"
    if errbuf != nil:
      try: msg = "seatbelt: " & $errbuf
      except CatchableError: discard
      let freeFn = loadSandboxFree()
      if not freeFn.isNil: freeFn(errbuf)
    raise newException(OSError, "sandwall: " & msg)
