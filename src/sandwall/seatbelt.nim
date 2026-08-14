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
  # Exec stays usable for system binaries.
  result.add("(allow process-exec file-read*\n")
  result.add("  (subpath " & quote("/bin") & ")\n")
  result.add("  (subpath " & quote("/sbin") & ")\n")
  result.add("  (subpath " & quote("/usr/bin") & ")\n")
  result.add("  (subpath " & quote("/usr/sbin") & ")\n")
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
    let n = paths.normalize(p)
    if n.len == 0 or seen.containsOrIncl(n): continue
    wpaths.add(n)
  for p in read:
    let n = paths.normalize(p)
    if n.len == 0 or seen.containsOrIncl(n): continue
    rpaths.add(n)

  # Denies are matched against the raw caller paths (pre-dedup), then
  # normalised with the same helper.
  var deniedN: seq[string] = @[]
  for p in denied:
    let n = paths.normalize(p)
    if n.len > 0 and not deniedN.contains(n): deniedN.add(n)

  for w in wpaths:
    result.add("(allow file-write* file-read*\n  (subpath " & quote(w) & "))\n")
  for p in rpaths:
    result.add("(allow file-read*\n  (subpath " & quote(p) & "))\n")
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
    result.add("(deny file-write* file-read* file-read-metadata\n  (subpath " & quote(d) & ")")
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
