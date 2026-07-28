## macOS Seatbelt backend for procbox.
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

proc directSubdirs(root: string): seq[string] =
  ## Immediate child directories of `root`, skipping unreadable entries.
  for kind, p in walkDir(root, relative = false):
    if kind == pcDir: result.add p

proc splitAround(root: string; denied: openArray[string]): seq[string] =
  ## The parts of `root` that remain allowed after removing the denied
  ## subpaths: `root` itself (file* ops, so no recursion) plus the sibling
  ## subdirectories at every level down to each denied path. The denied
  ## paths themselves are emitted as explicit denies afterwards.
  result.add(root)
  for d in denied:
    var anc = d.parentDir
    while isPathUnder(anc, root) and anc != root.parentDir and anc.len > root.len:
      for sub in directSubdirs(anc):
        if sub == d or isPathUnder(sub, d) or isPathUnder(d, sub): continue
        result.add(sub)
      anc = anc.parentDir

proc buildProfile(writable, read: openArray[string];
                  denied: openArray[string] = []): string =
  ## Assemble the TinyScheme profile. Order is: (deny default), baseline read
  ## allows, caller write allows, caller read allows, then per-policy deny
  ## narrowing. Seatbelt evaluates last-match-wins, so the grammar's own
  ## ordering is compiled directly: a denied subpath under a writable root
  ## first splits its root (file* on the root itself, subpath allows for
  ## the surviving siblings), then takes an explicit deny, then any
  ## narrower later allows reinstate on top.
  result = newStringOfCap(4096)
  result.add("(version 1)\n(deny default)\n")

  # Baseline: system dirs and devices the dynamic linker needs. The
  # baseline paths are OS-specific (defined in baseline.nim) and cover
  # /usr, /bin, /System, /Library, /dev/*, etc.
  result.add("(allow file-read*")
  for p in baselineRead:
    result.add("\n  (subpath " & quote(p) & ")")
  result.add(")\n")
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
    let under = deniedN.filterIt(isPathUnder(it, w))
    if under.len == 0:
      result.add("(allow file-write* file-read*\n  (subpath " & quote(w) & "))\n")
    else:
      # Root narrowed by denies: the root itself as a literal-level rule
      # plus the surviving sibling subtrees; denied subtrees are denied
      # below.
      result.add("(allow file-write* file-read*\n  (literal " & quote(w) & ")")
      for s in splitAround(w, under):
        if s != w:
          result.add("\n  (subpath " & quote(s) & ")")
      result.add(")\n")
  for p in rpaths:
    let under = deniedN.filterIt(isPathUnder(it, p))
    if under.len == 0:
      result.add("(allow file-read*\n  (subpath " & quote(p) & "))\n")
    else:
      result.add("(allow file-read*\n  (literal " & quote(p) & ")")
      for s in splitAround(p, under):
        if s != p:
          result.add("\n  (subpath " & quote(s) & ")")
      result.add(")\n")
  for d in deniedN:
    result.add("(deny file-write* file-read*\n  (subpath " & quote(d) & ")")
    result.add("\n  (literal " & quote(d) & "))\n")

proc backendSupported*(): bool = true

proc backendName*(): string = "seatbelt"

proc restrictImpl*(writable, read: openArray[string];
                    denied: openArray[string] = []) =
  ## Confine the calling thread via a Seatbelt profile. Writable paths get
  ## full access, read paths get read + execute (via the file-read* allow on
  ## system dirs that makes exec work), everything else is denied. The
  ## profile is rebuilt from scratch each call - no state, matching Landlock.
  let init = loadSandboxInit()
  if init.isNil:
    raise newException(OSError,
      "procbox: seatbelt unavailable (sandbox_init_with_parameters not found)")
  let profile = buildProfile(writable, read, denied)
  var errbuf: cstring = nil
  let r = init(profile.cstring, 0'u64, nil, addr errbuf)
  if r != 0:
    var msg = "seatbelt: profile rejected"
    if errbuf != nil:
      try: msg = "seatbelt: " & $errbuf
      except CatchableError: discard
      let freeFn = loadSandboxFree()
      if not freeFn.isNil: freeFn(errbuf)
    raise newException(OSError, "procbox: " & msg)
