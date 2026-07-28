## rules: the procbox policy file format, parser, and rule model.
##
## A policy is a tiny ordered DSL, one rule per line: an access code as
## the first character, one optional separating space, and a target.
## Blank lines and `#` comments are skipped; unrecognised lines are
## skipped silently so a half-edited file still loads its valid rules.
##
## Access codes:
##
##   +  allow     - writable path, or connectable host
##   -  deny      - no read, no write, no connect
##   *  read-only - read + execute (path targets only)
##
## Target classification, by first character:
##
##   /            absolute path (POSIX)
##   X:           absolute path (Windows drive, e.g. C:\work)
##   ~            home-dir path
##   .            path relative to the project dir; a bare access code
##                with no target means the project dir itself
##   [0-9A-Za-z]  host rule: hostname, IPv4, or IPv6 address, with an
##                optional :port suffix (host:443, [::1]:8080). No port
##                means all ports (stored as port 0).
##
## `+*` is special: a host rule matching all networks, i.e. "no network
## restrictions".
##
## Rules run top-to-bottom; for paths, the last rule whose root covers a
## concrete path wins. Anything unmentioned is denied.
##
## Host rules are parsed and carried in the policy but not yet enforced:
## the network half of procbox is a separate milestone. `resolve` collects
## them so callers can see (and later apply) the intended egress set.
##
## The default policy denies root, keeps the system temp dir writable
## (shells, git, and throwaway scripts need it), and opens the project
## dir for writing:
##
##   - /
##   + /tmp
##   +
##
## Cascading: an effective policy is the concatenation of a system-level
## file and a repo-level file, parsed once, so repo rules supersede
## system rules exactly like rules within one file.

import std/[os, strutils, tables]

type
  AccessKind* = enum
    akDeny, akReadOnly, akWritable

  RuleKind* = enum
    rkPath, rkHost

  Rule* = object
    access*: AccessKind
    case kind*: RuleKind
    of rkPath:
      path*: string        ## canonical absolute path
    of rkHost:
      host*: string        ## hostname, IPv4/IPv6 literal, or "*" for all
      port*: uint16        ## 0 = all ports

  Policy* = object
    rules*: seq[Rule]

  Resolved* = object
    ## The consumed form of a policy: path roots for the filesystem
    ## backends, plus the parsed host rules for the (future) network half.
    writable*: seq[string]
    readonly*: seq[string]
    hosts*: seq[Rule]

const
  PolicyDir* = ".3code"
  PolicyFile* = "sandbox"

# ---------------------------------------------------------------- classification

proc isAbsTarget*(rest: string): bool =
  ## True when the target starts absolute: `/`, or a Windows drive root
  ## like `C:` or `C:\`.
  if rest.len == 0: return false
  if rest[0] == '/': return true
  rest.len >= 2 and rest[0] in {'A'..'Z', 'a'..'z'} and rest[1] == ':'

proc classifyTarget*(rest: string): RuleKind =
  ## Path or host, per the first-character convention in the module docs.
  if rest.len == 0: return rkPath
  let c = rest[0]
  if c in {'/', '~', '.'}: rkPath
  elif isAbsTarget(rest): rkPath
  else: rkHost

# ---------------------------------------------------------------- hosts

proc isValidHost*(h: string): bool =
  ## Hostname label rules, or an IPv4/IPv6 literal, or the bare `*`.
  if h == "*": return true
  if h.len == 0 or h.len > 253: return false
  if h.contains(':') or h.contains('['):
    # IPv6 literal, with or without brackets. Full validation is left to
    # the network half; here we only need "looks like an address".
    var v = h
    if v.startsWith("[") and v.endsWith("]"): v = v[1 .. ^2]
    return v.len > 0 and v.allCharsInSet({'0'..'9', 'a'..'f', 'A'..'F', ':'})
  if h.allCharsInSet({'0'..'9', '.'}):
    # IPv4: four 0-255 octets.
    let parts = h.split('.')
    if parts.len != 4: return false
    for p in parts:
      if p.len == 0 or p.len > 3: return false
      try:
        if parseInt(p) > 255: return false
      except ValueError:
        return false
    return true
  # Hostname: labels of [a-z0-9-], not starting/ending with '-'.
  for label in h.split('.'):
    if label.len == 0 or label.len > 63: return false
    if label[0] == '-' or label[^1] == '-': return false
    if not label.allCharsInSet({'a'..'z', 'A'..'Z', '0'..'9', '-'}):
      return false
  true

proc parseHost*(rest: string): tuple[host: string, port: uint16] =
  ## Split a host target into host and port. `host:443`, `[::1]:8080`,
  ## bare `host` / `1.2.3.4` / `::1` (port 0 = all). Raises ValueError on
  ## a bad port.
  var h = rest
  var port = 0'u16
  if h.startsWith("["):
    let close = h.find(']')
    if close > 0:
      let tail = h[close + 1 .. ^1]
      if tail.startsWith(":"):
        let p = parseInt(tail[1 .. ^1])
        if p < 0 or p > 65535:
          raise newException(ValueError, "bad port: " & tail)
        port = p.uint16
      h = h[1 .. close - 1]
  else:
    # host:port has exactly one colon; IPv6 literals have several and are
    # kept whole.
    let c1 = h.find(':')
    if c1 >= 0 and h.find(':', c1 + 1) < 0:
      let p = parseInt(h[c1 + 1 .. ^1])
      if p < 0 or p > 65535:
        raise newException(ValueError, "bad port: " & h)
      port = p.uint16
      h = h[0 .. c1 - 1]
  if not isValidHost(h):
    raise newException(ValueError, "bad host: " & rest)
  (h, port)

# ---------------------------------------------------------------- paths

proc normalizePolicyPath*(p: string; projectDir: string): string =
  ## Resolve a policy path target to an absolute, cleaned form. An empty
  ## target (the bare access code) becomes `projectDir` itself. Tilde is
  ## expanded. No symlink resolution: the policy file is hand-written and
  ## the literal cleaned form is what the user expects to match.
  var q = p.strip
  if q.len == 0: return projectDir
  if q.startsWith("~"): q = expandTilde(q)
  try:
    if isAbsolute(q): q.normalizedPath else: (projectDir / q).normalizedPath
  except CatchableError:
    q

# ---------------------------------------------------------------- parsing

proc parsePolicy*(text: string; projectDir: string): Policy =
  ## Parse policy DSL text into ordered rules. Blank lines and `#`
  ## comments are skipped. Unrecognised prefixes, bad hosts, and bad ports
  ## are skipped silently so a half-edited file still loads its valid
  ## lines (the user owns this file and can see what they wrote).
  for raw in text.splitLines:
    let line = raw.strip(leading = true, trailing = false)
    if line.len == 0 or line[0] == '#': continue
    let access =
      case line[0]
      of '-': akDeny
      of '*': akReadOnly
      of '+': akWritable
      else: continue
    var rest = if line.len > 1: line[1 .. ^1] else: ""
    rest = rest.strip(leading = true, trailing = false)
    if classifyTarget(rest) == rkPath:
      result.rules.add Rule(access: access, kind: rkPath,
                            path: normalizePolicyPath(rest, projectDir))
    else:
      try:
        let (host, port) = parseHost(rest)
        result.rules.add Rule(access: access, kind: rkHost,
                              host: host, port: port)
      except ValueError:
        continue

proc loadPolicy*(path: string; projectDir: string): Policy =
  ## Read and parse the policy file at `path`, resolving relative targets
  ## against `projectDir`. A missing file yields an empty policy.
  if not fileExists(path): return Policy()
  parsePolicy(readFile(path), projectDir)

# ---------------------------------------------------------------- cascade

proc defaultPolicyText*(): string =
  ## Deny root, keep the system temp dir writable, open the project dir.
  when defined(windows):
    "- /\n+\n"
  else:
    "- /\n+ /tmp\n+\n"

proc repoPolicyPath*(projectDir: string): string =
  projectDir / PolicyDir / PolicyFile

proc systemPolicyPath*(): string =
  ## The system-level policy: next to the user config dir. Named "3code"
  ## because 3code is the primary consumer; the file format itself is
  ## application-agnostic.
  getConfigDir() / "3code" / PolicyFile

proc parseCascaded*(sysText, repoText: string; projectDir: string): Policy =
  ## The pure, file-free core of `loadCascaded`: concatenate the two
  ## levels and parse once. Factored out so last-wins concatenation
  ## semantics can be unit-tested without touching the real files.
  parsePolicy(sysText & "\n" & repoText, projectDir)

proc loadCascaded*(projectDir: string): Policy =
  ## Build the effective policy from two levels, system then repo. Each
  ## level is the file contents when present, or the built-in default
  ## text when absent, so the sandbox is "always on" even on a fresh
  ## checkout. A repo-level `- /` cleanly resets everything above it,
  ## matching per-file last-wins semantics.
  let sysPath = systemPolicyPath()
  let sysText = if fileExists(sysPath): readFile(sysPath) else: defaultPolicyText()
  let repoPath = repoPolicyPath(projectDir)
  let repoText = if fileExists(repoPath): readFile(repoPath) else: defaultPolicyText()
  parseCascaded(sysText, repoText, projectDir)

proc cascadedFiles*(projectDir: string): tuple[system, repo: string] =
  ## The two files `loadCascaded` reads, for mtime watching and for
  ## passing to subprocesses that load the policy themselves.
  (systemPolicyPath(), repoPolicyPath(projectDir))

# ---------------------------------------------------------------- queries

proc isPathUnder*(path, root: string): bool =
  ## True when `path` equals or is nested under `root` (both cleaned
  ## absolute). Trailing separators are normalised so `/a/b` covers
  ## `/a/b/sub`. An empty `root` matches nothing.
  if root.len == 0: return false
  if path == root: return true
  let sep = when defined(windows): "\\" else: "/"
  let r = if root.endsWith(sep): root else: root & sep
  path.startsWith(r)

proc checkPath*(p: Policy; path: string): AccessKind =
  ## Effective access for a concrete absolute `path`: the last path rule
  ## whose root covers it wins. Deny when nothing covers the path, which
  ## is the safe default. Host rules never affect paths.
  result = akDeny
  for r in p.rules:
    if r.kind == rkPath and isPathUnder(path, r.path):
      result = r.access

proc resolve*(p: Policy): Resolved =
  ## Walk the ordered rules into the consumed form. Last-wins per
  ## canonical path: a later rule for a path supersedes every earlier one
  ## for that same path. Deny is the default for anything unmentioned, so
  ## deny rules only matter as overrides of earlier allows; they drop the
  ## path from both lists. Host rules pass through as-is (last-wins per
  ## host:port pair, denies dropped the same way).
  var latest: Table[string, AccessKind]
  var order: seq[string]
  for r in p.rules:
    case r.kind
    of rkPath:
      if r.path notin latest: order.add r.path
      latest[r.path] = r.access
    of rkHost:
      let key = r.host & ":" & $r.port
      if key notin latest: order.add "\x00" & key
      latest[key] = r.access
  for k in order:
    if k.startsWith("\x00"):
      let key = k[1 .. ^1]
      if latest[key] == akWritable:
        let c = key.rfind(':')
        result.hosts.add Rule(access: akWritable, kind: rkHost,
                              host: key[0 .. c - 1],
                              port: uint16(parseUInt(key[c + 1 .. ^1])))
    else:
      case latest[k]
      of akWritable: result.writable.add k
      of akReadOnly: result.readonly.add k
      of akDeny: discard

proc renderPolicy*(p: Policy): string =
  ## Human-readable dump of the effective rules, newest last (matching
  ## file order). Used by `:sandbox show` in 3code.
  if p.rules.len == 0:
    return "(no sandbox rules)"
  for r in p.rules:
    let label =
      case r.access
      of akDeny: "deny   "
      of akReadOnly: "read   "
      of akWritable: "write  "
    case r.kind
    of rkPath:
      result.add label & "  " & r.path & "\n"
    of rkHost:
      let suffix = if r.port == 0: "" else: ":" & $r.port
      result.add label & "  " & r.host & suffix & "\n"

proc appendRule*(policyFile, target: string; access: AccessKind): bool =
  ## Append a single rule to `policyFile`. The literal `target` is
  ## written as-is so relative targets stay relative and the file stays
  ## portable and human-readable. Returns false on write failure.
  let code =
    case access
    of akDeny: "-"
    of akReadOnly: "*"
    of akWritable: "+"
  let line = code & (if target.len > 0: " " & target else: "") & "\n"
  try:
    var f = open(policyFile, fmAppend)
    try: f.write(line) finally: f.close()
  except CatchableError:
    return false
  true
