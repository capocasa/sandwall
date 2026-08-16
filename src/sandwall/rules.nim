## rules: the sandwall policy file format, parser, and rule model.
##
## A policy is a tiny ordered DSL, one rule per line: an access word,
## arbitrary whitespace, and a target. Blank lines and `#` comments are
## skipped; unrecognised lines are skipped silently so a half-edited
## file still loads its valid rules.
##
## Access words:
##
##   allow    allow    - writable path, or connectable host
##   deny     deny     - no read, no write, no connect
##   readonly readonly - read + execute (path targets only)
##
## A verb only matches at a word boundary (end of line or whitespace
## after it), so hostnames that begin with the same letters
## (`deny.corp.internal`) stay host rules.
##
## Target classification, by first character:
##
##   /            absolute path (POSIX)
##   X:           absolute path (Windows drive, e.g. C:\work)
##   ~            home-dir path
##   .            path relative to the project dir (`./foo`); a bare
##                access word with no target means the project dir
##                itself
##   (else)       host rule: hostname, IPv4, or IPv6 address, with an
##                optional :port suffix (host:443, [::1]:8080). No port
##                means all ports (stored as port 0). A bare word is a
##                host, never a path; targets that fail host validation
##                are dropped
##
## `allow *` is special: a host rule matching all networks, i.e. "no
## network restrictions".
##
## Display and append contract path targets back to the portable form:
## under the project dir as `./name` (bare target for the project dir
## itself), under home as `~/...`; everything else stays absolute.
## Internal rule storage keeps canonical absolute paths.
##
## Rules run top-to-bottom; for paths, the last rule whose root covers a
## concrete path wins. Anything unmentioned is denied.
##
## Host rules are the seam for the network wall: `resolve` collects
## them and `restrict` enforces them (hostname-allowlist proxy behind a
## kernel loopback fence).
##
## A policy here is a plain `seq[Rule]`; there is no wrapper object.
## File discovery, level cascading, and default rules are the
## consumer's job (3code): concatenate the texts you want and call
## `parsePolicy` once.

import std/[os, strutils, tables]
import ./baseline
import ./paths
export paths.isPathUnder

type
  AccessKind* = enum
    akDeny, akReadOnly, akWritable

  RuleKind* = enum
    rkPath, rkHost

  Rule* = object
    access*: AccessKind
    hidden*: bool      ## Guard rules: enforced, but not rendered
    case kind*: RuleKind
    of rkPath:
      path*: string        ## canonical absolute path
    of rkHost:
      host*: string        ## hostname, IPv4/IPv6 literal, or "*" for all
      port*: uint16        ## 0 = all ports

  Resolved* = object
    ## The consumed form of a policy: path roots for the filesystem
    ## backends, plus the parsed host rules for the (future) network half.
    writable*: seq[string]
    readonly*: seq[string]
    denied*: seq[string]
      ## Paths a later rule re-denied after an earlier allow. Under
      ## last-wins these are shadowed in the writable/readonly lists, so
      ## backends that only see those lists would wrongly allow them;
      ## the backends enforce them on top (Seatbelt/Windows subtract
      ## natively, Linux bind-masks them in a mount namespace).
    hosts*: seq[Rule]

# ---------------------------------------------------------------- classification

proc isAbsTarget*(rest: string): bool =
  ## True when the target starts absolute: `/`, or a Windows drive root
  ## like `C:` or `C:\`.
  if rest.len == 0: return false
  if rest[0] == '/': return true
  rest.len >= 2 and rest[0] in {'A'..'Z', 'a'..'z'} and rest[1] == ':'

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
  # Hostname: labels of [a-z0-9-], not starting/ending with '-'. A
  # leading `*.` label arms the suffix-wildcard form and validates the
  # rest as an ordinary hostname.
  var v = h
  if v.startsWith("*."): v = v[2 .. ^1]
  if v.len == 0: return false
  for label in v.split('.'):
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

proc classifyTarget*(rest: string): RuleKind =
  ## Path or host, per the first-character convention in the module
  ## docs: `./foo` is a path, a bare `foo` is a host. Targets that
  ## fail host validation are dropped by parseHost, never re-read as
  ## paths.
  if rest.len == 0: return rkPath
  let c = rest[0]
  if c in {'/', '~', '.'}: rkPath
  elif isAbsTarget(rest): rkPath
  else: rkHost

# ---------------------------------------------------------------- paths

proc canonicalForDisplay(p: string): string =
  ## Symlink-resolved form for display contraction only. macOS returns
  ## /var/... from $TMPDIR but /private/var/... from getcwd; comparing
  ## one against the other without resolving makes every temp-dir path
  ## miss the project prefix and render absolute. Resolution is
  ## prefix-wise: realpath fails on paths that do not exist yet, so
  ## resolve the longest existing ancestor and re-append the tail.
  var dir = p
  var tail = ""
  while dir.len > 0:
    try:
      let r = expandFilename(dir)
      if r.len > 0:
        return if tail.len > 0: r & tail else: r
    except CatchableError:
      discard
    let (head, last) = splitPath(dir)
    if last.len == 0: break
    tail = DirSep & last & tail
    dir = head.normalizedPath
  p

proc contractPath*(path, projectDir: string): string =
  ## The portable policy-file form of an absolute cleaned path: under
  ## `projectDir` as `./name` (empty target, i.e. the bare verb, for
  ## the project dir itself), under home as `~/...`, else absolute.
  ## Display and append only; internal rule storage stays absolute.
  let proj = projectDir.normalizedPath
  let pathC = canonicalForDisplay(path)
  let projC = canonicalForDisplay(proj)
  if pathC == projC: return ""
  if pathC.len > projC.len and pathC.startsWith(projC & DirSep):
    return "." & DirSep & pathC[projC.len + 1 .. ^1]
  let home = getHomeDir().normalizedPath
  if home.len > 1 or (home.len == 1 and home != $DirSep):
    if path == home: return "~"
    if path.len > home.len and
        path.startsWith(home & DirSep): return "~" & path[home.len .. ^1]
  path

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

proc parsePolicy*(text: string; projectDir: string): seq[Rule] =
  ## Parse policy DSL text into ordered rules. Blank lines and `#`
  ## comments are skipped. Unrecognised verbs, bad hosts, and bad ports
  ## are skipped silently so a half-edited file still loads its valid
  ## lines (the user owns this file and can see what they wrote).
  for raw in text.splitLines:
    let line = raw.strip(leading = true, trailing = false)
    if line.len == 0 or line[0] == '#': continue
    # The access word must stand alone (end of line or whitespace
    # after it); a line starting with anything else is treated as a
    # host rule and dropped below when the host is invalid.
    var access = akWritable
    var rest = ""
    let first = line.split(Whitespace, 1)[0]
    case first
    of "allow": access = akWritable
    of "deny": access = akDeny
    of "readonly": access = akReadOnly
    else: rest = line
    if rest.len == 0:
      rest = line[first.len .. ^1].strip(leading = true, trailing = false)
    if classifyTarget(rest) == rkPath:
      result.add Rule(access: access, kind: rkPath,
                      path: normalizePolicyPath(rest, projectDir))
    else:
      try:
        let (host, port) = parseHost(rest)
        result.add Rule(access: access, kind: rkHost,
                        host: host, port: port)
      except ValueError:
        continue

proc loadPolicy*(path: string; projectDir: string): seq[Rule] =
  ## Read and parse the policy file at `path`, resolving relative targets
  ## against `projectDir`. A missing file yields no rules.
  if not fileExists(path): return @[]
  parsePolicy(readFile(path), projectDir)

# ---------------------------------------------------------------- queries

proc checkPath*(rules: openArray[Rule]; path: string): AccessKind =
  ## Effective access for a concrete absolute `path`: the last path rule
  ## whose root covers it wins. Deny when nothing covers the path, which
  ## is the safe default. Host rules never affect paths.
  result = akDeny
  for r in rules:
    if r.kind == rkPath and isPathUnder(path, r.path):
      result = r.access

proc resolve*(rules: openArray[Rule]): Resolved =
  ## Walk the ordered rules into the consumed form. Last-wins per
  ## canonical path: a later rule for a path supersedes every earlier one
  ## for that same path. Deny is the default for anything unmentioned, so
  ## deny rules only matter as overrides of earlier allows; they drop the
  ## path from both lists. Host rules pass through with their access
  ## intact (last-wins per host:port key only collapses repeats of the
  ## exact same key); the wall matcher applies ordering across keys.
  var latest: Table[string, AccessKind]
  var order: seq[string]
  for r in rules:
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
      # Denies are carried too: last-wins happens per host:port KEY, so
      # `+host:80` then `-host:443` must keep BOTH rules (the matcher
      # sees them in policy order). The wall's HostList does the real
      # last-wins at match time.
      if latest[key] != akReadOnly:
        let c = key.rfind(':')
        result.hosts.add Rule(access: latest[key], kind: rkHost,
                              host: key[0 .. c - 1],
                              port: uint16(parseUInt(key[c + 1 .. ^1])))
    else:
      case latest[k]
      of akWritable: result.writable.add k
      of akReadOnly: result.readonly.add k
      of akDeny:
        # A deny needs compensating enforcement when it narrows an
        # allow that survives in the output lists, or a baseline root
        # the backends auto-grant (Landlock unions rules, so an
        # explicit deny under a baseline root must be carried through).
        for w in result.writable:
          if isPathUnder(k, w): result.denied.add k; break
        if k notin result.denied:
          for ro in result.readonly:
            if isPathUnder(k, ro): result.denied.add k; break
        if k notin result.denied:
          for b in baselineRead:
            if isPathUnder(k, b): result.denied.add k; break

proc renderPolicy*(rules: openArray[Rule];
                   projectDir = ""): string =
  ## Human-readable dump of the effective rules, newest last (matching
  ## file order). Hidden rules (implicit guards) are enforced but not
  ## shown. With a non-empty `projectDir`, path targets contract to the
  ## portable form (`./foo` under the project dir, bare for the project
  ## dir itself, `~/...` under home); with empty, paths print absolute.
  var shown = 0
  for r in rules:
    if not r.hidden: inc shown
  if shown == 0:
    return "(no sandbox rules)"
  for r in rules:
    if r.hidden: continue
    let label =
      case r.access
      of akDeny: "deny    "
      of akReadOnly: "readonly"
      of akWritable: "allow   "
    case r.kind
    of rkPath:
      let p = if projectDir.len > 0: contractPath(r.path, projectDir)
              else: r.path
      result.add label & "  " & p & "\n"
    of rkHost:
      let suffix = if r.port == 0: "" else: ":" & $r.port
      result.add label & "  " & r.host & suffix & "\n"

proc replaceAccess*(text, target, verb: string;
                    projectDir = ""): string =
  ## Strip existing rules for `target` that carry a real access verb and
  ## append `verb target` at the end. A rule only matches when the verb
  ## stands alone at a word boundary, so a hostname like
  ## `deny.corp.internal` is never mistaken for a deny rule. Host rules
  ## compare on the (host, port) pair, and a malformed host line is
  ## never stripped. Path rules compare on their resolved absolute
  ## form when `projectDir` is given, so `./foo` and `/proj/dir/foo`
  ## match the same rule; without `projectDir` they compare literal,
  ## an exact string match or a bare verb (the project dir) when
  ## `target` is empty. Lines that fail to parse keep their place,
  ## untouched.
  let cmpPaths = projectDir.len > 0
  let targetKey =
    if classifyTarget(target) == rkPath:
      if cmpPaths: ("\x01", normalizePolicyPath(target, projectDir))
      else: ("\x01", target)
    else:
      try:
        let (h, p) = parseHost(target)
        ("\x00", h & ":" & $p)
      except ValueError:
        ("\x00", "\x01" & target)  # unparseable: can never match a rule
  var lines = text.splitLines
  # splitLines yields a phantom empty tail for newline-terminated text;
  # drop it or it would round-trip into a growing stack of blank lines.
  if lines.len > 0 and lines[^1].len == 0: lines.setLen(lines.len - 1)
  for raw in lines:
    let line = raw.strip(leading = true, trailing = false)
    if line.len == 0 or line[0] == '#':
      result.add raw & "\n"
      continue
    let first = line.split(Whitespace, 1)[0]
    var rest = ""
    if first in ["allow", "deny", "readonly"]:
      rest = line[first.len .. ^1].strip(leading = true, trailing = false)
      let ruleKey =
        if classifyTarget(rest) == rkPath:
          if cmpPaths: ("\x01", normalizePolicyPath(rest, projectDir))
          else: ("\x01", rest)
        else:
          try:
            let (h, p) = parseHost(rest)
            ("\x00", h & ":" & $p)
          except ValueError:
            ("\x00", "\x01" & rest)
      if ruleKey == targetKey:
        continue  # superseded: the new rule at the end replaces it
    result.add raw & "\n"
  result.add verb & (if target.len > 0: " " & target else: "") & "\n"

proc appendRule*(policyFile, target: string; access: AccessKind;
                 projectDir = ""): bool =
  ## Add a rule to `policyFile`. With a non-empty `projectDir` (the
  ## normal case), a path `target` is normalized to the portable file
  ## form first: `/proj/dir/foo` writes as `./foo`, the project dir
  ## itself as the bare verb, home paths as `~/...`. Earlier rules for
  ## the same target are stripped, so flipping allow -> deny (or back)
  ## moves the rule to the end instead of stacking duplicates; other
  ## targets keep their order. Host targets pass through unchanged.
  ## Returns false on write failure.
  let word =
    case access
    of akDeny: "deny"
    of akReadOnly: "readonly"
    of akWritable: "allow"
  var t = target
  if projectDir.len > 0 and classifyTarget(t) == rkPath and t.len > 0:
    t = contractPath(normalizePolicyPath(t, projectDir), projectDir)
  try:
    let text = if fileExists(policyFile): readFile(policyFile) else: ""
    writeFile(policyFile, replaceAccess(text, t, word, projectDir))
  except CatchableError:
    return false
  true
