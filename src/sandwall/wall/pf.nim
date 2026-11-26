## pf: the macOS kernel egress fence, keyed on a marker gid.
##
## Seatbelt network filters take `*` or `localhost` as a host, never a
## literal address, so on macOS the per-address decision cannot live in
## Seatbelt. pf, the in-kernel L3/L4 filter, can decide by address, and it
## matches a packet to its socket's credential. A socket's credential is
## taken at socket creation, and pf reads the primary gid from it, so
## the marker is a primary gid nobody else on the box carries.
##
## Only root can setgid to an arbitrary gid, which makes the fence two
## processes:
##
##   `sandwall setup`   one-time, elevated: a LaunchDaemon and a record
##                      of the installing account's uid
##   sandwallpf         the daemon (pfdaemon.nim): owns pf, one child
##                      anchor and one gid per run, and the only thing
##                      that drops a process into a marker
##
## The daemon's operations, one JSON line each way over a unix socket:
##
##   ping                    -> ok
##   begin    snapshot       -> runId    (anchor up, tables filled)
##   refresh  runId snapshot -> ok       (tables replaced)
##   end      runId          -> ok      (anchor gone)
##   exec     runId cmd cwd  -> pid, then the child's exit code
##
## This module is the decision half: the rule text, the gid bookkeeping
## and the sweep. It has no socket and no pfctl of its own, so it
## compiles and is tested on every platform; pfdaemon.nim drives it.

import std/[json, locks, net, os, sequtils, sets, strutils, tables]
import std/sysrand
import std/posix except Time
import ./hosts
import ./permit

const
  PfLabel* = "com.capocasa.sandwall"
    ## LaunchDaemon label and reverse-domain prefix of the anchors
  PfRunsAnchor* = "com.sandwall.runs"
  PfOrphansAnchor* = "com.sandwall.orphans"
  PfSockPath* = "/var/run/com.sandwall.sandwallpf.sock"
  PfStateDir* = "/var/db/sandwall"
  PfUidFile* = PfStateDir / "uid"
  PfPlistPath* = "/Library/LaunchDaemons/" & PfLabel & ".plist"
  PfctlPath* = "/sbin/pfctl"
  FirstMarkerGid* = 42400
  LastMarkerGid* = 42499
  RunLeaseSeconds* = 900.0
    ## a run whose lease passed with no live child is swept; exec keeps
    ## a run alive for as long as its child runs
  PfUnavailableExit* = 125
    ## the run's exit code when the pf fence could not go up: the child
    ## never ran
  PfMarker* = "sandwall-pf-unavailable"

type
  PfCtl* = proc(args: openArray[string]; input = ""): tuple[ok: bool;
    output: string] {.gcsafe, raises: [].}
    ## Runs pfctl. `ok` is its exit status, `output` stdout and stderr.

  Run* = object
    gid*: int
    expires*: float
    pid*: int                ## the exec'd child while it runs, else 0

  Daemon* = ref DaemonObj

  DaemonObj* = object
    lock: Lock
    runs: Table[string, Run]
    pf*: PfCtl
    clock*: proc(): float {.gcsafe, raises: [].}
    groupExists*: proc(gid: int): bool {.gcsafe, raises: [].}
    log*: proc(msg: string) {.gcsafe, raises: [].}

  PfError* = object of CatchableError

# ------------------------------------------------------------ rule text

proc runAnchor*(runId: string): string = PfRunsAnchor & "/" & runId

proc validRunId*(runId: string): bool =
  if runId.len == 0 or runId.len > 64: return false
  for c in runId:
    if c notin {'a'..'z', 'A'..'Z', '0'..'9'}: return false
  true

proc anchorCallLines*: string =
  ## The two lines the main ruleset needs so the anchors are reached.
  ## The exact anchor name is load-bearing: `anchor "com.sandwall.runs/*"`
  ## skips the anchor's own rules.
  "anchor \"" & PfRunsAnchor & "\" all\n" &
  "anchor \"" & PfOrphansAnchor & "\" all\n"

proc hasAnchorCalls*(rules: string): bool =
  rules.contains("anchor \"" & PfRunsAnchor & "\"") and
    rules.contains("anchor \"" & PfOrphansAnchor & "\"")

proc patchedRuleset*(current: string): string =
  ## The main ruleset with the two anchor calls appended, or "" when it
  ## already has them. Nothing else in the ruleset is touched.
  if current.hasAnchorCalls: return ""
  result = current
  if result.len > 0 and not result.endsWith("\n"): result.add '\n'
  result.add anchorCallLines()

proc shadowingRule*(current: string): string =
  ## The first rule above our anchors that would pass every packet
  ## before the fence is consulted, "" when there is none. A user rule
  ## such as `pass out quick all` wins over any later quick rule.
  for line in current.splitLines:
    if line.contains("anchor \"" & PfRunsAnchor & "\""): break
    let l = line.strip()
    if l.startsWith("#") or not l.startsWith("pass"): continue
    if not l.contains(" quick"): continue
    if " all" in l and " group" notin l and " user" notin l and
       " on " notin l and " anchor" notin l:
      return l
  ""

proc splitFamilies*(ips: seq[IpAddress]): tuple[v4, v6: seq[string]] =
  ## Addresses as pf table members, by family. pf tables are one
  ## family each.
  var seen = initHashSet[string]()
  for a in ips:
    let s = $a
    if s in seen: continue
    seen.incl s
    if a.family == IpAddressFamily.IPv6: result.v6.add s
    else: result.v4.add s

proc snapshotAddresses*(entries: openArray[PermitEntry]): tuple[v4, v6: seq[string]] =
  ## Every live address of a snapshot: the current and the previous
  ## generation, both while its grace runs.
  var ips: seq[IpAddress]
  for e in entries:
    ips.add e.current
    ips.add e.previous
  splitFamilies(ips)

proc tableBody(ips: openArray[string]): string =
  if ips.len == 0: "{}" else: "{ " & ips.join(", ") & " }"

proc anchorRules*(gid: int; v4, v6: openArray[string];
                  loopPorts: openArray[uint16] = [0'u16]): string =
  ## The rules of one run's child anchor. Loopback is all ports when
  ## `loopPorts` holds a 0 and those ports when it holds others; the
  ## caller emits no lo0 rules at all when the policy has no loopback
  ## rule (Seatbelt then denies the child's loopback connects).
  ## tcp is refused with a reset so a denied connect fails fast.
  let g = "group = " & $gid
  result = "table <v4> " & tableBody(v4) & "\n" &
           "table <v6> " & tableBody(v6) & "\n"
  if loopPorts.len > 0:
    # pf takes a `port` only with a `proto`, and an `inet` family is one
    # family, so the port list costs four rules.
    if 0'u16 in loopPorts:
      result.add "pass out quick on lo0 " & g & "\n"
    else:
      let ports = "port { " & loopPorts.mapIt($it).join(", ") & " } " & g & "\n"
      for fam in ["inet ", "inet6 "]:
        for proto in ["tcp", "udp"]:
          result.add "pass out quick on lo0 " & fam & "proto " & proto &
            " from any to any " & ports
    # The child's own listener must answer its peers, and a local
    # proxy is an exit around the address table: loopback is scoped to
    # the policy's ports and everything else on lo0 is refused.
    result.add "pass in quick on lo0 " & g & "\n"
    result.add "block return out quick on lo0 " & g & "\n"
  result.add "block return-rst out quick inet proto tcp to ! <v4> " & g & "\n"
  result.add "block return-rst out quick inet6 proto tcp to ! <v6> " & g & "\n"
  result.add "block return out quick inet proto udp to ! <v4> " & g & "\n"
  result.add "block return out quick inet6 proto udp to ! <v6> " & g & "\n"
  # Permitted traffic is decided inside this anchor.
  result.add "pass out quick " & g & "\n"

proc runRules*(gid: int; loopPorts: openArray[uint16];
                entries: openArray[PermitEntry]): string =
  ## `anchorRules` with the tables taken from a snapshot.

  let (v4, v6) = snapshotAddresses(entries)
  anchorRules(gid, v4, v6, loopPorts)

proc orphanRules*(): string =
  ## The catch-all for a marked process whose run state is gone (daemon
  ## restarted): blocked, never unfenced.
  for gid in FirstMarkerGid .. LastMarkerGid:
    result.add "block drop out quick group = " & $gid & "\n"

# ---------------------------------------------------------- bookkeeping

proc loopbackPolicy*(l: HostList): tuple[enabled: bool; ports: seq[uint16]] =
  ## Whether the policy gives the child a loopback, and on which ports.
  ## Seatbelt decides the first, pf the second. A rule without a port
  ## opens every listener on the host.
  for name in ["localhost", "127.0.0.1", "::1"]:
    if not l.allowsAnyPort(name): continue
    result.enabled = true
    let p = winningPorts(l, name)
    if 0'u16 in p: return (true, @[0'u16])
    for x in p:
      if x notin result.ports: result.ports.add x

proc allowsEverything*(l: HostList): bool =
  ## Whether a port-less `+*` rule decides every connection. Such a
  ## policy has nothing to stamp.
  for m in l.matchers:
    if m.isAll and m.port == 0: result = m.allow

proc snapshotJson*(entries: openArray[PermitEntry]): JsonNode =
  ## The snapshot in the wire shape of `permit.writeSnapshot`'s entries.
  result = newJArray()
  for x in entries:
    result.add %*{
      "host": x.host,
      "ports": x.ports.mapIt(it.int),
      "current": x.current.mapIt($it),
      "previous": x.previous.mapIt($it),
      "expires": (if x.expires == Inf: newJNull() else: newJFloat(x.expires)),
      "prevUntil": (if x.prevUntil == Inf: newJNull() else: newJFloat(x.prevUntil)),
    }

proc entriesFromJson*(n: JsonNode): seq[PermitEntry] =
  for x in n:
    var e: PermitEntry
    e.host = x["host"].getStr
    for p in x["ports"]: e.ports.add p.getInt.uint16
    for a in x["current"]: e.current.add parseIpAddress(a.getStr)
    for a in x["previous"]: e.previous.add parseIpAddress(a.getStr)
    if x["expires"].kind != JNull: e.expires = x["expires"].getFloat
    if x["prevUntil"].kind != JNull: e.prevUntil = x["prevUntil"].getFloat
    result.add e

# ----------------------------------------------------------- daemon core

proc runPf*(d: Daemon; args: openArray[string]; input = "") =
  let r = d.pf(args, input)
  if not r.ok:
    raise newException(PfError, "pfctl " & args.join(" ") & ": " & r.output.strip)

proc loadAnchor*(d: Daemon; anchor, rules: string) =
  runPf(d, ["-a", anchor, "-f", "-"], rules)

proc flushAnchor*(d: Daemon; anchor: string) =
  ## Remove an anchor's rules, states and tables. Its absence is fine.
  discard d.pf(["-a", anchor, "-F", "all"])

proc ensurePf*(d: Daemon) =
  ## Enable pf and make the main ruleset reach the fence. Called at
  ## daemon start: none of it survives a reboot. Apple does not enable
  ## pf at startup and a load is runtime-only. The main ruleset is never
  ## flushed (system services insert anchors into it dynamically) and
  ## /etc/pf.conf is never written.
  runPf(d, ["-E"])
  let cur = d.pf(["-s", "rules"])
  if not cur.ok:
    raise newException(PfError, "pfctl -s rules: " & cur.output.strip)
  let patched = patchedRuleset(cur.output)
  if patched.len > 0:
    runPf(d, ["-f", "-"], patched)
  let shadow = shadowingRule(cur.output)
  if shadow.len > 0:
    d.log("sandwallpf: warning: this pf rule passes traffic before the " &
      "fence and overrides it: " & shadow)
  # Stale child anchors are gone on restart; the marked processes that
  # used them fall to the orphan block.
  flushAnchor(d, PfRunsAnchor & "/*")
  loadAnchor(d, PfOrphansAnchor, orphanRules())

proc freeGid*(d: Daemon): int =
  ## A marker gid not in use and not a group of the system, -1 when the
  ## range is full. Checked at every begin: a group can be created
  ## later, and sharing a gid would widen the fence to that group.
  var used = initHashSet[int]()
  for r in d.runs.values: used.incl r.gid
  for gid in FirstMarkerGid .. LastMarkerGid:
    if gid in used: continue
    if not d.groupExists(gid): return gid
  -1

proc endRun*(d: Daemon; runId: string) =
  var gid = -1
  withLock d.lock:
    if runId in d.runs:
      gid = d.runs[runId].gid
      d.runs.del runId
  if gid < 0: return
  flushAnchor(d, runAnchor(runId))

proc sweep*(d: Daemon) =
  ## Retire runs whose lease passed and that have no live child: a
  ## crashed parent cannot leave a run fenced forever, and a live child
  ## keeps its run alive without a refresh.
  let now = d.clock()
  var stale: seq[string]
  withLock d.lock:
    for id, r in d.runs:
      if r.pid == 0 and now >= r.expires: stale.add id
  for id in stale: endRun(d, id)

proc newRunId*(): string =
  let buf = urandom(16)
  for c in buf: result.add toHex(c, 2).toLowerAscii

proc handle*(d: Daemon; req: JsonNode): JsonNode =
  ## The socket-free half of the daemon: everything but `exec`, which
  ## needs the caller's file descriptors.
  try:
    case req["op"].getStr
    of "ping":
      %*{"ok": true, "version": 1}
    of "begin":
      sweep(d)
      let gid = freeGid(d)
      if gid < 0:
        raise newException(PfError,
          "marker range " & $FirstMarkerGid & "-" & $LastMarkerGid &
          " is full")
      let loopPorts = req["loopPorts"].mapIt(it.getInt.uint16)
      let rules = runRules(gid, loopPorts, entriesFromJson(req["snapshot"]))
      let id = newRunId()
      # Loaded before it is published: a caller only ever sees an id
      # whose fence is already up.
      loadAnchor(d, runAnchor(id), rules)
      withLock d.lock:
        d.runs[id] = Run(gid: gid, expires: d.clock() + RunLeaseSeconds)
      %*{"ok": true, "runId": id, "gid": gid}
    of "refresh":
      sweep(d)
      let id = req["runId"].getStr
      var gid = -1
      withLock d.lock:
        if id in d.runs:
          gid = d.runs[id].gid
          d.runs[id].expires = d.clock() + RunLeaseSeconds
      if gid < 0:
        raise newException(PfError, "unknown run: " & id)
      let rules = runRules(gid, req["loopPorts"].mapIt(it.getInt.uint16),
                              entriesFromJson(req["snapshot"]))
      loadAnchor(d, runAnchor(id), rules)
      %*{"ok": true}
    of "end":
      endRun(d, req["runId"].getStr)
      %*{"ok": true}
    else:
      raise newException(PfError, "unknown op")
  except PfError as e:
    %*{"ok": false, "error": e.msg}
  except CatchableError as e:
    %*{"ok": false, "error": e.msg}

proc execGid*(d: ptr DaemonObj; runId: string): int =
  ## The marker an exec must apply. "" is the open case: no marker.
  ## A run the daemon does not know is refused, never run unfenced.
  if runId.len == 0: return 0
  result = -1
  withLock d.lock:
    if runId in d.runs:
      result = d.runs[runId].gid
      d.runs[runId].expires = d.clock() + RunLeaseSeconds

proc markExec*(d: ptr DaemonObj; runId: string; pid: int) =
  withLock d.lock:
    if runId in d.runs: d.runs[runId].pid = pid

proc newDaemon*(pf: PfCtl; clock: proc(): float {.gcsafe, raises: []};
                groupExists: proc(gid: int): bool {.gcsafe, raises: []};
                log: proc(msg: string) {.gcsafe, raises: []}): Daemon =
  result = Daemon(pf: pf, clock: clock, groupExists: groupExists, log: log)
  initLock result.lock

proc liveRuns*(d: Daemon): int =
  withLock d.lock: result = d.runs.len
