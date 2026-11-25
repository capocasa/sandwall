## Unit tests for the permit set: lazy resolution with a fixed refresh,
## serve-stale, single flight, retraction, previous-generation grace,
## proactive seeding, the entry cap and the JSON snapshot. Lookups go
## through a scripted resolver and the set's clock is virtual, so nothing
## waits on DNS or on the wall clock except the pool's deadline.

import std/[json, locks, net, os, options, tables, times, unittest]
import sandwall/rules
import sandwall/wall/hosts
import sandwall/wall/permit

const proj = when defined(windows): r"C:\work" else: "/work"

proc listOf(text: string): HostList =
  parsePolicy(text, proj).resolve().hosts.toHostList()

proc ip(s: string): IpAddress = parseIpAddress(s)

type
  Answer = object
    outcome: ResolveOutcome   ## roAddrs takes `addresses`
    addresses: seq[string]
    delayMs: int              ## how long the lookup takes

  Script = ref object
    lock: Lock
    answers: Table[string, seq[Answer]]  ## consumed in order; the last one repeats
    calls: Table[string, int]

  Notes = ref object
    lock: Lock
    lines: seq[string]

  Rig = ref object
    ps: PermitSet
    script: Script
    notes: Notes
    t: float                 ## the set's idea of now

proc newScript(): Script =
  result = Script()
  initLock(result.lock)

proc plan(s: Script; name: string; answers: openArray[Answer]) =
  s.answers[name] = @answers

proc take(s: Script; name: string): ResolveResult =
  ## The scripted resolver: answer a name from its queue. Everything of
  ## the script is read and copied under its lock; a scripted answer
  ## is shared by every thread that asks, and a shared reference is not
  ## something this runtime survives.
  var outcome = roNxdomain
  var delayMs = 0
  withLock s.lock:
    var queue = s.answers.getOrDefault(name)
    if queue.len > 0:
      outcome = queue[0].outcome
      delayMs = queue[0].delayMs
      for x in queue[0].addresses:
        try: result.ips.add ip(x)
        except ValueError: discard   # a typo in the fixture is no answer
      if queue.len > 1:
        queue.delete(0)
        s.answers[name] = queue
    s.calls[name] = s.calls.getOrDefault(name) + 1
  if delayMs > 0: sleep(delayMs)
  if outcome == roAddrs and result.ips.len == 0: outcome = roTransient
  result.outcome = outcome

proc resolverOf(s: Script): Resolver =
  proc look(name: string): ResolveResult {.gcsafe, raises: [].} = s.take(name)
  look

proc callCount(s: Script; name: string): int =
  withLock s.lock:
    result = s.calls.getOrDefault(name)

proc add(n: Notes; msg: string) =
  withLock n.lock:
    n.lines.add msg

proc newRig(): Rig =
  ## A permit set on a scripted resolver, a virtual clock (start: epoch
  ## 1000) and a captured log.
  result = Rig(t: 1000.0, script: newScript(), notes: Notes())
  initLock(result.notes.lock)
  let r = result
  r.ps = newPermitSet(resolver = r.script.resolverOf())
  r.ps.clock = proc (): float = r.t
  r.ps.log = proc (msg: string) = r.notes.add(msg)

type
  Fetch = ref object
    ps: PermitSet
    name: string
    got: seq[IpAddress]   ## empty when the lookup returned none

proc fetch(f: Fetch) {.thread.} =
  let e = f.ps.getOrResolve(f.name, [0'u16])
  if e.isSome: f.got = e.get.current

type
  Churn = ref object
    ps: PermitSet
    list: HostList
    seeding: bool

proc churn(c: Churn) {.thread.} =
  for i in 0 ..< 40:
    if c.seeding:
      discard c.ps.seedFromPolicy(c.list, 5)
      discard c.ps.refreshForSpawn(5)
    else:
      discard c.ps.getOrResolve("c" & $(i mod 20) & ".test", [443'u16])
      discard c.ps.matchIp(ip("198.51.100." & $(i mod 20 + 1)), 443)

suite "lazy resolution":
  test "first lookup resolves; a fresh entry is served without asking again":
    var rig = newRig()
    let ps = rig.ps
    rig.script.plan("api.example", [Answer(outcome: roAddrs,
      addresses: @["192.0.2.1", "2001:db8::1"])])
    let e = ps.getOrResolve("API.Example.", [443'u16, 22'u16])
    check e.isSome
    check e.get.host == "api.example"
    check e.get.current == @[ip("192.0.2.1"), ip("2001:db8::1")]
    check e.get.ports == @[443'u16, 22'u16]
    check e.get.expires == 1300.0
    check e.get.lastGood == 1000.0
    check e.get.previous.len == 0
    check not e.get.stale
    # the port of this request is not the entry's whole port set
    let again = ps.getOrResolve("api.example", [443'u16])
    check again.get.ports == @[443'u16, 22'u16]
    check rig.script.callCount("api.example") == 1

  test "an expired entry is looked up again; the replaced set stays for the grace period":
    var rig = newRig()
    let ps = rig.ps
    rig.script.plan("rot.example", [
      Answer(outcome: roAddrs, addresses: @["192.0.2.1"]),
      Answer(outcome: roAddrs, addresses: @["192.0.2.2"])])
    discard ps.getOrResolve("rot.example", [0'u16])
    rig.t = 1299.0
    discard ps.getOrResolve("rot.example", [0'u16])
    check rig.script.callCount("rot.example") == 1   # one second short
    rig.t = 1300.0
    let e = ps.getOrResolve("rot.example", [0'u16])
    check rig.script.callCount("rot.example") == 2
    check e.get.current == @[ip("192.0.2.2")]
    check e.get.previous == @[ip("192.0.2.1")]
    check e.get.prevUntil == 1600.0
    check e.get.expires == 1600.0
    check e.get.lastGood == 1300.0

  test "an unchanged answer leaves the older generation alone":
    var rig = newRig()
    let ps = rig.ps
    rig.script.plan("same.example", [
      Answer(outcome: roAddrs, addresses: @["192.0.2.1"]),
      Answer(outcome: roAddrs, addresses: @["192.0.2.2"])])
    discard ps.getOrResolve("same.example", [0'u16])
    rig.t = 1300.0
    discard ps.getOrResolve("same.example", [0'u16])
    rig.t = 1600.0
    let e = ps.getOrResolve("same.example", [0'u16])
    check e.get.current == @[ip("192.0.2.2")]
    check e.get.previous == @[ip("192.0.2.1")]
    check e.get.prevUntil == 1600.0   # not extended: nothing was replaced

  test "the refresh interval is clamped to a minimum":
    check newPermitSet(refreshS = 5.0).refresh == MinRefreshS
    check newPermitSet().refresh == DefaultRefreshS
    check newPermitSet().grace == GraceS

  test "a transient failure serves the last good addresses and warns once per outage":
    var rig = newRig()
    let ps = rig.ps
    rig.script.plan("flaky.example", [
      Answer(outcome: roAddrs, addresses: @["192.0.2.1"]),
      Answer(outcome: roTransient),
      Answer(outcome: roAddrs, addresses: @["192.0.2.3"]),
      Answer(outcome: roTransient)])
    discard ps.getOrResolve("flaky.example", [0'u16])
    rig.t = 1300.0
    let e = ps.getOrResolve("flaky.example", [0'u16])
    check e.isSome
    check e.get.current == @[ip("192.0.2.1")]   # kept
    check e.get.stale
    check e.get.lastGood == 1000.0
    check rig.notes.lines == @["resolver has no answer for flaky.example; serving stale addresses (1)"]
    let back = ps.getOrResolve("flaky.example", [0'u16])
    check back.get.current == @[ip("192.0.2.3")]   # recovered
    check not back.get.stale
    check back.get.previous == @[ip("192.0.2.1")]
    check back.get.expires == 1600.0
    rig.t = 1600.0
    let again = ps.getOrResolve("flaky.example", [0'u16])
    check again.get.stale
    check rig.notes.lines.len == 2   # a new outage warns again

  test "a transient failure with no good answer fails hard":
    var rig = newRig()
    rig.script.plan("never.example", [Answer(outcome: roTransient)])
    check rig.ps.getOrResolve("never.example", [0'u16]).isNone
    check rig.notes.lines.len == 0

  test "NXDOMAIN retracts the entry; the next connect looks the name up again":
    var rig = newRig()
    let ps = rig.ps
    rig.script.plan("gone.example", [
      Answer(outcome: roAddrs, addresses: @["192.0.2.1"]),
      Answer(outcome: roNxdomain),
      Answer(outcome: roAddrs, addresses: @["192.0.2.9"])])
    discard ps.getOrResolve("gone.example", [0'u16])
    rig.t = 1300.0
    check ps.getOrResolve("gone.example", [0'u16]).isNone
    check ps.matchIp(ip("192.0.2.1"), 443).isNone
    check ps.matchIp(ip("192.0.2.1")).isNone
    check rig.notes.lines == @["gone.example no longer resolves; dropped its addresses"]
    let back = ps.getOrResolve("gone.example", [0'u16])
    check back.get.current == @[ip("192.0.2.9")]
    check back.get.previous.len == 0

  test "IP literals are their own answer and never expire":
    var rig = newRig()
    let ps = rig.ps
    let e = ps.getOrResolve("[2001:DB8::1]", [8443'u16])
    check e.get.host == "2001:db8::1"
    check e.get.current == @[ip("2001:db8::1")]
    check e.get.ports == @[8443'u16]
    check e.get.expires == Inf
    discard ps.getOrResolve("192.0.2.7", [0'u16])
    rig.t += 100_000.0
    discard ps.getOrResolve("2001:db8::1", [8443'u16])
    check rig.script.calls.len == 0     # nothing was ever looked up
    check ps.matchIp(ip("192.0.2.7"), 22).isSome
    check ps.matchIp(ip("2001:db8::1"), 8443).isSome
    check ps.matchIp(ip("2001:db8::1"), 22).isNone

  test "single flight: one lookup serves every waiter":
    var rig = newRig()
    let ps = rig.ps
    rig.script.plan("busy.example", [Answer(outcome: roAddrs,
      addresses: @["192.0.2.1"], delayMs: 150)])
    var th: array[6, Thread[Fetch]]
    var jobs: array[6, Fetch]
    for i in 0 ..< 6:
      jobs[i] = Fetch(ps: ps, name: "busy.example")
      createThread(th[i], fetch, jobs[i])
    for i in 0 ..< 6: joinThread(th[i])
    for i in 0 ..< 6:
      check jobs[i].got == @[ip("192.0.2.1")]
    check rig.script.callCount("busy.example") == 1

  test "a waiter outlived by a slow lookup serves the stale addresses":
    var rig = newRig()
    let ps = rig.ps
    ps.resolveTimeoutMs = 60
    rig.script.plan("slow.example", [
      Answer(outcome: roAddrs, addresses: @["192.0.2.1"]),
      Answer(outcome: roAddrs, addresses: @["192.0.2.2"], delayMs: 400)])
    discard ps.getOrResolve("slow.example", [0'u16])
    rig.t = 1300.0
    var th: Thread[Fetch]
    let job = Fetch(ps: ps, name: "slow.example")
    createThread(th, fetch, job)
    let limit = epochTime() + 5.0
    while rig.script.callCount("slow.example") < 2 and epochTime() < limit:
      sleep(1)
    let began = epochTime()
    let e = ps.getOrResolve("slow.example", [0'u16])
    check epochTime() - began >= 0.05
    check e.isSome                      # a timeout never retracts
    check e.get.current == @[ip("192.0.2.1")]
    joinThread(th)
    check job.got == @[ip("192.0.2.2")]
    check ps.getOrResolve("slow.example", [0'u16]).get.current == @[ip("192.0.2.2")]
    check ps.matchIp(ip("192.0.2.1"), 80).isSome   # previous, within grace

suite "matching":
  test "matchIp: current, previous within grace, previous after grace, port":
    var rig = newRig()
    let ps = rig.ps
    rig.script.plan("rot.example", [
      Answer(outcome: roAddrs, addresses: @["192.0.2.1"]),
      Answer(outcome: roAddrs, addresses: @["192.0.2.2"])])
    discard ps.getOrResolve("rot.example", [443'u16])
    check ps.matchIp(ip("192.0.2.1"), 443).get.host == "rot.example"
    check ps.matchIp(ip("192.0.2.1"), 80).isNone
    check ps.matchIp(ip("192.0.2.2"), 443).isNone
    check ps.matchIp(ip("192.0.2.1")).get.ports == @[443'u16]
    rig.t = 1300.0
    discard ps.getOrResolve("rot.example", [443'u16])
    check ps.matchIp(ip("192.0.2.1"), 443).isSome   # previous
    check ps.matchIp(ip("192.0.2.1"), 80).isNone
    check ps.matchIp(ip("192.0.2.2"), 443).isSome
    rig.t = 1600.0
    check ps.matchIp(ip("192.0.2.1"), 443).isNone   # grace over
    check ps.matchIp(ip("192.0.2.2"), 443).isSome   # kept until a refresh replaces it

  test "portAllowed":
    check portAllowed([0'u16], 22)
    check portAllowed([443'u16, 22'u16], 22)
    check not portAllowed([443'u16], 80)
    check not portAllowed([], 80)

suite "winning ports":
  test "a bare allow is every port":
    check listOf("allow a.test\n").winningPorts("a.test") == @[0'u16]
    check listOf("allow A.TEST\n").winningPorts("a.test.") == @[0'u16]
  test "a later rule for the same port, or a later bare rule, supersedes":
    let l = listOf("allow a.test:22\nallow a.test:443\ndeny a.test:22\n")
    check l.winningPorts("a.test") == @[443'u16]
    check listOf("allow a.test:443\ndeny a.test\n").winningPorts("a.test").len == 0
    check listOf("allow a.test\ndeny a.test\n").winningPorts("a.test").len == 0
    check listOf("deny a.test:22\nallow a.test\n").winningPorts("a.test") == @[0'u16]
  test "a carve-out cannot be expressed as ports and stays an open port set":
    check listOf("allow a.test\ndeny a.test:22\n").winningPorts("a.test") == @[0'u16]
  test "wildcards and the star":
    check listOf("allow *.wild.test\n").winningPorts("x.wild.test") == @[0'u16]
    check listOf("allow *.wild.test\n").winningPorts("wild.test") == @[0'u16]
    check listOf("allow *.wild.test\n").winningPorts("x.test").len == 0
    check listOf("allow *\ndeny a.test\n").winningPorts("b.test") == @[0'u16]
    check listOf("allow *\ndeny a.test\n").winningPorts("a.test").len == 0
  test "a deny-only policy has no allow to enumerate":
    check listOf("deny evil.test\n").winningPorts("a.test").len == 0

suite "seeding":
  test "exact names, literals and hosts-file names; wildcards, failures and the deadline are reported":
    var rig = newRig()
    let ps = rig.ps
    let dir = getTempDir() / "sandwall_permit_" & $getCurrentProcessId()
    createDir(dir)
    defer: removeDir(dir)
    let hostsFile = dir / "hosts"
    writeFile(hostsFile, "# fixture\n" &
      "127.0.0.1 localhost\n" &
      "192.0.2.201 boxed.example alias.example # boxed\n" &
      "999.9.9.9 skipped.example\n")
    ps.hostsPath = hostsFile
    rig.script.plan("exact.example", [Answer(outcome: roAddrs,
      addresses: @["192.0.2.1"])])
    rig.script.plan("dead.example", [Answer(outcome: roNxdomain)])
    rig.script.plan("slow.example", [Answer(outcome: roAddrs,
      addresses: @["192.0.2.2"], delayMs: 400)])
    rig.script.plan("ports.example", [Answer(outcome: roAddrs,
      addresses: @["192.0.2.3"])])
    rig.script.plan("denied.example", [Answer(outcome: roAddrs,
      addresses: @["192.0.2.250"])])
    let report = ps.seedFromPolicy(listOf("""
allow exact.example
allow 192.0.2.200:443
allow [2001:db8::1]:8443
allow boxed.example
allow dead.example
allow slow.example
allow ports.example:22
allow ports.example:443
deny ports.example:22
allow denied.example
deny denied.example
allow *.wild.example
"""), 100)
    check report.resolved == 5   # two DNS names, two literals, one hosts-file name
    check report.failed == @["dead.example"]
    check report.pending == @["slow.example"]
    check report.wildcards == @["*.wild.example"]
    check rig.script.calls.len == 4   # exact, ports, dead, slow: nothing else
    check ps.getOrResolve("exact.example", [0'u16]).get.expires == 1300.0
    check ps.getOrResolve("ports.example", [443'u16]).get.ports == @[443'u16]
    check ps.matchIp(ip("192.0.2.200"), 443).get.host == "192.0.2.200"
    check ps.matchIp(ip("192.0.2.200"), 80).isNone
    check ps.matchIp(ip("2001:db8::1"), 8443).isSome
    let boxed = ps.matchIp(ip("192.0.2.201"), 22).get
    check boxed.host == "boxed.example"
    check boxed.expires == Inf
    check ps.matchIp(ip("192.0.2.250")).isNone   # the allow lost to a later deny
    sleep(600)
    check ps.matchIp(ip("192.0.2.2"), 80).isSome   # the late lookup landed
    ps.close()

  test "an open policy is reported as a wildcard and seeds nothing":
    var rig = newRig()
    let report = rig.ps.seedFromPolicy(
      listOf("allow *\ndeny evil.example\n"), 0)
    check report.wildcards == @["*"]
    check report.resolved == 0
    check rig.script.calls.len == 0

  test "re-seeding drops what the old policy allowed; a cleared set looks names up again":
    var rig = newRig()
    let ps = rig.ps
    rig.script.plan("a.example", [
      Answer(outcome: roAddrs, addresses: @["192.0.2.1"]),
      Answer(outcome: roAddrs, addresses: @["192.0.2.5"])])
    rig.script.plan("b.example", [Answer(outcome: roAddrs,
      addresses: @["192.0.2.2"])])
    discard ps.seedFromPolicy(listOf("allow a.example\n"), 1000)
    check ps.matchIp(ip("192.0.2.1"), 443).isSome
    let report = ps.seedFromPolicy(listOf("allow b.example\n"), 1000)
    check report.resolved == 1
    check ps.matchIp(ip("192.0.2.1"), 443).isNone
    check ps.matchIp(ip("192.0.2.2"), 443).get.host == "b.example"
    ps.clear()
    check ps.matchIp(ip("192.0.2.2"), 443).isNone
    check ps.getOrResolve("a.example", [0'u16]).get.current == @[ip("192.0.2.5")]

  test "refreshForSpawn looks up what is due and serves stale past the deadline":
    var rig = newRig()
    let ps = rig.ps
    rig.script.plan("fresh.example", [Answer(outcome: roAddrs,
      addresses: @["192.0.2.1"])])
    rig.script.plan("due.example", [
      Answer(outcome: roAddrs, addresses: @["192.0.2.10"]),
      Answer(outcome: roAddrs, addresses: @["192.0.2.11"], delayMs: 400)])
    rig.script.plan("dead2.example", [
      Answer(outcome: roAddrs, addresses: @["192.0.2.20"]),
      Answer(outcome: roNxdomain)])
    rig.script.plan("flap.example", [
      Answer(outcome: roAddrs, addresses: @["192.0.2.30"]),
      Answer(outcome: roTransient)])
    discard ps.seedFromPolicy(listOf(
      "allow fresh.example\nallow due.example\nallow dead2.example\n" &
      "allow flap.example\n"), 2000)
    rig.t = 1299.0
    var report = ps.refreshForSpawn(1000)
    check report.resolved == 0 and report.failed.len == 0 and report.pending.len == 0
    check rig.script.calls.len == 4
    rig.t = 1300.0
    report = ps.refreshForSpawn(100)
    check report.resolved == 1                 # fresh.example
    check report.pending == @["due.example"]   # still being looked up
    check report.failed == @["dead2.example"]  # retracted
    check rig.script.callCount("flap.example") == 2   # refreshed, got no answer
    check ps.matchIp(ip("192.0.2.10"), 443).isSome   # stale, served past the deadline
    check ps.matchIp(ip("192.0.2.30"), 443).isSome   # stale, kept
    check ps.matchIp(ip("192.0.2.20"), 443).isNone
    sleep(600)
    let due = ps.matchIp(ip("192.0.2.11"), 443)
    check due.isSome
    check due.get.previous == @[ip("192.0.2.10")]

  test "seeding, refreshing and lazy lookups from several threads at once":
    var rig = newRig()
    let ps = rig.ps
    var policy = ""
    for i in 0 ..< 20:
      policy.add "allow c" & $i & ".test\n"
      rig.script.plan("c" & $i & ".test", [Answer(outcome: roAddrs,
        addresses: @["198.51.100." & $(i + 1)])])
    let list = listOf(policy)
    var a = Churn(ps: ps, list: list, seeding: true)
    var b = Churn(ps: ps, list: list, seeding: false)
    var ta, tb: Thread[Churn]
    createThread(ta, churn, a)
    createThread(tb, churn, b)
    joinThread(ta)
    joinThread(tb)
    let e = ps.getOrResolve("c7.test", [443'u16])
    check e.isSome
    check e.get.current == @[ip("198.51.100.8")]
    ps.close()

suite "entry cap":
  test "at the cap the oldest expired entry makes room; with nothing due the newcomer is dropped and logged once":
    var rig = newRig()
    let ps = rig.ps
    ps.maxEntries = 3
    for i, name in @["a.example", "b.example", "c.example"].pairs:
      rig.script.plan(name, [Answer(outcome: roAddrs,
        addresses: @["192.0.2." & $(i + 1)])])
      rig.t = 1000.0 + 10.0 * i.float
      discard ps.getOrResolve(name, [0'u16])
    rig.t = 1030.0
    rig.script.plan("d.example", [Answer(outcome: roAddrs,
      addresses: @["192.0.2.4"])])
    check ps.getOrResolve("d.example", [0'u16]).isNone   # nothing to evict
    check rig.notes.lines == @["entry cap (3) reached; dropping d.example"]
    check ps.getOrResolve("9.9.9.9", [0'u16]).isNone    # literals too
    check rig.notes.lines.len == 1                        # logged once
    rig.t = 1310.0
    let e = ps.getOrResolve("d.example", [0'u16])
    check e.get.current == @[ip("192.0.2.4")]
    check ps.matchIp(ip("192.0.2.1")).isNone   # a.example, expired oldest
    check ps.matchIp(ip("192.0.2.2")).isSome   # b.example
    check ps.matchIp(ip("192.0.2.3")).isSome   # c.example, still fresh

suite "snapshot":
  test "round trip: addresses, ports, both generations, null for never":
    var rig = newRig()
    let ps = rig.ps
    rig.script.plan("rot.test", [
      Answer(outcome: roAddrs, addresses: @["192.0.2.1"]),
      Answer(outcome: roAddrs, addresses: @["192.0.2.2"])])
    rig.script.plan("old.test", [
      Answer(outcome: roAddrs, addresses: @["192.0.2.10"]),
      Answer(outcome: roAddrs, addresses: @["192.0.2.11"])])
    discard ps.getOrResolve("rot.test", [443'u16, 22'u16])
    discard ps.getOrResolve("old.test", [0'u16])
    discard ps.getOrResolve("192.0.2.200", [443'u16])
    rig.t = 1301.0
    discard ps.getOrResolve("old.test", [0'u16])   # previous until 1601
    rig.t = 1700.0
    discard ps.getOrResolve("rot.test", [443'u16, 22'u16])   # previous until 2000
    let path = getTempDir() / "sandwall_permit_snapshot_" &
      $getCurrentProcessId() & ".json"
    defer: removeFile(path)
    ps.writeSnapshot(path)
    let root = parseJson(readFile(path))
    check root["version"].getInt == 1
    check root["entries"].len == 3
    check root["entries"][0]["host"].getStr == "192.0.2.200"
    check root["entries"][0]["expires"].kind == JNull
    check root["entries"][1]["host"].getStr == "old.test"
    check root["entries"][1]["previous"].len == 0   # past grace: not stamped
    check root["entries"][2]["previous"].len == 1
    let back = readSnapshot(path)
    check back[0].expires == Inf
    check back[0].ports == @[443'u16]
    check back[0].current == @[ip("192.0.2.200")]
    check back[1].current == @[ip("192.0.2.11")]
    check back[1].previous.len == 0
    check back[1].expires == 1601.0
    check back[2].host == "rot.test"
    check back[2].ports == @[443'u16, 22'u16]
    check back[2].current == @[ip("192.0.2.2")]
    check back[2].previous == @[ip("192.0.2.1")]
    check back[2].expires == 2000.0
    check back[2].prevUntil == 2000.0
    # unknown fields are ignored; an unknown version is refused
    root["entries"][0]["note"] = %"written by the parent"
    root["generated"] = %1700
    writeFile(path, $root)
    check readSnapshot(path).len == 3
    root["version"] = %2
    writeFile(path, $root)
    expect ValueError:
      discard readSnapshot(path)

suite "system resolver":
  test "localhost answers; a reserved name is NXDOMAIN":
    let good = systemResolver("localhost")
    check good.outcome == roAddrs
    check ip("127.0.0.1") in good.ips
    check systemResolver("nonexistent-xyz.invalid").outcome == roNxdomain
