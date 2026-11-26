import std/[json, net, os, sequtils, sets, strutils, unittest]
import sandwall
import sandwall/wall/pf
import sandwall/wall/[hosts, permit, pfdaemon]

proc ip(s: string): IpAddress = parseIpAddress(s)

proc rules(text: string): HostList =
  ## `+host` / `-host` shorthand for `allow host` / `deny host`.
  var lines: seq[string]
  for w in text.split():
    lines.add (if w.startsWith("+"): "allow " & w[1 .. ^1] else: "deny " & w[1 .. ^1])
  toHostList(parsePolicy(lines.join("\n"), "/p").resolve().hosts)

proc entry(host: string; ports: seq[uint16]; ips: seq[string]): PermitEntry =
  result.host = host
  result.ports = ports
  for a in ips: result.current.add ip(a)

type
  Fake* = object
    calls*: seq[string]       ## args joined, plus the input when given
    inputs*: seq[string]
    main*: string             ## what `-s rules` answers: the last `-f -` input
    refuse*: string           ## args substring whose call fails
    now*: float

proc fakePf(f: ptr Fake): PfCtl =
  result = proc(args: openArray[string]; input = ""): tuple[ok: bool; output: string] {.gcsafe.} =
    let a = args.join(" ")
    f[].calls.add a
    f[].inputs.add input
    for x in f[].refuse.split(";"):
      if x.len > 0 and a.contains(x): return (false, "refused: " & x)
    if a == "-f -": f[].main = input
    if a == "-s rules": return (true, f[].main)
    if a == "-E": return (true, "pf enabled")
    (true, "")

proc fakeGroup(taken: HashSet[int]): proc(gid: int): bool {.gcsafe, raises: [].} =
  result = proc(gid: int): bool {.gcsafe, raises: [].} = gid in taken

proc fakeClock(f: ptr Fake): proc(): float {.gcsafe, raises: [].} =
  result = proc(): float {.gcsafe, raises: [].} = f[].now

proc quiet(msg: string) {.gcsafe, raises: [].} = discard

proc daemon(f: ptr Fake; taken: HashSet[int] = initHashSet[int]()): Daemon =
  newDaemon(fakePf(f), fakeClock(f), fakeGroup(taken), quiet)

let appleRules = "scrub-anchor \"com.apple/*\" all fragment reassemble\n" &
  "nat-anchor \"com.apple/*\" all\nrdr-anchor \"com.apple/*\" all\n" &
  "anchor \"com.apple/*\" all\n"

suite "pf rule text":
  test "a run anchor: tables, loopback, blocks, then the pass":
    let r = anchorRules(42400, @["1.2.3.4"], @["2001:db8::1"], @[5432'u16, 8080'u16])
    check r.contains("table <v4> { 1.2.3.4 }\n")
    check r.contains("table <v6> { 2001:db8::1 }\n")
    check r.contains("pass out quick on lo0 inet proto tcp from any to any port { 5432, 8080 } group = 42400\n")
    check r.contains("pass out quick on lo0 inet6 proto udp from any to any port { 5432, 8080 } group = 42400\n")
    check r.count("pass out quick on lo0") == 4
    check r.contains("block return-rst out quick inet proto tcp to ! <v4> group = 42400\n")
    check r.contains("block return-rst out quick inet6 proto tcp to ! <v6> group = 42400\n")
    check r.contains("block return out quick inet proto udp to ! <v4> group = 42400\n")
    check r.contains("block return out quick inet6 proto udp to ! <v6> group = 42400\n")
    let loPass = r.find("pass out quick on lo0")
    let loBlock = r.find("block return out quick on lo0")
    let netBlock = r.find("block return-rst out quick inet ")
    let lastPass = r.find("pass out quick group = 42400")
    check loPass < loBlock and loBlock < netBlock and netBlock < lastPass
    check r.contains("block return out quick on lo0 group = 42400\n")
    check r.endsWith("pass out quick group = 42400\n")

  test "no loopback rule means no lo0 rules; a 0 port means every port":
    let r = anchorRules(7, [], [], [])
    check not r.contains("on lo0")
    check r.contains("table <v4> {}\n") and r.contains("table <v6> {}\n")
    let all = anchorRules(7, [], [], @[0'u16])
    check all.contains("pass out quick on lo0 group = 7\n")
    check not all.contains(" port {")
    check all.count("pass out quick on lo0") == 1

  test "the snapshot's addresses fill the tables by family, once each":
    let e = entry("a.com", @[443'u16], @["1.1.1.1", "2606:4700::6810:84e5"])
    let r = runRules(1, @[80'u16], @[e, entry("b.com", @[], @["1.1.1.1"])])
    check r.contains("table <v4> { 1.1.1.1 }")
    check r.contains("table <v6> { 2606:4700::6810:84e5 }")

  test "main ruleset: anchor calls appended once, nothing flushed":
    let p = patchedRuleset(appleRules)
    check p.startsWith(appleRules)
    check p.endsWith(anchorCallLines())
    check p.count("anchor \"com.sandwall.runs\"") == 1
    check patchedRuleset("") == anchorCallLines()
    check patchedRuleset(p) == ""
    check hasAnchorCalls(p)

  test "main ruleset: a pass-all above the fence is reported":
    check shadowingRule("pass out quick all\n" & appleRules) == "pass out quick all"
    check shadowingRule(appleRules & anchorCallLines() & "pass out quick all\n") == ""
    check shadowingRule("pass out quick on en0 inet from any to any keep state\n" &
      appleRules) == ""

  test "orphans are blocked across the whole marker range":
    let o = orphanRules()
    check o.count("\n") == LastMarkerGid - FirstMarkerGid + 1
    check o.contains("block drop out quick group = " & $FirstMarkerGid & "\n")
    check o.contains("block drop out quick group = " & $LastMarkerGid & "\n")

  test "run ids are anchor-safe":
    check validRunId("abc123")
    check not validRunId("")
    check not validRunId("../x")
    check not validRunId("a b")
    check runAnchor("abc") == "com.sandwall.runs/abc"

suite "pf policy decisions":
  test "loopback is off unless a localhost rule allows it":
    check not loopbackPolicy(rules("+a.com")).enabled
    check not loopbackPolicy(rules("+a.com -localhost")).enabled
    let on = loopbackPolicy(rules("+localhost"))
    check on.enabled and on.ports == @[0'u16]

  test "loopback ports come from the localhost rules":
    let lb = loopbackPolicy(rules("+localhost:5432 +127.0.0.1:8080 +a.com"))
    check lb.enabled and lb.ports == @[5432'u16, 8080'u16]
    let wide = loopbackPolicy(rules("+localhost:5432 +::1"))
    check wide.ports == @[0'u16]
    check loopbackPolicy(rules("+*")).enabled

  test "a port-less +* is everything, and a later deny takes it back":
    check allowsEverything(rules("+*"))
    check allowsEverything(rules("+* +a.com"))
    check not allowsEverything(rules("+a.com +*.example.com"))
    check not allowsEverything(rules("+* -*"))
    check not allowsEverything(rules("+*:443"))

  test "the snapshot round-trips through its wire form":
    let e = entry("a.com", @[443'u16], @["1.1.1.1"])
    var e2 = entry("b.com", @[], @["1.1.1.1"])
    e2.previous.add ip("2606:4700::6810:84e5")
    e2.prevUntil = 5.0
    let back = entriesFromJson(snapshotJson(@[e, e2]))
    check back.len == 2
    check back[0].host == "a.com" and back[0].ports == @[443'u16]
    check $back[0].current[0] == "1.1.1.1"
    check back[1].expires == 0.0 and back[1].prevUntil == 5.0
    check $back[1].previous[0] == "2606:4700::6810:84e5"

suite "pf daemon bookkeeping":
  var f: Fake
  setup:
    f = Fake(now: 1000.0)

  test "begin loads the anchor before it publishes the run":
    let d = daemon(addr f)
    let rep = handle(d, %*{"op": "begin", "loopPorts": [5432],
      "snapshot": snapshotJson(@[entry("a.com", @[], @["1.2.3.4"])])})
    check rep["ok"].getBool
    let id = rep["runId"].getStr
    check validRunId(id)
    let gid = rep["gid"].getInt
    check gid >= FirstMarkerGid
    let load = f.calls.find("-a " & runAnchor(id) & " -f -")
    check load >= 0
    check f.inputs[load].contains("group = " & $gid)
    check f.inputs[load].contains("table <v4> { 1.2.3.4 }")
    check f.inputs[load].contains("port { 5432 }")
    check f.inputs[load].count("port { 5432 }") == 4
    check liveRuns(d) == 1

  test "gids are never shared, never a system group, and reused after end":
    let d = daemon(addr f, toHashSet([42400]))
    let a = handle(d, %*{"op": "begin", "loopPorts": [], "snapshot": []})["gid"].getInt
    let b = handle(d, %*{"op": "begin", "loopPorts": [], "snapshot": []})["gid"].getInt
    check a == 42401 and b == 42402
    check handle(d, %*{"op": "end", "runId": "nope"})["ok"].getBool
    check liveRuns(d) == 2
    let id = handle(d, %*{"op": "begin", "loopPorts": [], "snapshot": []})["runId"].getStr
    check handle(d, %*{"op": "end", "runId": id})["ok"].getBool
    check liveRuns(d) == 2
    check ("-a com.sandwall.runs/" & id & " -F all") in f.calls

  test "a full range is refused":
    let d = daemon(addr f, toHashSet(toSeq(FirstMarkerGid .. LastMarkerGid)))
    let rep = handle(d, %*{"op": "begin", "loopPorts": [], "snapshot": []})
    check not rep["ok"].getBool
    check rep["error"].getStr.contains("full")

  test "refresh replaces the tables; an unknown run is refused":
    let d = daemon(addr f)
    let id = handle(d, %*{"op": "begin", "loopPorts": [], "snapshot": []})["runId"].getStr
    let rep = handle(d, %*{"op": "refresh", "runId": id, "loopPorts": [22],
      "snapshot": snapshotJson(@[entry("a.com", @[], @["9.9.9.9"])])})
    check rep["ok"].getBool
    check f.inputs[^1].contains("table <v4> { 9.9.9.9 }")
    check f.inputs[^1].contains("port { 22 }")
    let bad = handle(d, %*{"op": "refresh", "runId": "ghost", "loopPorts": [],
      "snapshot": []})
    check not bad["ok"].getBool

  test "a pfctl refusal means begin fails and nothing is published":
    let d = daemon(addr f)
    f.refuse = "-f -"
    let rep = handle(d, %*{"op": "begin", "loopPorts": [], "snapshot": []})
    check not rep["ok"].getBool
    check liveRuns(d) == 0

  test "the sweep retires an idle run past its lease, never a live child":
    let d = daemon(addr f)
    let id = handle(d, %*{"op": "begin", "loopPorts": [], "snapshot": []})["runId"].getStr
    f.now = 1000.0 + RunLeaseSeconds / 2
    sweep(d)
    check liveRuns(d) == 1
    f.now = 1000.0 + RunLeaseSeconds + 1
    markExec(addr d[], id, 4242)
    sweep(d)
    check liveRuns(d) == 1
    markExec(addr d[], id, 0)
    sweep(d)
    check liveRuns(d) == 0
    check ("-a com.sandwall.runs/" & id & " -F all") in f.calls
    check execGid(addr d[], "gone") == -1

  test "exec marker: an unknown run is refused, the open case is no marker":
    let d = daemon(addr f)
    check execGid(addr d[], "") == 0
    check execGid(addr d[], "not-a-run") == -1
    let id = handle(d, %*{"op": "begin", "loopPorts": [], "snapshot": []})
    check execGid(addr d[], id["runId"].getStr) == id["gid"].getInt

  test "start: enable, patch the main ruleset once, flush stale runs, block orphans":
    let d = daemon(addr f)
    ensurePf(d)
    check f.calls[0] == "-E"
    check f.calls[1] == "-s rules"
    check "-a com.sandwall.runs/* -F all" in f.calls
    check "-a com.sandwall.orphans -f -" in f.calls
    check f.inputs[f.calls.find("-f -")].contains(anchorCallLines())
    check f.inputs[^1] == orphanRules()
    # a second start finds the calls and does not reload the main ruleset
    let n = f.calls.len
    ensurePf(d)
    check "-f -" notin f.calls[n .. ^1]

when defined(posix):
  import std/posix except Time
  import std/[tables, threadpool]

  suite "pf daemon protocol":
    var f: Fake
    var d: Daemon
    let sock = getTempDir() / "test-sandwallpf-" & $getCurrentProcessId() & ".sock"

    # One daemon and one socket for the whole suite: the serve thread
    # of the first test owns the path for the rest of the run.
    if d == nil:
      f = Fake(now: 1000.0)
      d = daemon(addr f)

    test "ping, begin, end over the socket":
      spawn serve(sock, geteuid().int, d)
      var ok = false
      for i in 0 .. 200:              # the listener comes up in its thread
        if pfPing(sock): ok = true; break
        sleep 10
      check ok
      let id = pfBegin(sock, @[5432'u16], @[entry("a.com", @[], @["1.2.3.4"])])
      check validRunId(id)
      check liveRuns(d) == 1
      pfRefresh(sock, id, @[], @[])
      pfEnd(sock, id)
      check liveRuns(d) == 0
      pfEnd(sock, id)                # idempotent

    test "exec without a marker runs the command with this stdio and cwd":
      let code = pfExec(sock, "", @["/bin/sh", "-c",
        "pwd; echo pf-stdout; echo pf-stderr >&2; exit 3"], "/tmp")
      check code == 3

    test "exec with an unknown run is refused, the command never runs":
      expect PfError:
        discard pfExec(sock, "ghost", @["/bin/sh", "-c", "touch /tmp/pf-ghost"], "/tmp")
      check not fileExists("/tmp/pf-ghost")

    test "exec renews the lease and holds the run until the child exits":
      let id = pfBegin(sock, @[], @[])
      # Unprivileged the marker cannot be applied and the child exits
      # 126 before running; as root it runs. Either way the run is kept
      # for the child's lifetime and swept afterwards.
      let before = liveRuns(d)
      let code = try: pfExec(sock, id, @["/bin/sh", "-c", "exit 0"], "/tmp")
                 except PfError: -1
      check code >= 0
      check liveRuns(d) == before
      pfEnd(sock, id)
      check liveRuns(d) == before - 1

    test "a caller that is not the recorded account is refused":
      spawn serve(sock & "-other", geteuid().int + 1, d)
      var refused = false
      for i in 0 .. 200:
        try:
          discard pfCall(sock & "-other", pingReq())
          break
        except PfError as e:
          if e.msg.contains("setup"): refused = true; break
          sleep 10
      check refused

    test "a daemon that is not there fails closed":
      expect PfError:
        discard pfCall(sock & "-absent", pingReq())
      check not pfPing(sock & "-absent")
