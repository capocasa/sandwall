## permit: hostname rules as resolved address sets.
##
## The forwarder decides by name and dials by address. The spawn-time
## backends (WFP filters, Seatbelt allow lines) never see a name: they
## permit addresses, and only the ones known when the child was spawned.
## This module is the brain the two share. One entry per hostname carries
## the ports its allow rules still stand for and two address
## generations: `current`, and `previous`, kept for a grace period so a
## rotation does not cut off a peer that still holds the old address.
##
## Two ways in, one table:
##
##   getOrResolve    lazy. The forwarder resolves a name when a
##                   connection first asks for it and again once the
##                   refresh interval has passed. A name a wildcard
##                   covers is learned on first use; wildcards are
##                   never enumerated.
##   seedFromPolicy  proactive. A child that connects directly has no
##                   forwarder to resolve for it, so every exact name
##                   in the policy is resolved up front, within a
##                   deadline. IP literals and hosts-file names go in
##                   without a lookup and never expire.
##
## Refresh is a fixed interval, not DNS TTL: `getaddrinfo` reports no
## TTL, so there is nothing to honor. Per-connect freshness is an age
## check against that interval.
##
## Failure is classified by the resolver:
##
##   addresses   replace `current`; the set they replace becomes
##               `previous` for the grace period
##   NXDOMAIN    retract: the name does not exist, so the entry goes
##   transient   no answer right now (resolver down, SERVFAIL, timeout).
##               Keep the last good addresses, mark the entry `stale`
##               and warn once per outage. The very first lookup has
##               nothing to keep and fails.
##
## An ambiguous resolver error is transient. A timeout never retracts.
##
## Concurrency: one lookup per name at a time. The first caller
## resolves with the set lock released; callers arriving meanwhile wait
## for that name, bounded by `resolveTimeoutMs`, and get whatever the
## table holds when their wait runs out. std has no timed condition
## wait, so waiting is a 1 ms sleep loop.
##
## Ownership. ORC's reference counts are plain here, not atomic, and
## its cycle collector keeps its books per thread, so an object of this
## module must never be in use in two threads at once, and nothing that
## can form a cycle may be freed outside the thread that made it. A
## count lost to a race frees a thing early, and the crash shows up
## somewhere else entirely. The set keeps to three rules. The table
## holds private copies of everything put into it (keys, names,
## addresses). Everything handed out is a private copy made under the
## lock. A pool worker owns no reference at all: it is handed a raw
## pointer to the set and a raw record of its own, and copies out what
## it needs. Only strings and seqs of plain values cross a thread
## boundary, and the set lock serializes their counts.

import std/[algorithm, json, locks, net, nativesockets, os, options, sets,
            strutils, syncio, tables, times]
when defined(posix):
  import std/posix
else:
  import winlean except Socket
import ./hosts

const
  MinRefreshS* = 60.0        ## below this the resolver is hammered for no freshness
  DefaultRefreshS* = 300.0
  GraceS* = 300.0           ## how long a replaced address set stays permitted
  MaxEntries* = 10_000      ## entry cap; past it the oldest expired entry goes
  PoolSize = 8               ## lookups in flight at once, at most
  SnapshotVersion = 1

type
  PermitEntry* = object
    host*: string              ## lowercase name, or an IP literal
    ports*: seq[uint16]        ## ports the name's allow rules stand for; 0 = all
    current*: seq[IpAddress]   ## this generation's addresses
    previous*: seq[IpAddress]  ## the set `current` replaced, kept until `prevUntil`
    expires*: float            ## epoch seconds after which `current` wants a refresh
    prevUntil*: float          ## epoch seconds until which `previous` is permitted
    lastGood*: float           ## epoch seconds of the last good answer; 0 before any
    stale*: bool               ## past `expires`, and the refresh attempt got no answer

  ResolveOutcome* {.pure.} = enum
    roAddrs                   ## `ips` holds the answer
    roNxdomain                ## the resolver knows the name does not exist
    roTransient               ## no answer right now

  ResolveResult* = object
    outcome*: ResolveOutcome
    ips*: seq[IpAddress]

  Resolver* = proc(name: string): ResolveResult {.gcsafe, raises: [].}

  LogProc* = proc(msg: string) {.gcsafe, raises: [].}
    ## Called from any thread, never with the set lock held.

  SeedReport* = object
    resolved*: int           ## names that came back with addresses
    failed*: seq[string]     ## names left with no address to serve
    pending*: seq[string]    ## names still being looked up when the deadline hit
    wildcards*: seq[string]  ## allow rules no set can enumerate: `*`, `*.suffix`

  Batch = object
    ## The job the pool is on. It lives in the set, under its lock, and
    ## holds private copies: the caller's own seqs are not kept alive
    ## by it, and no worker gets a reference into them.
    names: seq[string]
    ports: seq[seq[uint16]]
    done: seq[bool]
    next: int
    left: int
    active: bool
    gen: int                 ## which job this is; a worker outliving its job checks it

  PoolWorker = object
    ## A pool thread's own record, on the shared heap and untraced: it
    ## points at the set (valid from pool start until `close`) and parks
    ## on its own lock and cond, so an abandoned set's idle workers never
    ## touch freed memory.
    ps: ptr PermitSetObj
    lock: Lock
    cond: Cond
    called: bool             ## a job is waiting
    stop: bool               ## the pool is closing

  PermitSet* = ref PermitSetObj
    ## Hostnames resolved to addresses, with the lookup pool behind
    ## `seedFromPolicy` and `refreshForSpawn`. Safe from any number of
    ## threads.

  PermitSetObj = object
    lock: Lock
    table: Table[string, PermitEntry]
    inflight: Table[string, int]  ## name -> generation its lookup began in
    gen: int                      ## bumped whenever the table is cleared
    batch: Batch
    workers: seq[ptr Thread[ptr PoolWorker]]
    resolver: Resolver
    clock*: proc(): float {.gcsafe, raises: [].}
      ## epoch seconds; injectable, so tests move time instead of waiting
    log*: LogProc
    refresh*: float          ## seconds; the fixed refresh interval
    grace*: float            ## seconds
    resolveTimeoutMs*: int   ## how long a waiter waits for a lookup it does not own
    maxEntries*: int
    hostsPath*: string       ## hosts(5) file; names listed there are seeded without DNS
    capLogged: bool

# ------------------------------------------------------ private copies

proc fresh(s: string): string =
  ## A copy of `s` that shares no allocation with it.
  if s.len == 0: return ""
  result = newString(s.len)
  copyMem(addr result[0], unsafeAddr s[0], s.len)

proc fresh[T](xs: seq[T]): seq[T] =
  ## A copy of `xs`, element by element. `T` must hold no reference of
  ## its own (an address, a port, a flag).
  if xs.len == 0: return
  newSeq(result, xs.len)
  for i, x in xs: result[i] = x

proc fresh(e: PermitEntry): PermitEntry =
  PermitEntry(host: fresh(e.host), ports: fresh(e.ports),
              current: fresh(e.current), previous: fresh(e.previous),
              expires: e.expires, prevUntil: e.prevUntil,
              lastGood: e.lastGood, stale: e.stale)

# ---------------------------------------------------------- ports

proc portAllowed*(ports: openArray[uint16]; port: uint16): bool =
  ## Is `port` admitted by an entry's `ports` (0 = all)?
  for p in ports:
    if p == 0 or p == port: return true
  false

proc unionPorts(a, b: openArray[uint16]): seq[uint16] =
  ## Both port lists, deduplicated. A 0 in either one is the whole range
  ## and swallows the other.
  for p in a:
    if p == 0: return @[0'u16]
    if p notin result: result.add p
  for p in b:
    if p == 0: return @[0'u16]
    if p notin result: result.add p

# ---------------------------------------------------------- resolver

when defined(windows):
  const
    WsaHostNotFound = 11001'i32   ## authoritative: no such host
    WsaNoData = 11004'i32         ## valid name, no address record
else:
  # C macros: imported as variables, the way winlean imports socket levels
  var
    EaiNoname {.importc: "EAI_NONAME", header: "<netdb.h>".}: cint
  when defined(linux) or defined(macosx):
    var
      EaiNodata {.importc: "EAI_NODATA", header: "<netdb.h>".}: cint

proc isNxdomainCode(rc: cint): bool =
  ## Which resolver error means "that name does not exist" rather than
  ## "no answer right now". Everything else is transient.
  when defined(windows):
    rc == WsaHostNotFound or rc == WsaNoData
  else:
    if rc == EaiNoname: return true
    when defined(linux) or defined(macosx):
      rc == EaiNodata
    else:
      false

proc systemResolver*(name: string): ResolveResult {.gcsafe, raises: [].} =
  ## The OS resolver, both families, with its errors classified. It
  ## blocks as long as the resolver does; there is no timeout here on
  ## purpose: a slow answer is "not yet", which is transient.
  var hints: AddrInfo
  hints.ai_family = toInt(AF_UNSPEC)
  hints.ai_socktype = toInt(SOCK_STREAM)
  var list: ptr AddrInfo
  let rc = getaddrinfo(name, nil, addr hints, list)
  if rc != 0:
    return ResolveResult(outcome:
      if isNxdomainCode(rc): roNxdomain else: roTransient)
  defer: freeAddrInfo(list)
  var it = list
  while it != nil:
    if it.ai_addr != nil:
      if it.ai_family == toInt(AF_INET):
        let sa = cast[ptr Sockaddr_in](it.ai_addr)
        var a = IpAddress(family: IpAddressFamily.IPv4)
        copyMem(addr a.address_v4[0], addr sa.sin_addr, sizeof(a.address_v4))
        result.ips.add a
      elif it.ai_family == toInt(AF_INET6):
        let sa = cast[ptr Sockaddr_in6](it.ai_addr)
        var a = IpAddress(family: IpAddressFamily.IPv6)
        copyMem(addr a.address_v6[0], addr sa.sin6_addr, sizeof(a.address_v6))
        result.ips.add a
    it = it.ai_next
  result.outcome = if result.ips.len > 0: roAddrs else: roTransient

# ---------------------------------------------------------- hosts file

proc defaultHostsPath(): string =
  when defined(windows):
    getEnv("SystemRoot", r"C:\Windows") & r"\System32\drivers\etc\hosts"
  else:
    "/etc/hosts"

proc parseHostsFile(path: string): Table[string, seq[IpAddress]] =
  ## name -> addresses, from a hosts(5) file. A missing or unreadable
  ## file is simply empty: hosts-file seeding is a shortcut, not a
  ## requirement, so nothing raises here.
  let text =
    try: readFile(path)
    except CatchableError: return
  for raw in text.splitLines:
    let hash = raw.find('#')
    let line = if hash >= 0: raw[0 ..< hash] else: raw
    let fields = line.splitWhitespace()
    if fields.len < 2: continue
    let address = try: parseIpAddress(fields[0])
                  except ValueError: continue
    for i in 1 ..< fields.len:
      let name = normalizeHost(fields[i])
      var known = result.getOrDefault(name)
      if address notin known: known.add address
      result[name] = known

# ---------------------------------------------------------- lifetime

proc newPermitSet*(refreshS = DefaultRefreshS; graceS = GraceS;
                   resolver: Resolver = nil): PermitSet =
  ## An empty permit set. `refreshS` is clamped to `MinRefreshS`; a nil
  ## `resolver` is the OS resolver. Once the lookup pool has started,
  ## `close` is what lets the set go.
  result = PermitSet(
    resolver: if resolver.isNil: Resolver(systemResolver) else: resolver,
    clock: proc (): float = epochTime(),
    log: proc (msg: string) =
      try: stderr.writeLine("sandwall permit: " & msg)
      except CatchableError: discard,
    refresh: max(refreshS, MinRefreshS),
    grace: graceS,
    resolveTimeoutMs: 5000,
    maxEntries: MaxEntries,
    hostsPath: defaultHostsPath())
  initLock(result.lock)

proc close*(ps: PermitSet) =
  ## Stop the lookup pool and release the set's lock. Blocks until every
  ## worker is back from its current lookup, so a stuck resolver makes
  ## it wait too. Once. A set whose pool started and was never closed is
  ## never freed: its idle workers still point at it.
  withLock ps.lock:
    for slot in ps.workers:
      let w = slot[].data
      withLock w.lock:
        w.stop = true
        signal(w.cond)
  for slot in ps.workers:
    joinThread(slot[])
    let w = slot[].data
    deinitCond(w.cond)
    deinitLock(w.lock)
    deallocShared(w)
    deallocShared(slot)
  ps.workers = @[]
  deinitLock(ps.lock)

# --------------------------------------------------- under the lock

proc resetLocked(ps: PermitSet) =
  ps.table.clear()
  inc ps.gen
  ps.capLogged = false

proc putLocked(ps: PermitSet; e: PermitEntry): tuple[kept: bool, note: string] =
  ## Insert or replace `e`, under the entry cap: at the cap the oldest
  ## expired entry makes room, and when nothing is due `e` is dropped
  ## instead, logged once per visit to the cap. Also returns the line to
  ## log once the lock is released ("" when there is none).
  if ps.table.len >= ps.maxEntries and not ps.table.hasKey(e.host):
    var victim = ""
    var oldest = Inf
    let now = ps.clock()
    for name, x in ps.table:
      if x.expires <= now and x.expires < oldest:
        oldest = x.expires
        victim = name
    if victim.len == 0:
      if ps.capLogged: return (false, "")
      ps.capLogged = true
      return (false, "entry cap (" & $ps.maxEntries & ") reached; dropping " & e.host)
    ps.table.del(victim)
  ps.table[e.host] = e
  if ps.table.len < ps.maxEntries: ps.capLogged = false
  (true, "")

proc applyLocked(ps: PermitSet; name: string; won: seq[uint16];
                 answer: ResolveResult): string =
  ## Fold one resolver answer into `name`'s entry. Returns the line to
  ## log once the lock is released.
  let now = ps.clock()
  let old = ps.table.getOrDefault(name)
  let ports = unionPorts(old.ports, won)
  if answer.outcome == roAddrs and answer.ips.len > 0:
    let key = fresh(name)
    var e = PermitEntry(host: key, ports: ports, current: fresh(answer.ips),
                        previous: old.previous, prevUntil: old.prevUntil,
                        expires: now + ps.refresh, lastGood: now)
    if old.current.len > 0 and old.current != answer.ips:
      e.previous = old.current
      e.prevUntil = now + ps.grace
    return ps.putLocked(e).note
  if answer.outcome == roNxdomain:
    ps.table.del(name)
    if old.current.len == 0: return ""
    return name & " no longer resolves; dropped its addresses"
  # transient
  if old.current.len == 0: return ""
  var e = old
  e.ports = ports
  e.stale = true
  ps.table[name] = e
  if old.stale: "" else:
    "resolver has no answer for " & name & "; serving stale addresses (" &
      $old.current.len & ")"

proc settleLocked(ps: PermitSet; name: string; won: seq[uint16];
                  answer: ResolveResult): string =
  ## Record a finished lookup, unless the table was cleared while it
  ## ran: that answer belongs to rules that are gone.
  if ps.inflight.getOrDefault(name) == ps.gen:
    result = ps.applyLocked(name, won, answer)
  ps.inflight.del(name)

proc reportLocked(ps: PermitSet; names: seq[string]; done: seq[bool]): SeedReport =
  ## Classify a batch of lookups by the table as it stands now. A name
  ## that finished with a stale entry to serve is in none of the lists.
  let now = ps.clock()
  for i, name in names:
    let e = ps.table.getOrDefault(name)
    if e.current.len > 0 and now < e.expires: inc result.resolved
    elif not done[i]: result.pending.add fresh(name)
    elif e.current.len == 0: result.failed.add fresh(name)

# ------------------------------------------------------------- pool

proc resolveName(ps: ptr PermitSetObj; name: string; won: seq[uint16]): bool =
  ## Look `name` up and record the answer, unless another lookup owns
  ## it (then false). The resolver runs with the lock released.
  withLock ps[].lock:
    if ps[].inflight.hasKey(name): return false
    ps[].inflight[fresh(name)] = ps[].gen
  let answer = ps[].resolver(name)
  var note: string
  withLock ps[].lock:
    # a ref is a pointer to its object
    note = settleLocked(cast[PermitSet](ps), name, won, answer)
  if note.len > 0: ps[].log(note)
  true

proc summon(w: ptr PoolWorker) =
  ## Call a worker for the job just installed.
  withLock w.lock:
    w.called = true
    signal(w.cond)

proc poolWorker(w: ptr PoolWorker) {.thread.} =
  ## One pool thread: sleep in its own record until called, then copy
  ## names out of the job and look them up with the set lock released.
  ## A job the pool outlived (its caller hit the deadline) is no longer
  ## counted; the name lands in the table all the same.
  let ps = w.ps
  while true:
    var stopping = false
    withLock w.lock:
      while not w.called and not w.stop:
        wait(w.cond, w.lock)
      w.called = false
      stopping = w.stop
    if stopping: return
    while true:
      var i = -1
      var gen = 0
      var name = ""
      var won: seq[uint16]
      withLock ps[].lock:
        let b = addr ps[].batch
        if not b.active or b.next >= b.names.len: break
        i = b.next
        inc b.next
        gen = b.gen
        name = fresh(b.names[i])
        won = fresh(b.ports[i])
      let handled = resolveName(ps, name, won)
      withLock ps[].lock:
        if ps[].batch.gen == gen:
          ps[].batch.done[i] = handled
          dec ps[].batch.left

proc startWorkersLocked(ps: PermitSet; n: int) =
  ## Bring the pool up to `n` threads. They start once and live until
  ## `close`; the set owns their records and thread slots, on the shared
  ## heap: a finished thread still writes into its own slot as it exits.
  while ps.workers.len < n:
    let w = cast[ptr PoolWorker](allocShared0(sizeof(PoolWorker)))
    w.ps = addr ps[]
    initLock(w.lock)
    initCond(w.cond)
    let slot = cast[ptr Thread[ptr PoolWorker]](
      allocShared0(sizeof(Thread[ptr PoolWorker])))
    createThread(slot[], poolWorker, w)
    ps.workers.add slot

proc runJob(ps: PermitSet; names: seq[string]; ports: seq[seq[uint16]];
            deadlineMs: int): seq[bool] =
  ## Look `names` up through the pool and wait up to `deadlineMs`.
  ## Returns which ones the pool got through; the rest land in the table
  ## whenever their lookups return. One job runs at a time.
  result = newSeq[bool](names.len)
  if names.len == 0: return
  let deadline = epochTime() + deadlineMs / 1000
  var gen = 0
  while true:
    withLock ps.lock:
      if not ps.batch.active:
        ps.batch.names = newSeq[string](names.len)
        ps.batch.ports = newSeq[seq[uint16]](names.len)
        for i, n in names:
          ps.batch.names[i] = fresh(n)
          ps.batch.ports[i] = fresh(ports[i])
        ps.batch.done = newSeq[bool](names.len)
        ps.batch.next = 0
        ps.batch.left = names.len
        ps.batch.active = true
        inc ps.batch.gen
        gen = ps.batch.gen
        ps.startWorkersLocked(min(PoolSize, names.len))
        for slot in ps.workers: summon(slot[].data)
        break
    if epochTime() >= deadline: return
    sleep(1)
  while epochTime() < deadline:
    withLock ps.lock:
      if not ps.batch.active or ps.batch.gen != gen or ps.batch.left == 0:
        break
    sleep(1)
  withLock ps.lock:
    if ps.batch.active and ps.batch.gen == gen:
      ps.batch.active = false
      result = fresh(ps.batch.done)

# ------------------------------------------------------------- public

proc getOrResolve*(ps: PermitSet; name: string;
                   ports: openArray[uint16]): Option[PermitEntry] =
  ## The entry for `name`, looking it up when the table has no fresh
  ## one. `ports` is what the policy allows for the name (see
  ## `winningPorts`), not the port of the request that happens to be
  ## asking: the entry is also consulted by address, where the name
  ## behind the request is unknown. An IP literal is its own answer and
  ## never expires. `none` when the name has no address to serve.
  let key = normalizeHost(name)
  let wanted = unionPorts(ports, newSeq[uint16]())
  if isIpAddress(key):
    var note: string
    withLock ps.lock:
      let won = unionPorts(ps.table.getOrDefault(key).ports, wanted)
      let (kept, logged) = ps.putLocked(PermitEntry(host: fresh(key),
        ports: won, current: @[parseIpAddress(key)], expires: Inf,
        prevUntil: Inf))
      if kept: result = some(fresh(ps.table[key]))
      note = logged
    if note.len > 0: ps.log(note)
    return
  var owner = false
  var note: string
  withLock ps.lock:
    if ps.table.hasKey(key):
      var e = ps.table[key]
      let merged = unionPorts(e.ports, wanted)
      if merged != e.ports:
        e.ports = merged
        ps.table[key] = e
      if ps.clock() < e.expires:
        return some(fresh(e))
    owner = key notin ps.inflight
    if owner: ps.inflight[fresh(key)] = ps.gen
  if owner:
    let answer = ps.resolver(key)
    withLock ps.lock:
      note = ps.settleLocked(key, wanted, answer)
      if ps.table.hasKey(key) and ps.table[key].current.len > 0:
        result = some(fresh(ps.table[key]))
    if note.len > 0: ps.log(note)
    return
  let deadline = epochTime() + ps.resolveTimeoutMs / 1000
  while true:
    var settled = false
    withLock ps.lock:
      settled = key notin ps.inflight
    if settled or epochTime() >= deadline: break
    sleep(1)
  withLock ps.lock:
    if ps.table.hasKey(key) and ps.table[key].current.len > 0:
      result = some(fresh(ps.table[key]))

proc seedFromPolicy*(ps: PermitSet; hosts: HostList; deadlineMs: int): SeedReport =
  ## Start over from `hosts`: drop every entry, put in the IP literals
  ## and the names the hosts file knows, and look up the rest of the
  ## exact allow rules in parallel, within `deadlineMs`.
  ##
  ## A policy cannot be enumerated when it allows by wildcard: those
  ## rules are reported in `wildcards` and seed nothing. A deny-only
  ## policy has no allow rules to seed either; its open default is not
  ## the set's to enumerate. Either way the caller needs a forwarder
  ## that decides by name.
  var seen: HashSet[string]
  var exact: seq[string]
  for m in hosts.matchers:
    if not m.allow: continue
    if m.isAll or m.isWildcard:
      let rule = if m.isAll: "*" else: "*." & m.host
      if rule notin result.wildcards: result.wildcards.add rule
    elif m.host notin seen:
      seen.incl m.host
      exact.add m.host
  let hostsFile = parseHostsFile(ps.hostsPath)
  var names: seq[string]
  var ports: seq[seq[uint16]]
  var notes: seq[string]
  withLock ps.lock:
    ps.resetLocked()
    for name in exact:
      let won = hosts.winningPorts(name)
      if won.len == 0: continue
      var entry: PermitEntry
      if isIpAddress(name):
        entry = PermitEntry(host: fresh(name), ports: won,
          current: @[parseIpAddress(name)], expires: Inf, prevUntil: Inf)
      elif hostsFile.hasKey(name):
        entry = PermitEntry(host: fresh(name), ports: won,
          current: fresh(hostsFile[name]), expires: Inf, prevUntil: Inf)
      if entry.host.len > 0:
        let (kept, note) = ps.putLocked(entry)
        if kept: inc result.resolved
        if note.len > 0: notes.add note
      else:
        names.add name
        ports.add won
  for note in notes: ps.log(note)
  let done = ps.runJob(names, ports, deadlineMs)
  withLock ps.lock:
    let r = ps.reportLocked(names, done)
    result.resolved += r.resolved
    result.failed = r.failed
    result.pending = r.pending

proc refreshForSpawn*(ps: PermitSet; deadlineMs: int): SeedReport =
  ## Look up every entry that is past its refresh, in parallel, within
  ## `deadlineMs`. Whatever is not done in time keeps serving its old
  ## addresses: a spawn never waits on a slow resolver.
  var names: seq[string]
  var ports: seq[seq[uint16]]
  withLock ps.lock:
    let now = ps.clock()
    for name, e in ps.table:
      if now >= e.expires:
        names.add fresh(name)
        ports.add fresh(e.ports)
  let done = ps.runJob(names, ports, deadlineMs)
  withLock ps.lock:
    result = ps.reportLocked(names, done)

proc clear*(ps: PermitSet) =
  ## Forget every entry, as a policy reload does: a rule that went away
  ## must stop being served. Lookups in flight began under the old
  ## rules; they run to completion and their answers are thrown away.
  withLock ps.lock:
    ps.resetLocked()

proc hold(e: PermitEntry; ip: IpAddress; now: float): bool =
  ip in e.current or (now < e.prevUntil and ip in e.previous)

proc matchIp*(ps: PermitSet; ip: IpAddress; port: uint16): Option[PermitEntry] =
  ## The entry that permits `ip` on `port`: `ip` is in its `current`
  ## set, or in `previous` while that is still within its grace, and
  ## `port` is one of the entry's ports. `none` when no entry admits it.
  withLock ps.lock:
    let now = ps.clock()
    for e in ps.table.values:
      if e.hold(ip, now) and portAllowed(e.ports, port):
        return some(fresh(e))

proc matchIp*(ps: PermitSet; ip: IpAddress): Option[PermitEntry] =
  ## The first entry that permits `ip` on any port, for a caller that
  ## checks `ports` itself or only wants the name. With several names
  ## on one address, which one comes back is unspecified; decide ports
  ## with the three-argument form.
  withLock ps.lock:
    let now = ps.clock()
    for e in ps.table.values:
      if e.hold(ip, now): return some(fresh(e))

# ---------------------------------------------------------- snapshot

proc stamp(t: float): JsonNode =
  if t == Inf: newJNull() else: newJFloat(t)

proc unstamp(n: JsonNode): float =
  if n.kind == JNull: Inf else: n.getFloat

proc entryJson(e: PermitEntry): JsonNode =
  result = newJObject()
  result["host"] = %e.host
  result["ports"] = newJArray()
  for p in e.ports: result["ports"].add newJInt(p.int)
  result["current"] = newJArray()
  for a in e.current: result["current"].add %($a)
  result["previous"] = newJArray()
  for a in e.previous: result["previous"].add %($a)
  result["expires"] = stamp(e.expires)
  result["prevUntil"] = stamp(e.prevUntil)

proc entryFromJson(n: JsonNode): PermitEntry =
  result.host = n["host"].getStr
  for p in n["ports"]: result.ports.add p.getInt.uint16
  for a in n["current"]: result.current.add parseIpAddress(a.getStr)
  for a in n["previous"]: result.previous.add parseIpAddress(a.getStr)
  result.expires = unstamp(n["expires"])
  result.prevUntil = unstamp(n["prevUntil"])

proc writeSnapshot*(ps: PermitSet; path: string) =
  ## Write every entry that has an address to `path`, sorted by host.
  ## A `previous` set past its grace is left out: the snapshot carries
  ## what a spawn may stamp.
  var entries: seq[PermitEntry]
  withLock ps.lock:
    let now = ps.clock()
    for e in ps.table.values:
      if e.current.len == 0: continue
      var c = fresh(e)
      if now >= c.prevUntil: c.previous = @[]
      entries.add c
  entries.sort(proc (a, b: PermitEntry): int = cmp(a.host, b.host))
  let nodes = newJArray()
  for e in entries: nodes.add e.entryJson
  writeFile(path, $ %* {"version": SnapshotVersion, "entries": nodes})

proc readSnapshot*(path: string): seq[PermitEntry] =
  ## The entries `writeSnapshot` left at `path`: `{"version": 1,
  ## "entries": [{host, ports, current, previous, expires, prevUntil}]}`
  ## with addresses as strings, times as epoch seconds and `null` for
  ## "never". Unknown fields are ignored. Raises IOError when the file
  ## cannot be read, JsonParsingError when it is not JSON, ValueError
  ## when its version is not one this build speaks.
  let root = parseJson(readFile(path))
  if root["version"].getInt != SnapshotVersion:
    raise newException(ValueError,
      "sandwall permit: unsupported snapshot version: " & $root["version"])
  for n in root["entries"]:
    result.add n.entryFromJson
