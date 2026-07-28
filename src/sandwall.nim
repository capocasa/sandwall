## sandwall - a filesystem sandbox backed by OS-native primitives.
##
## Linux uses Landlock; macOS uses Seatbelt (sandbox_init_with_parameters).
## The user-facing API is identical on both.
##
## As a library:
##   import sandwall
##   restrict("/tmp", "/home/me/work")
##   # this thread and all children can now only touch those paths
##
## As a binary:
##   sandwall restrict RWPATH [RWPATH ...] [--ro ROPATH ...] [--deny PATH ...] -- CMD [ARGS ...]
##   # confines itself to RWPATHs (writable) + ROPATHs (read-only), then exec()s CMD
##
## Two primitives, exposed both ways:
##   1. restrict(paths)  - confine the current thread's filesystem access
##   2. forkSandbox/exec/wait - fork a child where you restrict() then exec()
##
## See the `restrict` and `process` modules. Low-level Landlock access in
## `landlock`.

import ./sandwall/restrict
export restrict

import ./sandwall/process
export process

import ./sandwall/rules
export rules

# ----------------------------------------------------------------------- CLI

when isMainModule:
  import std/[os, syncio]
  when defined(posix):
    import std/posix except Time

  const usage = """
sandwall - filesystem sandbox backed by OS-native primitives

Usage:
  sandwall restrict RWPATH [RWPATH ...] [--ro ROPATH [ROPATH ...]] -- CMD [ARGS ...]

  Applies a sandbox allowing full access (read, write, create, delete,
  rename, execute) to the RWPATHs, read+execute access to the ROPATHs, and
  nothing else, then exec()s CMD. CMD and its children are confined: writes
  outside the writable paths fail with EACCES.

  System dirs (/usr, /bin, /lib, /dev/*, etc.) are always read-only so the
  command's binaries and libs stay runnable; --ro adds to that set, it does
  not replace it.

Examples:
  sandwall restrict /tmp /home/me/work -- ls -la
  sandwall restrict /build --ro /secrets -- make test
  sandwall restrict . -- make test

Landlock is monotonic: the restriction is permanent for this process and all
descendants. There is no "unrestrict".
  """

  proc cliMain(): int =
    let args = commandLineParams()
    if args.len == 0 or args[0] == "-h" or args[0] == "--help":
      stdout.writeLine(usage)
      return 0

    if args[0] != "restrict":
      stderr.writeLine(usage)
      stderr.writeLine("\nError: unknown subcommand (expected 'restrict')")
      return 2

    var
      writable: seq[string] = @[]
      readOnly: seq[string] = @[]
      denied: seq[string] = @[]
      cmd: seq[string] = @[]
      seenSep = false
      seenRo = false
      seenDeny = false

    var i = 1
    while i < args.len:
      let a = args[i]
      if seenSep:
        cmd.add(a)
      elif a == "--":
        seenSep = true
      elif a == "--ro":
        seenRo = true; seenDeny = false
      elif a == "--deny":
        seenDeny = true; seenRo = false
      elif a == "-h" or a == "--help":
        stdout.writeLine(usage); return 0
      elif seenDeny:
        denied.add(a)
      elif seenRo:
        readOnly.add(a)
      else:
        writable.add(a)
      inc i

    if writable.len == 0:
      stderr.writeLine(usage)
      stderr.writeLine("\nError: no writable paths given")
      return 2
    if cmd.len == 0:
      stderr.writeLine(usage)
      stderr.writeLine("\nError: no command given (use -- before the command)")
      return 2

    # System dirs (/usr, /bin, /lib, /dev/*, etc.) are auto-added as
    # read-only inside each backend's restrictImpl, so the command's
    # binaries and libs stay runnable without the caller listing them.
    when defined(windows):
      # Windows cannot confine the current process; restrict() only prepares
      # the token and stamps ACLs. runSandboxed spawns the child with that
      # token and rolls the ACLs back in a defer.
      #
      # The ACL backend stamps a write/delete DENY on every volume root,
      # leaving read+execute open, so C:\Windows and System32 stay readable
      # and runnable without an ALLOW ACE. User --ro paths get an explicit
      # ALLOW for read+execute so a denied volume can still be read from.
      try:
        return int(runSandboxed(writable, cmd, read = readOnly,
                                denied = denied))
      except CatchableError as e:
        stderr.writeLine("sandwall: " & e.msg)
        return 127
    else:
      # posix: confine this process, then exec into CMD. Children inherit
      # the domain, so the parent restricting itself before exec is enough.
      #
      # setsid() runs before restrict+exec so CMD lands in its own session
      # and process group. Callers (like 3code) that wrap long-running
      # commands signal the whole group on cancel/timeout; without setsid
      # those signals would miss CMD's children.
      discard setsid()
      restrict(writable, read = readOnly, denied = denied)
      try:
        exec(cmd)
      except CatchableError as e:
        stderr.writeLine("sandwall: " & e.msg)
        return 127

  quit(cliMain())
