## Demo: run a command sandboxed, and show the parent stays free.
##
## Three parts:
##   1. fork() a child, restrict() it, exec() ls. Show the child is confined.
##   2. Show the parent process can still write anywhere (it never restricted).
##   3. Self-invoke the CLI with the --ro syntax: a read-only path is readable
##      but not writable, a writable path is both.

import std/[os, osproc, posix, syncio, strutils]
import procbox

const
  sandboxDir = "/tmp/procbox-demo"

proc cleanup() =
  try: removeDir(sandboxDir) except CatchableError: discard
  try: removeFile(sandboxDir & ".outside") except CatchableError: discard

proc main() =
  cleanup()
  createDir(sandboxDir)

  echo "=== fork + restrict + exec ==="
  echo "parent: forking child to run 'ls /tmp' sandboxed to ", sandboxDir
  let pid = forkNimbox()
  if pid == 0:
    # child: restrict, then exec. Never returns.
    restrict([sandboxDir], read = ["/usr", "/bin", "/lib", "/etc"])
    exec(["ls", "-la", "/tmp"])
    # only reached if exec failed
    exitnow(127)
  let code = wait(pid)
  echo "parent: child exited with code ", code
  echo "  (ls saw permission denied for /tmp because only ", sandboxDir,
       " was writable)"

  echo ""
  echo "=== parent stays unrestricted ==="
  writeFile(sandboxDir & ".outside", "parent can still write anywhere")
  echo "parent wrote to ", sandboxDir, ".outside (outside the child's sandbox)"
  echo "parent can read it back: ", readFile(sandboxDir & ".outside").strip()

  echo ""
  echo "=== CLI --ro: read-only path ==="
  let roDir = sandboxDir & "-ro"
  createDir(roDir)
  writeFile(roDir / "secret.txt", "topsecret\n")
  # invoke the procbox CLI built at the project root. --ro marks a path
  # read+execute only; reads succeed, writes fail.
  let exe = parentDir(parentDir(currentSourcePath())) / "procbox"
  echo "child reads the read-only path (succeeds):"
  discard execCmd(exe.quoteShell & " restrict " & sandboxDir.quoteShell &
                  " --ro " & roDir.quoteShell &
                  " -- cat " & (roDir / "secret.txt").quoteShell)
  echo "child writes the read-only path (fails with permission denied):"
  discard execCmd(exe.quoteShell & " restrict " & sandboxDir.quoteShell &
                  " --ro " & roDir.quoteShell &
                  " -- sh -c 'echo bad > " & (roDir / "new.txt").quoteShell & "'")

  cleanup()

main()
