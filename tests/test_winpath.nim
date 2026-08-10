import std/[os, unittest]
import sandwall

## Tests for the Windows bare-name resolution (findExeInPath in
## process.nim): CreateProcessW does no PATH search with a nil
## lpApplicationName, so sandwall resolves bare command names against
## PATH/PATHEXT itself (execvp parity). Windows-only: PATH entries
## use ';' and PATHEXT carries the executable extensions, so the
## lookup cannot be simulated meaningfully on POSIX.

when defined(windows):
  import std/strutils

  suite "findExeInPath":
    test "name with a directory is returned unchanged":
      check findExeInPath(r"C:\Windows\System32\xcopy.exe") ==
        r"C:\Windows\System32\xcopy.exe"
      check findExeInPath(r".\tool.exe") == r".\tool.exe"
      check findExeInPath("a/b") == "a/b"

    test "unresolvable name is returned unchanged":
      check findExeInPath("no-such-exe-sandwall-test") ==
        "no-such-exe-sandwall-test"

    test "system exe resolves via PATH and PATHEXT":
      # xcopy.exe lives in System32 on every supported Windows and
      # System32 is always on PATH; the bare name has no extension,
      # so a hit proves both the PATH walk and the PATHEXT probe.
      let hit = findExeInPath("xcopy")
      check hit != "xcopy"
      check hit.toLowerAscii.endsWith("xcopy.exe")
      check fileExists(hit)

    test "cwd wins over PATH":
      let dir = getTempDir() / "sandwall-winpath-test"
      createDir(dir)
      let fake = dir / "sandwall-fake-tool.exe"
      writeFile(fake, "")
      let oldCwd = getCurrentDir()
      setCurrentDir(dir)
      # A PATH that could not produce the hit: the cwd match must
      # be what comes back.
      putEnv("PATH", dir & "-nonexistent")
      defer:
        setCurrentDir(oldCwd)
        removeFile(fake)
        removeDir(dir)
      check findExeInPath("sandwall-fake-tool") == fake
else:
  suite "findExeInPath":
    test "windows-only":
      check true
