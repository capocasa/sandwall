# nimble file for sandwall
# Package

version       = "0.4.0"
author        = "Carlo Capocasa"
description   = "A process-level filesystem sandbox backed by OS-native primitives (Landlock, Seatbelt, Windows ACLs)"
license       = "MIT"
srcDir        = "src"
installExt    = @["nim", "c", "h"]  # c/h: csrc/wfp_shim.c compiled by wall/wfp.nim on Windows

bin           = @["sandwall"]


# Dependencies

requires "nim >= 2.0.0"

# Tasks / tests

task test, "Run sandwall tests":
  # build the binary first; CLI tests invoke it from the project root
  exec "nim c --path:src -d:release -o:sandwall src/sandwall.nim"
  withDir "tests":
    exec "nim c --path:../src -r test_sandbox.nim"
    exec "nim c --path:../src -r test_rules.nim"
    exec "nim c --path:../src -r test_hosts.nim"
    exec "nim c --path:../src -r test_proxy.nim"
    exec "nim c --path:../src -r test_connect.nim"
    exec "nim c --path:../src -r test_wall.nim"
    exec "nim c --path:../src -r test_winwall.nim"
    exec "nim c --path:../src -r test_winpath.nim"

# Windows cross-compile check (run manually; needs mingw):
#   nim c --os:windows -d:mingw --cpu:amd64 --compileOnly --path:src src/sandwall/wall/wfp.nim
#   nim c --os:windows -d:mingw --cpu:amd64 --compileOnly --path:src src/sandwall/wall/winuser.nim
#   nim c --os:windows -d:mingw --cpu:amd64 --compileOnly --path:src tests/test_winpath.nim
# tests/wincli.sh runs the end-to-end CLI cases against the beck VM.
# (wall.nim as a whole does not cross-compile: proxy/connect/netns are
# POSIX-only modules not yet gated behind `when defined(windows)`.)
# Not wired into the test task because CI/dev hosts may lack the
# x86_64-w64-mingw32 toolchain.
