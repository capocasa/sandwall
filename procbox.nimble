# nimble file for procbox
# Package

version       = "0.1.0"
author        = "Carlo Capocasa"
description   = "A process-level filesystem sandbox backed by OS-native primitives (Landlock, Seatbelt, Windows ACLs)"
license       = "MIT"
srcDir        = "src"
installExt    = @["nim"]

bin           = @["procbox"]


# Dependencies

requires "nim >= 2.0.0"

# Tasks / tests

task test, "Run procbox tests":
  # build the binary first; CLI tests invoke it from the project root
  exec "nim c --path:src -d:release -o:procbox src/procbox.nim"
  withDir "tests":
    exec "nim c --path:../src -r test_sandbox.nim"
