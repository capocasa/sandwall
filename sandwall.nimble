# nimble file for sandwall
# Package

version       = "0.2.1"
author        = "Carlo Capocasa"
description   = "A process-level filesystem sandbox backed by OS-native primitives (Landlock, Seatbelt, Windows ACLs)"
license       = "MIT"
srcDir        = "src"
installExt    = @["nim"]

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
