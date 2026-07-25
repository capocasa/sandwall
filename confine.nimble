# nimble file for confine
# Package

version       = "0.1.0"
author        = "Carlo Capocasa"
description   = "A filesystem sandbox backed by OS-native primitives (Landlock, Seatbelt, Windows ACLs)"
license       = "MIT"
srcDir        = "src"
installExt    = @["nim"]

bin           = @["confine"]


# Dependencies

requires "nim >= 2.0.0"

# Tasks / tests

task test, "Run confine tests":
  # build the binary first; CLI tests invoke it from the project root
  exec "nim c --path:src -d:release -o:confine src/confine.nim"
  withDir "tests":
    exec "nim c --path:../src -r test_sandbox.nim"
