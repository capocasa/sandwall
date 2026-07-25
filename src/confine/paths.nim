## Shared path helpers used by every OS backend.
##
## Canonicalisation matters because both Landlock and Seatbelt match on
## literal path strings: a rule for `/tmp/foo` won't cover `/tmp/./foo` or
## `/private/tmp/foo` (the macOS symlink target). `normalize` resolves those
## so the backend sees one canonical form.

import std/os

proc normalize*(p: string): string =
  ## Absolute, symlink-resolved path. Falls back to the cleaned absolute
  ## path if the target does not exist yet (e.g. a path we intend to create).
  result = absolutePath(p).normalizedPath()
  try:
    if dirExists(result) or fileExists(result):
      let r = expandFilename(result)
      if r.len > 0: result = r
  except CatchableError:
    discard
