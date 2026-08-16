## quotecmd: Windows argv-to-command-line quoting, one copy.
##
## CreateProcessW takes a single command line, not an argv; the child
##'s CRT re-splits it per the rules in MSDN "Parsing C Command-Line
## Arguments". This module is the inverse of that split, shared by
## every spawn site (rtoken's CreateProcessWithLogonW hop, the stdio
## relay's CreateProcessW, winuser's CreateProcessAsUserW). The naive
## wrap-only version mangles args that themselves contain quotes -
## the `bash -c` script string - so there is exactly one correct copy.

when defined(windows):
  import std/strutils

  proc quoteArg*(a: string): string =
    ## Quote one argv element per the CreateProcessW conventions:
    ## quoted when it has whitespace or a quote; backslashes preceding
    ## a quote are doubled; trailing backslashes inside quotes are
    ## doubled.
    if a.len > 0 and a.find(Whitespace) < 0 and a.find('"') < 0:
      return a
    result = "\""
    var bs = 0
    for ch in a:
      if ch == '\\': inc(bs)
      elif ch == '"':
        result.add repeat('\\', bs * 2 + 1)
        result.add '"'
        bs = 0
      else:
        if bs > 0: result.add repeat('\\', bs); bs = 0
        result.add ch
    if bs > 0: result.add repeat('\\', bs * 2)
    result.add '"'

  proc quoteCmdLine*(cmd: openArray[string]): string =
    ## Join argv into one CreateProcessW command line.
    for i, a in cmd:
      if i > 0: result.add(' ')
      result.add quoteArg(a)
