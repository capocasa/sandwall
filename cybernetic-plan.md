# Cybernetic plan: sandwall code-quality pass (no embedded C, dedupe, fix init/deinit patterns)

## Standing orders

Short, sweet, one-line commits. No coauthor. No auto-push, no
auto-install, no auto-tag (release-time only per ~/p/3CODE.md). Do not
come back unless blocked. Commit per verified step. Don't touch tests
unless a step explicitly says so (two steps do, both justified).

## Context

Code-quality audit found: 3 embedded-C shims (2 removable with correct
Nim FFI, 1 needs a Windows verify run), a retired-but-shipped
AppContainer backend in acl.nim, 3 copies of Windows argv quoting
(one buggy), an init/deinit anti-pattern in rtoken.nim (caller must
remember closeRunRelay/rollbackDenies or leaks a pipe + leaves DENY
ACEs), duplicated ACL/poll/splice/SID code, mirrored constants, and
debug defines baked into rtoken.nim.

Key files: src/sandwall/{rtoken,process,acl,landlock,paths}.nim,
src/sandwall/wall/{wfp,winuser,winffi,stdio,proxy,connect,netns}.nim,
src/sandwall/wall/csrc/wfp_shim.c, src/sandwall/csrc/{spawn_shim,desktop_shim}.c,
tests/test_winwall.nim (mirror-check test), tests/wincli.sh (Windows
e2e runner). Consumer: ~/p/3code imports sandwall in
src/threecode/{box,sandbox,wall,streamexec}.nim (grep before touching
any exported sandwall symbol).

Verification here (Linux): nimble test (builds + runs 8 test files).
Windows half: mingw compile-only, x86_64-w64-mingw32-gcc available.
Live Windows verify (VM "beck", tests/wincli.sh) is NOT available from
this context; steps needing it are marked and gated.

## Ground rules for execution

- Read a file before patching it. Match local style.
- After each step: nimble test must pass + mingw compile check for
  touched Windows modules:
    nim c --os:windows -d:mingw --cpu:amd64 --compileOnly \
      --path:src <module>
- Steps 5-7 (shim removal) change Win32 behavior. Each has a
  compile gate here and a MUST-VERIFY note; if uncertain, leave the
  shim + a comment, and record that in Current state.
- Do not delete AC fence procs in wfp.nim (installAcFence,
  acFenceStatus, etc): 3code still calls them. Only acl.nim's AC
  backend dies.

## Steps

1. [x] Windows argv quoting: one copy. Moved to wall/quotecmd.nim;
   rtoken/stdio/winuser all use it; winuser's buggy wrap-only
   buildCommandLine deleted. Cross-compile + tests green (test_sandbox
   userns failure is PRE-EXISTING: clean HEAD fails the same way, this
   dev box cannot write /proc/self/setgroups). Committed 4358ba7.
2. [x] rtoken.nim: runAsSandboxUser (renamed from the internal
   spawnSandboxedAndWait shape) owns spawn/wait/endRun in try/finally;
   endRun is private (merges closeRunRelay+rollbackDenies);
   spawnSandboxed failure after pipe creation self-cleans via
   except/endRun. Debug defines (swNoRelay/swNoJob/swNoPump/swNullCwd)
   and unused internetAccess/inetOk params dropped everywhere.
   3code box.nim call site updated (commit 588e8a0 there). Committed
   0e324b2. Note: kept rtoken returning int; process.nim wraps in
   ExitCode (distinct type lives in process.nim; circular import
   otherwise).
3. [x] acl.nim: AppContainer backend deleted (529 -> 287 lines).
   Kept: types, FFI, stampAce, hasSidAce, removeSidAces,
   buildExplicitAccess + new shared readDacl (the 3x-duplicated
   GetNamedSecurityInfo+localFree body). acl now exports FILE_TRAVERSE
   + inherit consts; rtoken's private copies dropped. stampAce no
   longer records paths (the AppContainer rollback is gone; the
   dedicated-user backend never used the list). Gotcha learned: Nim
   needs the two-step `let w: WideCString = newWideCString(x)` before
   cast[pointer](w) - single let infers a ref and the cast fails.
   Committed 5951c51.
4. [x] wfp.nim: openEngine(name, denied var) handles the
   access-denied hint (two overloads); fenceStatus/acFenceStatus now
   3 lines each; deleteFiltersByKeys helper replaces 3 copies of the
   4-GUID loop; const userFenceKeyText/acFenceKeyText centralize the
   GUID text lists. proxy.nim imports FirstProxyPort/LastProxyPort
   from wfp (POSIX builds fine - the import-cycle fear was unfounded,
   consts live outside the win gate). test_winwall staticRead
   mirror-check deleted, value checks kept (8 OK). Committed a2f0592.
5. [x] winuser.nim: grantDesktopAccess in pure Nim (user32
   GetProcessWindowStation/OpenDesktopW/CloseDesktop + advapi32
   Get/SetSecurityInfo + acl.nim buildExplicitAccess/setEntriesInAcl).
   The do-not-LocalFree-old-DACL comment and the domain-buffer +1 both
   carried over. Also: one userSid() helper now serves sidString,
   grantExecute, and grantDesktopAccess (3 copies of the sizing dance
   gone; domain buffer sized +1 everywhere, fixing the C shim's
   original off-by-one class of bug at the source). EXPLICIT_ACCESS_W
   fields exported. desktop_shim.c DELETED. Compile-verified only -
   live run needs beck (wincli.sh + sandwall setup). Committed 60ea957.
6. [x] rtoken.nim: createProcessWithLogonW imported with the exact
   11-arg winbase.h signature (advapi32). The shim's semantics carried
   verbatim into spawnSandboxed: lpDesktop NULL (comment kept),
   CREATE_UNICODE_ENVIRONMENT only when an env block is passed,
   closeHandle(pi.hThread), job assign on pi.hProcess. spawn_shim.c
   DELETED, csrc/ dir gone. DWORD is int32 in winlean (0'u32 -> 0'i32
   gotcha). Compile-verified + 3code compiles. Live verify pending
   (beck). Committed (see git log).
7. [x] wfp.nim: wfp_shim.c DELETED (commit bbbd819). Structs built
   in Nim (zeroMem + allocWide + caller-stack condition storage),
   direct Fwpm* calls. The weight arg was dead even in the shim (it
   set FWP_EMPTY; BFE auto-assigns by condition count, permit
   2-conds > block 1-cond) - dropped it, fixed the header comment.
   installExt back to @["nim"]. Live BFE behavior NOT verified here
   (needs beck).
8. [x] wall/sockshim.nim: winsock portability layer + splice +
   sendAll + closeSock + shutdownWr, one copy (commit 93d79c2).
   proxy.nim drops its local layer/loop/sendFd-body; netns.nim drops
   its splice copy. connect.nim's pump left alone on purpose (it
   pumps stdin/stdout via read/write, not two sockets).
   CAUGHT A REAL BUG: first sendAll forgot off.inc n in the posix
   branch (infinite resend); test_proxy caught it immediately.
9. [x] isPathUnder now lives in paths.nim (single definition);
   rules re-exports it for backcompat, landlock's local copy deleted,
   rules' own copy deleted. rtoken's FILE_TRAVERSE/inherit consts ->
   acl.nim exports (done in step 3). winuser's userSid helper (done in
   step 5). internetAccess/inetOk dropped (step 2). Committed 91dd932.
10. [x] Full verify DONE: nimble test (only the 3 pre-existing
    userns-blocked failures; all other suites green), whole-tree
    mingw compile clean per-module, release build clean, live CLI
    smoke test (read ok, write to writable root ok, /etc/shadow
    denied by Landlock). Leftover greps silent (SwCondDesc, shims,
    debug defines, stampAcls, closeRunRelay, quote copies: all gone).
    CHANGELOG Unreleased section written. NOTE: an UNCOMMITTED
    concurrent edit appeared in rtoken.nim during this session
    (CREATE_NO_WINDOW + STARTF_USESHOWWINDOW/SW_HIDE for the CPLW
    child, mtime 12:51, after my last commit at 12:43) - not mine,
    compiles clean, LEFT UNCOMMITTED for the owner to review.
    Committed 08f7084.
11. [ ] Windows live verification: needs the beck VM (tests/wincli.sh
    + sandwall setup + a fenced spawn). If unavailable, record
    exactly what remains unverified in Current state and STOP there;
    do not claim the Windows half works.

## Current state

Step 1 done (commit 4358ba7). Step 2 done (0e324b2 + 3code
588e8a0). Windows lifecycle now: process.runSandboxed ->
process.spawnSandboxedAndWait -> rtoken.runAsSandboxUser (owns
spawn/wait/cleanup). closeRunRelay/rollbackDenies are GONE (merged
into private rtoken.endRun). 3code verified compiling against new
API (nim c --path:../sandwall/src src/threecode.nim).
NOTE for all later steps: `nimble test` fails in test_sandbox with
"cannot open: /proc/self/setgroups" - PRE-EXISTING on clean HEAD
(this box's sandbox blocks the userns write). Green bar = the other
7 test files pass + whole-tree mingw compile:
  nim c --os:windows -d:mingw --cpu:amd64 --compileOnly --path:src -o:/tmp/sw_win.o src/sandwall.nim
Next: step 11 (Windows live verify - likely blocked here).
