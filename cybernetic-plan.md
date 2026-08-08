# Cybernetic plan: cut sandwall 0.2.4 and wire to 3code

## Standing orders

Short, sweet, one-line commits. No coauthor. No auto-push, no
auto-install (release-time only per ~/p/3CODE.md). Do not come back
unless blocked. Commit per verified step.

## Context

Sandwall 0.2.3 (current tag) shipped broken Windows WFP code: 5
hallucinated GUIDs, wrong match-type and action-type constants, wrong
condition key for AppContainer matching. All fixed in commit 8111517,
verified live on beck: `sandwall setup` installs 12 filters, the AC
child is confined to loopback (direct connect gets WSAEACCES 10013),
the host user is unaffected.

3code depends on `sandwall >= 0.2.1` and folds the wall subcommands
into its own binary via `src/threecode/wall.nim`. The 3code wall.nim
setup code calls `setupSandwallUser` + `installFence` but does NOT
call the new `installAcFence`. The 3code spawn path (`box.nim`) calls
`runSandboxed` without `inetOk`, defaulting to false (airgap posture).
Sandwall's own `sandwall.nim` CLI already has the complete setup
(walls + AC fence + status), and its runMain already passes
`inetOk = true` for host rules.

## Part A: cut sandwall 0.2.4

### A1. Update CHANGELOG

Add a 0.2.4 section above Unreleased summarizing: WFP fence now
actually works (5 hallucinated GUIDs fixed, FWP_MATCH_RANGE=5,
FWP_ACTION flags 0x1000, ALE_PACKAGE_ID for AC matching, V6 addr mask,
enum loop, _WIN32_WINNT guard). The "six critical FFI bugs" text in
the Unreleased section was from the prior broken attempt and should
be replaced with what actually happened.

### A2. Bump version to 0.2.4

`sandwall.nimble`: version = "0.2.4". Commit "bump version".

### A3. Tag and push

`git tag 0.2.4` (no v prefix). `git push origin main --tags`.

### A4. Watch CI (if workflow exists)

`.github/workflows/` exists. `gh run watch` after push.

## Part B: wire to 3code via nimble develop

### B1. nimble develop -g in sandwall

In ~/p/sandwall: `nimble develop -g`. This creates a global symlink
so 3code picks up the live sandwall source. Verify with
`nimble paths` or checking ~/.nimble/pkgdump2 for a sandwall entry
pointing at ~/p/sandwall.

### B2. Update 3code wall.nim setup-windows

`src/threecode/wall.nim` setup-windows must mirror sandwall.nim's
setup: call `installAcFence()` after `installFence`, add `--status`
to show both fences (acFenceStatus), add `--uninstall` to call
`uninstallAcFence` too. Minimal diff: ~10 lines added to the existing
setup-windows case.

### B3. Update 3code box.nim spawn path

`src/threecode/box.nim` Windows branch calls
`runSandboxed(writable, a.cmd, read=readOnly, denied=denied)` with no
`inetOk`. Sandwall's `runSandboxed` defaults `inetOk = false`. With
host rules, this gives the AC child no internetClient capability,
which blocks ALL network including loopback to the proxy. The fence
needs the child to have internetClient (so loopback works), then WFP
blocks non-loopback. Add `inetOk = true` when host rules are present
(same logic as sandwall.nim's runMain). Check: does box.nim know
whether host rules are present? It receives `fence` (bool from the
policy). If `fence` is true (host rules present), pass `inetOk = true`.

### B4. Update 3code streamexec warning

`src/threecode/streamexec.nim` line 428 checks
`sandwallWall.sidString() == ""` to decide whether to warn. With the
new AC-fence posture, the correct check is `acFenceStatus().installed`.
Update the warning condition to call acFenceStatus instead. This is
optional but correct: the old sidString check was for the old
sandwall-user model.

### B5. Build 3code and run tests

`nimble build` in ~/p/3code. `nimble test`. Verify the wall subcommand
help shows the updated setup-windows.

### B6. Commit 3code changes

Commit the wall.nim + box.nim + streamexec.nim changes with a message
like "wire sandwall 0.2.4 AC fence to wall setup and box spawn".

## Steps

1. [ ] A1: Update CHANGELOG for 0.2.4
2. [ ] A2: Bump version to 0.2.4, commit
3. [ ] A3: Tag 0.2.4, push to origin
4. [ ] A4: Watch CI
5. [ ] B1: nimble develop -g in sandwall
6. [ ] B2: Update 3code wall.nim setup-windows (installAcFence, status, uninstall)
7. [ ] B3: Update 3code box.nim spawn path (inetOk = true for host rules)
8. [ ] B4: Update 3code streamexec warning (acFenceStatus)
9. [ ] B5: Build + test 3code
10. [ ] B6: Commit 3code changes
