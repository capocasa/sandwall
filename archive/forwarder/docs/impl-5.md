# Chunk 5: 3code integration, fallback wiring, docs, changelogs

## Goal

Wire the modes together in 3code, drop the ssh shim, document the
feature honestly, and close out with end-to-end runs and changelog entries
in both repos.

## Read first

- `~/p/3code/src/threecode/sandbox.nim` - `wallEnv`, `wallSshConfig`,
  `installSshShim`, `writeWallConf`, `moveWallSock`, `ensureWallProxy`.
- `~/p/3code/src/threecode/streamexec.nim` - the fenced spawn block
  (symbols, not line numbers: `ensureWallProxy`, `writeWallConf`,
  `wallEnv`, `installSshShim`).
- `~/p/3code/src/threecode/box.nim` - the `restrict` / `runSandboxed`
  path.
- `~/p/3code/docs/manual.md` - the Sandbox section and the scp/sftp
  paragraph.
- Both CHANGELOGs.

## Instructions

1. **wall.conf:** the parent writes `raw = on|off` plus `permits = <path>`
   after deciding. Linux: `raw = on` requires nft; the child exits 75 on
   failure and the parent re-spawns `raw = off`. Windows: `raw = on`
   only when the policy has at least one exact allow host rule, no
   wildcard allow rule, and the platform gate passed; otherwise env mode.
   macOS has no raw path (cut in chunk 4: Seatbelt cannot permit single
   addresses) and always takes env mode.
   The wrapper, where one exists, is `proxied = not raw`.
2. **No ssh shim.** The raw path removes the ProxyCommand, `wall connect`
   and the `-F` wrapper. The sandbox runs as the user, so `~`, `User`,
   config and key paths are already right. The default policy gains two
   narrow writable grants in the macOS and Linux blocks:
   `allow ~/.ssh/known_hosts` (3code touches the file if absent, so a first
   connect can persist the host key) and `allow ~/.ssh/control` (3code
   creates the dir if absent), so ControlMaster works with
   `ControlPath ~/.ssh/control/...` and no shim. The private keys stay
   denied. Env mode keeps a plain ProxyCommand wrapper for `ssh`/git, with
   no `-F` repair. Skip only `GIT_SSH_COMMAND` when raw is on. The
   existing test "unproxied fence still repairs ssh pw_dir defaults" is
   removed or rewritten to assert the new default rules, not a shim.
3. **Snapshot handoff:** the 3code parent seeds/refreshes the long-lived
   set and writes `permits.json` into the run tmp; the box child reads it
   before the backend (Windows: in `runSandboxed` before the spawn; the
   macOS seatbelt half is cut, see above). The standalone CLI builds and
   seeds in-process.
4. **Fallback:** child exit 75 with the marker line -> parent re-spawns
   with `raw = off`; one stderr line in each. The child never half-applies.
5. **scp/sftp text:** the network blind spot is gone on Linux (raw) and,
   if the gates pass, on Windows too; macOS stays env mode. Absolute-path ssh reads the
   user's config as the user and writes known_hosts through the new
   default rule, so it needs no wrapper on Linux. Update the paragraph
   per platform, honestly.
6. **docs/manual.md:** a new egress subsection (name decision, Linux
   fake-IP DNS, Windows spawn permits, what works without env vars
   per platform); the fixed-refresh note (not DNS TTL); the rotation
   note; the DNS exfil note (Linux none, Windows system resolver);
   the elevation gate; the IP-permit deny caveat; the 127/8 trade-off; the
   two ssh grants (`known_hosts` file, `~/.ssh/control` dir) and the
   `ControlPath` recommendation.
7. **CHANGELOGs** (match each repo: sandwall `### Fixed`/`### Changed` with
   plain bullets; 3code bold lead-in + what broke, why, what it costs):
   sandwall (permit set, Linux fence DNS + fake-IP + nft, WFP permits;
   no seatbelt lines, macOS is cut); 3code (env-var-free raw egress, no ssh shim, writable
   known_hosts and control-dir defaults, scp/sftp on Linux, docs).
8. **End-to-end:** Linux both modes (hide nft from the **parent** to force
   the fallback); env-only fallback; loopback regression. Extend
   `tests/core/test_wall_bash.nim`: raw ssh through redirect, deny via
   raw, fake-IP stability (forwarder verbose logs: same fake-IP, new real
   IP). Add a verbose raw log line
   (`sandwall proxy: raw <name> fake=<ip> real=<ip>:<port>`). Hermetic
   raw-path test with an injectable resolver and a local echo; e2e
   environment-gated.

## Verification

- Both repos build; `nimble test` green; Linux e2e green in both modes.
- `git diff` review in both repos: no stray debug, no TODOs, changelogs
  and manual updated.
- Leave the plan files unless the user asks to delete them.

## Next step

Feature complete. Report: what shipped, what remains environment-gated
(beck/stefani), and the documented residues (mid-command failover on
Windows, DNS exfil on Windows, IP-permit deny caveat, 127/8
host-loopback trade-off on Linux).
