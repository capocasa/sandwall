# Chunk 4: Windows fence (WFP + dedicated user)

## Goal

Windows network fencing, mirroring Anthropic srt's `srt-win` shape:
a dedicated local user `sandwall`, persistent WFP filters keyed on its
SID (block all egress, permit loopback to a fixed proxy port range),
and a one-time elevated idempotent setup. Compile-verified only; there
is no Windows machine in this environment, so everything is written
against the Microsoft WFP docs and srt's vendor/srt-win-src/src/wfp.rs
as the reference implementation.

## Read first

- `src/sandwall/acl.nim` (existing Windows FFI style: winlean,
  widestrs, manual advapi32 declarations)
- `src/sandwall/restrict.nim` + `src/sandwall/process.nim` (how
  Windows spawns the sandboxed child today; the fs sandbox STAYS this
  way - locked decision: no-admin users keep fs sandbox without
  network)
- `impl-plan.md` locked decisions 1-4 (user name `sandwall`, DPAPI,
  fixed port range, setup-windows command, keep fs implementation)
- Reference: Microsoft Learn "Permitting and Blocking Applications and
  Users" (FilterByUserAndApp sample) and the ALE_USER_ID /
  FWPM_LAYER_ALE_AUTH_CONNECT_V4|V6 docs; srt wfp.rs filter shape
  (two filters per IP family: PERMIT loopback+port-range weighted
  above BLOCK user-SID).

## Locked parameters

- Local user name: `sandwall`. Password: 32 random chars (CSPRNG via
  BCryptGenRandom or RtlGenRandom), generated at setup, stored with
  CryptProtectData (DPAPI, CurrentUser scope) at
  `%LOCALAPPDATA%\sandwall\credentials.dat`. The file holds just the
  entropy-protected password blob; read+unprotect at launch time.
- Proxy port range: 60080-60089 (10 ports, same as srt; constant
  `FirstProxyPort`/`LastProxyPort` in the module, exported).
- Filters at FWPM_LAYER_ALE_AUTH_CONNECT_V4 and _V6, inside our own
  provider + sublayer (fixed GUIDs, generated once and hardcoded):
  1. PERMIT: IP_REMOTE_ADDRESS in 127.0.0.0/8 (v4) / == ::1 (v6) AND
     IP_REMOTE_PORT in range 60080-60089. No user condition. Weight
     0x0F80_0000_0000_0000.
  2. BLOCK: ALE_USER_ID matches an SD built from SDDL
     `O:LSG:LSD:(A;;CC;;;<sid>)` for the sandwall user's SID. Weight
     0x0F40_0000_0000_0000 (below the permit).
  Everyone else falls through to default-permit, so the host user is
  unaffected. Filter displayData names prefixed `sandwall-`.

## Instructions

### 1. `src/sandwall/wall/wfp.nim` (windows only)

advapi32/fwpuclnt FFI in acl.nim's style (winlean + manual decls,
link `-lfwpuclnt` via `{.passL.}` under `when defined(windows)`):

- Types: FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWP_VALUE0,
  FWP_V4_ADDR_AND_MASK, FWP_BYTE_ARRAY16, FWP_RANGE0,
  FWPM_PROVIDER0, FWPM_SUBLAYER0, FWP_BYTE_BLOB, GUID.
- Procs: FwpmEngineOpen0, FwpmEngineClose0, FwpmProviderAdd0,
  FwpmSubLayerAdd0, FwpmFilterAdd0, FwpmFilterDeleteById0,
  FwpmFilterCreateEnumHandle0 / FwpmFilterEnum0 /
  FwpmFilterDestroyEnumHandle0 (for status/uninstall),
  FwpmFreeMemory0.
- `proc installFence*(userSid: string; firstPort, lastPort: uint16)` -
  idempotent: open engine (dynamic session NOT used; filters persist),
  add provider + sublayer (tolerate FWP_E_ALREADY_EXISTS), delete any
  existing filters whose providerKey is ours (enum + delete), add the
  4 filters. Raise OSError with the Win32 error code on failure.
- `proc uninstallFence*()` - remove filters, sublayer, provider.
- `proc fenceStatus*(): tuple[installed: bool; filters: int;
  hint: string]` - enum-based; when BFE access is denied (non-admin),
  return `installed=false, hint` explaining that status needs admin
  and that `sandwall`-user behavioral verify is the non-elevated
  check. Never raise for access-denied.
- `proc verifyFenceBehavioral*(cred: SandwallCred): bool` - LogonUser
  + CreateProcessAsUser of a tiny self-command
  (`<self> wall wfp-probe`) that attempts a TCP connect to a fixed
  external address (192.0.2.1:9, TEST-NET-1, unroutable but the fence
  blocks before routing matters) expecting WSAEACCES. True iff the
  probe was blocked. The `wall wfp-probe` subcommand lives in the
  consumer's CLI (3code); here expose `proc wfpProbeMain*(): int` so
  the consumer wires one line.

### 2. `src/sandwall/wall/winuser.nim` (windows only)

- `proc setupSandwallUser*(): string` (returns SID string) - elevated:
  NetUserAdd("sandwall", random password, UF_NORMAL_ACCOUNT |
  UF_DONT_EXPIRE_PASSWD), NetLocalGroupAddMembers into "Users" is
  default; LookupAccountNameW -> SID -> ConvertSidToStringSidW.
  Idempotent: if the user exists, reset its password (NetUserSetInfo
  level 1003) and return the existing SID. Store the password DPAPI-
  protected (CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN) at
  `%LOCALAPPDATA%\sandwall\credentials.dat` (create dir).
- `proc loadSandwallCred*(): tuple[ok: bool; password: string]` -
  read + CryptUnprotectData. ok=false when missing/corrupt.
- `proc sidString*(): string` - SID of the sandwall user ("" when the
  user does not exist).
- Random password: BCryptGenRandom (bcrypt.dll, passL `-lbcrypt`),
  32 bytes base64-ish alphabet mapped to avoid quoting issues.

### 3. Launch path (minimal, composable)

The fs sandbox already spawns via restricted token
(process.spawnSandboxed). The wall does NOT replace it (locked
decision). Add to `src/sandwall/wall/winuser.nim`:

- `proc spawnAsSandwall*(cmd: openArray[string]): Handle` - LogonUserW
  (LOGON32_LOGON_NETWORK_CLEARTEXT? No: use LOGON32_LOGON_INTERACTIVE
  fallback NEW_CREDENTIALS is wrong for this; use
  LOGON32_LOGON_BATCH, provider DEFAULT; srt uses cleartext network
  logon - pick LOGON32_LOGON_NETWORK_CLEARTEXT with
  LOGON32_PROVIDER_WINNT50 and document why: no profile load needed
  for a fenced batch-style child, and the password never leaves the
  machine), then CreateProcessAsUserW with a CREATE_SUSPENDED-less
  plain spawn, returning the process handle. The caller combines:
  fs-restricted child (existing path) OR wall-fenced child (this
  path) OR both (document that combining = run restricted-token
  sandbox AS the sandwall user; deferred - mark UNPLANNED in the
  module header per the original plan's marking requirement).
  Actually keep it simpler: expose the logon/spawn primitive, and in
  the module header mark "combined fs+net launch" as explicitly
  UNPLANNED with a pointer to impl-plan.md.

### 4. Public wiring

- `src/sandwall/wall.nim`: add `when defined(windows): import
  ./wall/wfp; export wfp; import ./wall/winuser; export winuser`,
  and export `FirstProxyPort`/`LastProxyPort` on all platforms (define
  the constants outside the `when` so cross-compiling consumers can
  reference them).
- Nothing in `restrict()` changes on Windows yet; fenceNet stays a
  no-op there with a doc note pointing at spawnAsSandwall.

### 5. Tests

Windows-only, compile-gated. Since we cannot RUN anything windows
here: `tests/test_winwall.nim` that compiles the modules
(`nim c --os:windows --cpu:amd64 --compileOnly` if mingw is
available; check with `which x86_64-w64-mingw32-gcc` and SKIP the
nimble-task wiring with a comment if the cross toolchain is absent).
Test only pure logic that runs on Linux: SDDL string construction,
guid byte layout, port-range validation. Factor those into
`wall/wfp.nim` as pure procs (`sddlForUserSid*(sid: string): string`)
so they are testable cross-platform.

## Verification

- `nimble test` green (pure-logic parts on Linux).
- `nim c --os:windows -d:mingw --compileOnly src/sandwall/wall/wfp.nim`
  and winuser.nim compile clean IF the mingw toolchain is installed;
  if not installed, state `unverified: no mingw cross toolchain` in
  the handoff and skip.
- Self-review against the srt wfp.rs filter table (weights,
  conditions, layers) - write the comparison as a comment block at the
  top of wfp.nim.
- Commit: `windows wall: wfp fence + sandwall user + dpapi creds (compile-only)`.

## Next step

When complete and verified, call clear with:
- summary: "Chunk 4 done: wall/wfp.nim + wall/winuser.nim written to
  srt shape (sandwall user, DPAPI creds, persistent WFP filters,
  60080-60089 permit), pure logic tested on Linux, windows compile
  <status>, committed. Sandwall repo wall is feature-complete."
- instructions: "Read /home/carlo/p/3code/sandbox/impl-5.md and
  execute it. If impl-5.md does not exist yet, STOP and tell the user
  the sandwall side is done and the 3code integration plans need to be
  written next."
