## Built-in default policies, one literal block per OS.
##
## The defaults make ordinary development work inside an otherwise
## closed sandbox:
##
## * temp dirs and the project dir are writable;
## * the dependency and build caches the mainstream toolchains keep
##   under $HOME are writable, because those homes are disposable by
##   specification or construction (~/.cache is defined by the XDG
##   Base Directory spec as non-essential data; ~/.npm and ~/go hold
##   package caches and fetched modules; ~/.cargo/registry|git hold
##   downloaded dependencies);
## * the toolchain shims are read-only+execute (~/.cargo/bin,
##   ~/.rustup) - code, not data, exactly like the system /usr the
##   baseline already grants;
## * the version-control user config is readable, because the tools
##   are *fatal* without it: git aborts every invocation when
##   ~/.gitconfig exists but is unreadable (it treats EACCES unlike
##   ENOENT), cargo dies the same way on ~/.cargo/config.toml. Those
##   two lines are not an invented list - they mirror git's and
##   mercurial's own documented config search paths, of which the
##   system tier (/etc) is already covered by the sandwall baseline.
##
## The same logic covers command-line builds of the common
## languages: ~/.nimble + ~/.choosenim (the Nim toolchain: without
## them `nim` cannot even exec on a choosenim install) and ~/.local/
## share/uv read-only (uv keeps its managed pythons there; a project
## venv symlinks into it, so running .venv needs the read). Python,
## Go, C and Zig builds already ride the project dir, the read-only
## system baseline, and ~/.cache (Zig's global cache; on Windows it
## moves to ~/AppData/Local/zig). Stacks past that - ruby, java,
## gradle, scons, and friends - are deliberately NOT defaulted; their
## verified recipes live in 3code's manual.
##
## Everything else under $HOME stays denied. Token-bearing files
## (~/.npmrc, ~/.git-credentials, ~/.cargo/credentials, ~/.netrc,
## ~/.ssh, ~/.aws, ...) are deliberately absent: a missed allow fails
## loud (git dies, the user sees it), a missed deny fails silent and
## forever. There is no published "safe dotfiles" list to defer to;
## config files are private by convention, so the default opens
## exactly the documented lookup paths of the tools it wants to keep
## alive and no more.
##
## Windows keeps the same shape with its cache locations; VCS config
## is handled by the caller (3code seeds the bash child's redirected
## HOME with a copy of the real ~/.gitconfig, because the child runs
## as a separate user and git's ownership check would otherwise
## reject every repo).

when defined(windows):
  const defaultPolicyText* = """
deny /
allow ~/AppData/Local/Temp
allow ~/AppData/Local/npm-cache
allow ~/AppData/Local/pip/cache
allow ~/go
allow ~/.npm
allow ~/.cargo/registry
allow ~/.cargo/git
readonly ~/.cargo/bin
readonly ~/.cargo/config.toml
readonly ~/.rustup
allow ~/.nimble
readonly ~/.choosenim
allow ~/AppData/Local/zig
allow ./
"""
elif defined(macosx):
  const defaultPolicyText* = """
deny /
allow /tmp
allow /var/tmp
allow ./
allow ~/go
allow ~/.cache
allow ~/Library/Caches
allow ~/.npm
allow ~/.cargo/registry
allow ~/.cargo/git
readonly ~/.cargo/bin
readonly ~/.cargo/config.toml
readonly ~/.rustup
allow ~/.nimble
readonly ~/.choosenim
readonly ~/.local/share/uv
readonly ~/.gitconfig
readonly ~/.config/git
readonly ~/.hgrc
readonly ~/.config/hg
allow *
"""
else:
  const defaultPolicyText* = """
deny /
allow /tmp
allow /var/tmp
allow ./
allow ~/go
allow ~/.cache
allow ~/.npm
allow ~/.cargo/registry
allow ~/.cargo/git
readonly ~/.cargo/bin
readonly ~/.cargo/config.toml
readonly ~/.rustup
allow ~/.nimble
readonly ~/.choosenim
readonly ~/.local/share/uv
readonly ~/.gitconfig
readonly ~/.config/git
readonly ~/.hgrc
readonly ~/.config/hg
allow *
"""
