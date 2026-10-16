# Installing ttl

Every way to install ttl, the permissions it needs to send probes, shell
completions, and fixes for common setup problems.

[Channels](#channels) · [Permissions](#permissions) · [Shell completions](#shell-completions) ·
[Windows](#windows) · [Verify a download](#verify-a-download) · [Troubleshooting](#troubleshooting)

## Channels

<a id="from-cratesio-recommended"></a>

### crates.io

Requires a [Rust toolchain](https://www.rust-lang.org/tools/install) (1.88 or
newer):

```bash
# Install Rust if needed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

cargo install ttl
```

`cargo install ttl --no-default-features` builds without the startup update
check (see [Update Notifications](FEATURES.md#disabling-the-update-check)).

<a id="homebrew-macoslinux"></a>

### Homebrew (macOS and Linux)

```bash
brew install ttl
```

ttl is in [Homebrew core](https://formulae.brew.sh/formula/ttl). The
`lance0/tap/ttl` tap also works and installs the pre-built release binary,
sometimes shortly before the core formula updates.

### Install script

Downloads the latest pre-built binary for Linux or macOS into
`/usr/local/bin` (override with `INSTALL_DIR`). On Linux it offers to run
`setcap` for you.

```bash
curl -fsSL https://raw.githubusercontent.com/lance0/ttl/master/install.sh | sh
```

Piping a script into `sh` runs it without review.
[Read install.sh](https://github.com/lance0/ttl/blob/master/install.sh) first,
or use another channel.

### Pre-built binaries

Download from [GitHub Releases](https://github.com/lance0/ttl/releases):

| Platform | Archive |
|----------|---------|
| Linux x86_64 (static musl) | `ttl-x86_64-unknown-linux-musl.tar.gz` |
| Linux ARM64 (glibc) | `ttl-aarch64-unknown-linux-gnu.tar.gz` |
| Linux ARM64 (static musl) | `ttl-aarch64-unknown-linux-musl.tar.gz` |
| macOS Apple Silicon | `ttl-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `ttl-x86_64-apple-darwin.tar.gz` |

```bash
# Linux x86_64 example; see Verify a download below
curl -LO https://github.com/lance0/ttl/releases/latest/download/ttl-x86_64-unknown-linux-musl.tar.gz
curl -LO https://github.com/lance0/ttl/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
tar xzf ttl-x86_64-unknown-linux-musl.tar.gz && sudo mv ttl /usr/local/bin/
```

There are no pre-built Windows binaries; see [Windows](#windows).

### Docker

Multi-arch images (amd64, arm64) are published to GHCR on each release, tagged
`latest`, `X.Y` and `X.Y.Z`:

```bash
docker run --rm -it ghcr.io/lance0/ttl 8.8.8.8

# Headless monitoring with Prometheus metrics
docker run -d -p 9090:9090 ghcr.io/lance0/ttl --daemon --prometheus :9090 8.8.8.8
curl localhost:9090/metrics
```

The image is Alpine-based with a static musl binary and `ttl` as its
entrypoint. Build it locally with `docker build -t ttl .`.

Docker grants the `NET_RAW` capability by default. Stricter runtimes need it
added: `--cap-add NET_RAW` for Docker or Podman, or in Kubernetes:

```yaml
securityContext:
  capabilities:
    add: ["NET_RAW"]
```

### Distribution packages

These packages are maintained by their distributions or community packagers,
so they can lag behind the latest release.

| System | Command |
|--------|---------|
| Alpine Linux (`edge/testing`) | `apk add ttl --repository=https://dl-cdn.alpinelinux.org/alpine/edge/testing` |
| Arch Linux (AUR) | `yay -S ttl-bin` |
| Gentoo | `emerge net-analyzer/ttl` |
| NetBSD (pkgsrc) | `pkgin install ttl`, or `cd /usr/pkgsrc/net/ttl && make install` |
| Nix / NixOS (nixpkgs unstable) | `nix-shell -p ttl`, `nix-env -iA nixpkgs.ttl`, or `environment.systemPackages = [ pkgs.ttl ];` |

### From source

```bash
git clone https://github.com/lance0/ttl
cd ttl && cargo build --release
sudo cp target/release/ttl /usr/local/bin/
```

## Permissions

<a id="permissions-linux"></a>

ttl sends and receives raw ICMP, so it needs privileges on every platform.

**Linux:** grant the `CAP_NET_RAW` capability once, then run without sudo:

```bash
sudo setcap cap_net_raw+ep "$(command -v ttl)"
ttl 8.8.8.8
```

The capability is attached to the file, so reinstalling or rebuilding the
binary (including `cargo install` upgrades) clears it; run `setcap` again
afterwards. Running as root (`sudo ttl ...`) also works.

**macOS, FreeBSD and NetBSD:** run with `sudo`. ttl uses raw sockets to receive
ICMP replies on these platforms, and raw sockets require root.

```bash
sudo ttl 8.8.8.8
```

**Containers:** the process needs `NET_RAW`; see [Docker](#docker).

If ttl lacks permission, it exits with an `Insufficient permissions` error that
names the fix for the current platform.

## Shell completions

```bash
# Bash
ttl --completions bash > ~/.local/share/bash-completion/completions/ttl

# Zsh (add ~/.zfunc to fpath in .zshrc first)
ttl --completions zsh > ~/.zfunc/_ttl

# Fish
ttl --completions fish > ~/.config/fish/completions/ttl.fish

# PowerShell (append to $PROFILE)
ttl --completions powershell >> $PROFILE
```

## Windows

<a id="windows-via-wsl2"></a>

Live tracing runs under WSL2. The crate also builds on native Windows
(`cargo install ttl`), where `--replay` and `--diff` work, but tracing is not
implemented there yet: ttl exits with a message pointing to WSL2.

To set up WSL2, run in PowerShell:

```powershell
wsl --install    # then restart and open Ubuntu
```

Then, inside Ubuntu, install with the [install script](#install-script) or
[cargo](#cratesio) and run with sudo or after `setcap`:

```bash
curl -fsSL https://raw.githubusercontent.com/lance0/ttl/master/install.sh | sh
sudo ttl 8.8.8.8
```

## Verify a download

<a id="download-verification"></a>

Each release includes a `SHA256SUMS` file covering every archive.

```bash
# Linux
curl -LO https://github.com/lance0/ttl/releases/latest/download/ttl-x86_64-unknown-linux-musl.tar.gz
curl -LO https://github.com/lance0/ttl/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing

# macOS
curl -LO https://github.com/lance0/ttl/releases/latest/download/ttl-aarch64-apple-darwin.tar.gz
curl -LO https://github.com/lance0/ttl/releases/latest/download/SHA256SUMS
shasum -a 256 -c SHA256SUMS --ignore-missing
```

The install script does not verify checksums; download and verify manually if
you need that.

## Troubleshooting

### "sudo: ttl: command not found"

sudo uses a restricted `PATH` that usually excludes `~/.cargo/bin`. Use the full
path, or put the binary somewhere sudo can find it:

```bash
sudo ~/.cargo/bin/ttl 8.8.8.8                       # full path
sudo cp ~/.cargo/bin/ttl /usr/local/bin/            # one-time copy
sudo ln -sf ~/.cargo/bin/ttl /usr/local/bin/ttl     # symlink that follows cargo upgrades
```

### Permission errors

Raw ICMP sockets need `CAP_NET_RAW` or root. See [Permissions](#permissions).
On Linux, re-run `setcap` after every upgrade.

### High packet loss

Routers often rate-limit the ICMP replies ttl relies on, which looks like loss
at that hop but not beyond it. Look for the `RL?` title flag and the `RL` tag after
the loss value (see [Detection Indicators](FEATURES.md#detection-indicators)), or
slow the probes down with `-i 2.0`.

### All hops show `* * *`

A firewall, VPN, or network policy is dropping the probes or the replies. Try
another protocol: `ttl -p udp <target>` or `ttl -p tcp --port 443 <target>`.

### Theme or settings not persisting (macOS)

Since v0.12.1 the macOS config directory is `~/Library/Application Support/ttl/`
(previously `~/Library/Preferences/ttl/`). Move an older config:

```bash
mv ~/Library/Preferences/ttl ~/Library/Application\ Support/ttl
```

More limitations and platform caveats are listed in
[KNOWN_ISSUES.md](../KNOWN_ISSUES.md).
