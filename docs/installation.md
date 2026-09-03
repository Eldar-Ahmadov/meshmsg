# Installation

## Release installer

Install the latest release on x86-64 Linux:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/Eldar-Ahmadov/meshmsg/main/install.sh | bash
```

The installer detects the operating system and architecture, downloads the portable `x86_64-unknown-linux-musl` archive from the latest GitHub release, verifies it against `SHA256SUMS`, and installs `meshmsg`. It uses `/usr/local/bin` as root and `$HOME/.local/bin` otherwise.

Override the destination:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/Eldar-Ahmadov/meshmsg/main/install.sh \
  | MESHMSG_INSTALL_DIR="$HOME/bin" bash
```

Review [`install.sh`](../install.sh) before piping it to a shell. Unsupported operating systems or architectures fail without downloading an archive.

## Install from source

From a local checkout:

```sh
cargo install --locked --path .
```

Install a specific Git revision without creating a release:

```sh
cargo install \
  --git https://github.com/Eldar-Ahmadov/meshmsg.git \
  --rev <commit> \
  --locked \
  --force
```

## Manual release installation

Release archives are provided for:

- `x86_64-unknown-linux-gnu`
- `x86_64-unknown-linux-musl`
- `x86_64-pc-windows-msvc`

Download a release and verify it against `SHA256SUMS`:

```sh
gh release download <tag> --repo Eldar-Ahmadov/meshmsg
sha256sum -c SHA256SUMS --ignore-missing
```

On Linux, extract the matching `.tar.gz` and place `meshmsg` on `PATH`. On Windows, extract the `.zip` and place `meshmsg.exe` on `PATH`. The Windows release statically links the MSVC C runtime. PowerShell can verify an archive with:

```powershell
(Get-FileHash .\meshmsg-*.zip -Algorithm SHA256).Hash
```

Compare the result with the matching `SHA256SUMS` entry.

## State directory

State defaults to `$XDG_DATA_HOME/meshmsg` (`~/.local/share/meshmsg`) on Linux and the platform local data directory (normally `%LOCALAPPDATA%\meshmsg`) on Windows.

Override it consistently for both daemon and client commands with `--state-dir` or `MESHMSG_STATE_DIR`.
