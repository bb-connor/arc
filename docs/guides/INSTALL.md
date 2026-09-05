# Install Chio from source

The source installer builds the `chio` CLI from the checkout you review, using
`Cargo.lock`. It prints that checkout's revision, reports uncommitted changes,
and installs into your own directory without `sudo` or shell startup-file edits.
The MCP adoption and verified LangChain integrations require this checkout's
CLI and SDKs. An older binary with the same package version can lack those
commands; record the source revision when reporting a problem.

## Prerequisites

The installation acceptance check runs on Linux. The source installer also uses
standard Cargo installation on macOS, but that platform is not covered by this
check. The MCP importer requires Linux or macOS.

- Git and Rust installed through `rustup`. Building inside this repository selects
  the toolchain in [rust-toolchain.toml](../../rust-toolchain.toml).
- A native C/C++ toolchain, CMake, and `protoc`. On Debian or Ubuntu:
  `sudo apt-get install build-essential cmake protobuf-compiler pkg-config`.
- For the Python examples and acceptance check: Python 3.11 or newer and `uv`.

The CLI links a substantial Rust workspace. Allow several minutes for a cold
build and several gigabytes of build space. `CARGO_BUILD_JOBS=4` bounds parallel
compilation; `CARGO_TARGET_DIR=/path/with/space` selects a build cache directory.

## Install a developer preview

```bash
git clone https://github.com/backbay-labs/chio.git
cd chio
git rev-parse HEAD
./scripts/install-chio.sh --debug
export PATH="$HOME/.local/bin:$PATH"
chio --version
chio mcp adopt --help
```

`--debug` uses Cargo's development profile. Omit it for an optimized release
profile build. A local release profile build does not carry the signatures,
provenance, or qualification of a published release.

To build a specific reviewed revision, check it out before running the installer:

```bash
git checkout --detach <reviewed-commit-sha>
./scripts/install-chio.sh --root "$HOME/chio-preview" --debug
"$HOME/chio-preview/bin/chio" mcp adopt --help
```

The installer refuses to replace an existing `chio` unless you pass `--force`.
For an upgrade, review the new source revision and rerun the installer with
`--force` and the same `--root`. Cargo builds before replacing the executable.
Existing policies, kernel identities, and receipt databases are separate from
the installed binary. Keep the installation path stable when a generated MCP
configuration references it.

To remove the installed CLI, use
`cargo uninstall --root "$HOME/.local" chio-cli`, adjusting the root if needed.
This removes the executable; it does not remove your kernel state directories.

## Verify the installed workflow

From the checkout, run:

```bash
./scripts/check-agent-install.sh --debug --output /tmp/chio-install-check
```

Choose a new output directory outside the source checkout. This check:

1. Installs the CLI into `install/bin/chio` using the source installer.
2. Builds wheels for `chio-sdk`, `chio-sdk-python`, `chio-adapter-base`, and
   `chio-langchain`, then installs them into a fresh Python environment.
3. Installs third-party runtime dependencies from the checked-in Python lockfile
   with hash verification and checks dependency consistency.
4. Copies the MCP adoption and LangChain examples outside the checkout and runs
   them with isolated Python imports, actual tool processes, and the installed CLI.
5. Verifies six signed receipts across an MCP kernel restart, four permitted
   writes and two denials, then verifies a separate three-receipt LangChain run
   with two writes and a denial.

No model API key is needed. `acceptance.json` records the source revision, dirty
checkout status, build profile, installed package versions, and artifact hashes.
It is written only after both scenarios pass. The output also retains wheels,
locked runtime requirements, and local receipt evidence for inspection.

This directory is a local test installation. Its virtual environment contains
absolute paths and its state directories contain generated private signing keys;
share the manifest or wheels, not the whole directory. Checksums identify these
local artifacts; they do not authenticate a publisher. Release qualification
continues to use the repository's existing release workflows and gates.

Next, [adopt an existing local MCP configuration](ADOPT-EXISTING-MCP.md) or use the
[verified LangChain integration](../../sdks/python/chio-langchain/README.md).
