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

The CLI links a substantial Rust workspace. Cold builds can take tens of minutes
and use tens of gigabytes of build space. Optimized linking also uses substantial
memory. `CARGO_BUILD_JOBS=4` bounds parallel
compilation; `CARGO_TARGET_DIR=/path/with/space` selects a build cache directory.

## Install a developer preview

Run these commands from the reviewed checkout containing the agent integration
changes. The commands below do not establish that these changes are on a public
repository's default branch or in a published version.

```bash
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

The installation directory contains generated private signing keys and a virtual
environment with absolute paths. Keep it private. Use the packager below to
produce a shareable archive containing only the reviewed installation artifacts.

## Package a preview for another machine

After a successful installation check from a clean checkout, create a Linux
preview archive outside the installation directory:

```bash
python3 scripts/package-agent-preview.py \
  --installation /tmp/chio-install-check \
  --output /tmp/chio-agent-preview.tar.gz
```

The packager verifies the recorded checksums while writing the archive. It includes
only the CLI, four Python wheels, locked third-party requirements, the reviewed
examples, license and notice files, a usage guide, and public metadata. Runtime databases, receipt history,
signing keys, and virtual environments are excluded. Changed or missing artifacts,
symlinks, an incomplete acceptance report, and existing output files are rejected.
The same inputs produce identical archive bytes. The command prints the archive's
SHA-256 digest.

The recipient needs the matching Linux architecture and compatible native
libraries. After extracting into a new directory, verify `SHA256SUMS` and run
`bin/chio --version`. The CLI runs without a Rust toolchain. Python 3.11+ and `uv`
are needed only for the bundled Python examples and SDK environment; instructions
are included in the archive. Keep the extracted directory at a stable path when
an adopted client configuration references its CLI.

This is an unsigned developer preview, not a published release. The source
revision and acceptance results are local build records, not publisher
authentication. Share the archive and its checksum through a trusted channel.

Release qualification continues to use the repository's existing release
workflows and gates.

## Check a preview in a clean runtime

With Docker, Python 3.11+, and `uv` installed on the host, run:

```bash
python3 scripts/check-agent-preview-runtime.py \
  --archive /tmp/chio-agent-preview.tar.gz \
  --sha256 <expected-archive-sha256> \
  --output /tmp/chio-preview-runtime
```

Choose a new output directory outside the checkout. The check pulls a pinned
Debian Python image, verifies and extracts the archive, and installs its wheels
and hash-locked requirements into a fresh container environment. Dependency
installation needs network access. The MCP and LangChain scenarios then run in
a second container with networking disabled and no Rust, C/C++, CMake, protoc,
or uv tools. Only the archive, checker scripts, and new output directory are
mounted during execution.

`acceptance.json` records the tested distribution, libc, architecture, image
digest, archive hash, source revision, and verified effects and receipts. A
container check shares the host kernel; it does not establish compatibility
with every Linux distribution or constitute release qualification. Keep the
output directory private because its scenario state contains generated keys.

The [preview acceptance workflow](../../.github/workflows/agent-preview-acceptance.yml)
builds native Linux x86_64 and ARM64 previews, runs installation and container
acceptance, and retains successful archives and public acceptance records as
Actions artifacts for seven days. Artifact names include the source commit.
These remain unsigned developer previews.

Next, [adopt an existing local MCP configuration](ADOPT-EXISTING-MCP.md) or use the
[verified LangChain integration](../../sdks/python/chio-langchain/README.md).
