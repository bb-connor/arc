# Install Chio

Build the CLI from source. Install Rust with `rustup` and the Protocol Buffers
compiler (`protoc`) first; the checkout's `rust-toolchain.toml` selects Rust.

```bash
git clone https://github.com/bb-connor/arc.git
cd arc
cargo build --locked --release -p chio-cli --bin chio
export PATH="$PWD/target/release:$PATH"
chio --help
```

For the process host with Python and Node workers, use the
[process preview guide](PROCESS_PREVIEW.md). It pins the exact repository and
revision to build.

## Release status

No current Chio release is published. Build from source as described above.

The next release is a signed `0.2.0-alpha.N` preview built from `main` (REL-1
in [UNIFIED_ROADMAP.md](../operations/UNIFIED_ROADMAP.md)). It will be a GitHub
prerelease on `bb-connor/arc`, never marked Latest, and installed only by exact
tag after [VERIFY.md](VERIFY.md) authenticates it. Previews carry no format
compatibility with each other; see
[Format Stability](../release/FORMAT_STABILITY.md).

> **Deprecated artifacts.** Do not use the website installer, the `v0.1.0`
> GitHub release (which GitHub still marks Latest), the `0.1.0` packages on npm
> (`@chio-protocol/*`) and PyPI (`chio-sdk`), or the `chio-*` 0.1.x crates on
> crates.io. They were built in April 2026 or from the public mirror, far behind
> `main`, and do not match the current protocol, receipt format or CLI. They
> are unsigned under the [VERIFY.md](VERIFY.md) policy and cannot satisfy it.
> Because `releases/latest` resolves to `v0.1.0`, never install from a
> `latest` URL.

## Release distribution contract

The binary, checksum, container and Homebrew pages describe the contract a
preview must satisfy before those install paths are advertised. They are not
publication evidence.

- Signer policy and verification: [VERIFY.md](VERIFY.md)
- Planned binary and image shape: [BINARY_DISTRIBUTION.md](./BINARY_DISTRIBUTION.md)
- Planned Homebrew formula flow: [homebrew.md](./homebrew.md)
- Format stability rule: [../release/FORMAT_STABILITY.md](../release/FORMAT_STABILITY.md)
- Repo-local Docker demo stack: [../../examples/docker/README.md](../../examples/docker/README.md)
- Proof Room quickstart smoke: [../start-here/PROOF_ROOM_QUICKSTART.md](../start-here/PROOF_ROOM_QUICKSTART.md)

## Next Step

After install, choose the supported path that matches your use case:

1. Guided walkthrough: [../PROGRESSIVE_TUTORIAL.md](../start-here/PROGRESSIVE_TUTORIAL.md)
2. MCP migration and coding agents: [../guides/MIGRATING-FROM-MCP.md](../guides/MIGRATING-FROM-MCP.md)
3. Web backends: [../guides/WEB_BACKEND_QUICKSTART.md](../guides/WEB_BACKEND_QUICKSTART.md)
4. Native Chio servers: [../NATIVE_ADOPTION_GUIDE.md](../start-here/NATIVE_ADOPTION_GUIDE.md)
