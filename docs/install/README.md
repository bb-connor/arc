# Install Chio

Build the CLI from source. Install Rust with `rustup` and the Protocol Buffers
compiler (`protoc`) first; the checkout's `rust-toolchain.toml` selects Rust.

```bash
git clone https://github.com/backbay-labs/chio.git
cd chio
cargo build --locked --release -p chio-cli --bin chio
export PATH="$PWD/target/release:$PATH"
chio --help
```

For the process host, Python and Node workers, and shared-resource execution
work under review, use the [process preview guide](PROCESS_PREVIEW.md). It pins
the development repository and revision containing those features. The public
mirror's default branch did not contain the process starter when checked on
2026-09-08.

## Download availability

The website installer was checked on 2026-09-08. Its macOS ARM and Linux x86_64
downloads redirected to missing `backbay-labs/chio` release assets (HTTP 404).
That repository had no GitHub Releases. An older `v0.1.0` binary release exists
under `bb-connor/arc`, dated 2026-04-22; it is not evidence that the newer process
stack is distributed. Use source or the explicitly identified development
preview until current release downloads are available.

## Release Distribution Contract

The binary, checksum, container, and Homebrew docs describe the release contract
that must be satisfied before those install paths are advertised as available.
They are not current publication evidence.

- Planned binary and image shape: [BINARY_DISTRIBUTION.md](./BINARY_DISTRIBUTION.md)
- Planned Homebrew formula flow: [homebrew.md](./homebrew.md)
- Repo-local Docker demo stack: [../../examples/docker/README.md](../../examples/docker/README.md)
- Proof Room quickstart smoke: [../start-here/PROOF_ROOM_QUICKSTART.md](../start-here/PROOF_ROOM_QUICKSTART.md)

## Next Step

After install, choose the supported path that matches your use case:

1. Guided walkthrough: [../PROGRESSIVE_TUTORIAL.md](../start-here/PROGRESSIVE_TUTORIAL.md)
2. MCP migration and coding agents: [../guides/MIGRATING-FROM-MCP.md](../guides/MIGRATING-FROM-MCP.md)
3. Web backends: [../guides/WEB_BACKEND_QUICKSTART.md](../guides/WEB_BACKEND_QUICKSTART.md)
4. Native Chio servers: [../NATIVE_ADOPTION_GUIDE.md](../start-here/NATIVE_ADOPTION_GUIDE.md)
