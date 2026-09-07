# chio-reference-tools

Three MCP servers over standard input and output, built to run inside the
Chio cage as the wrapped servers of the reference runtime. Each one is
single-threaded, reads one JSON-RPC object per line, never touches the
environment or the network, and bounds every message, so the
`native_minimal_v1` syscall profile is enough for all three.

| Binary | Arguments | Tools | Grants the launch policy needs |
|--------|-----------|-------|--------------------------------|
| `chio-tool-repo-reader` | `--root <directory>` | `list_directory`, `read_file`, `stat` | read access to the root |
| `chio-tool-artifact-writer` | `--artifact <file>` | `write_artifact`, `read_artifact`, `artifact_status` | read and write access to the one pre-created file |
| `chio-tool-digest` | none | `sha256`, `canonical_json` | none |

The reader resolves every path inside its root and refuses `..`, absolute
paths and symlinks that leave the root; a session reads at most 64 distinct
files, 4 MiB in total and 256 KiB per call. The writer replaces the content
of a file that exists before it starts, never creating, renaming or removing
anything. The digest tool needs no grant at all and is the control for the
other two: if it cannot start, the host is the problem.

## Building for the cage

The cage admits a target executable either statically linked or with its
interpreter and shared objects declared as runtime files. Build the tools
static-PIE, the same way the cage helper is built, so the launch policy
carries no runtime files:

```bash
RUSTFLAGS="-C target-feature=+crt-static -C relocation-model=pie" \
  cargo build --release --target x86_64-unknown-linux-gnu -p chio-reference-tools
```

Name the target explicitly: with it, the flags apply to the tools alone and
the build's own procedural macros stay dynamically linked. The x86_64 GNU
toolchain produces static position-independent images; the aarch64 GNU
toolchain produces static fixed-address images, which the cage also admits
as targets.

`chio security provision-reference-runtime` checks the linkage of the target
it binds and refuses a dynamically linked target whose runtime files are not
declared.
