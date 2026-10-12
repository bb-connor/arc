# chio-reference-tools architecture

## Responsibility and boundary

The library owns line-delimited MCP tool framing. Implementers supply a
`ToolServer` with identity, descriptors, and call dispatch.
`ToolDescriptor` describes listing metadata, `ToolOutput` carries text and
optional structured content, and `ToolError` distinguishes invalid arguments,
refused operations, and failed operations.

Three binaries implement this trait for repository reading, one-file writing,
and digest calculation. The cage controls operating-system access and the
kernel controls authorization and receipt production. Local tool checks add
input limits and configured-path restrictions within that runtime boundary.

## Structure

`src/lib.rs` defines `serve`, `handle`, response helpers, argument readers,
SHA-256 encoding, and exact single-flag parsing.
`src/line_boundary_tests.rs` checks request-frame size transitions.
`src/bin/chio-tool-repo-reader.rs` stores a canonical root and read budgets.
`src/bin/chio-tool-artifact-writer.rs` stores a configured artifact path.
`src/bin/chio-tool-digest.rs` implements hashing and canonical JSON.
`tests/tools.rs` starts all three binaries and drives their stdio interface.
The process-report fixture and enforcement-probe examples support host tests.

## Data and control flow

`serve` reads one bounded line, ignores whitespace-only lines, decodes JSON,
passes it to `handle`, and flushes each response.
Malformed or oversized frames produce parse errors with a null ID.
Oversized reads drain the remainder of that frame before accepting another.

`handle` requires an object and dispatches only requests with an ID.
It answers initialize with revision `2025-11-25`, handles ping and tools/list,
and delegates tools/call after checking name and object arguments.
Unknown methods and argument failures use JSON-RPC errors.
Refused and failed tool operations return a result with `isError: true`.
There is no initialization state machine or general input-schema validator.

The reader canonicalizes paths, checks root containment, and opens regular
files with a bounded read plus one lookahead byte. It truncates excess bytes,
requires UTF-8, then charges returned bytes and records the resolved file.
Listings are sorted and reject more than 512 directory entries.

The writer checks exact path spelling for each call. It opens the existing
artifact with truncation, writes content, and calls `sync_all`.
Reads and stats read at most 1 MiB plus one byte before deciding whether
to refuse oversized content. The digest server hashes UTF-8 input or RFC 8785
canonical output and returns structured content alongside text.

## Trust and invariants

The transport ceiling is 4 MiB including a newline when one is present.
`read_line` bounds allocations while draining oversized frames.
`handle` can be called directly without the stream byte limit.
It does not validate the `jsonrpc` member or enforce descriptor schemas;
each tool validates the arguments its implementation consumes.

Reader paths reject absolute and parent components. Canonical containment
permits symlinks resolving inside the root and refuses outside destinations.
Canonicalization and open are separate calls, so tool checks alone do not
eliminate races with filesystem mutation. UTF-8 failure leaves read budgets
uncharged. Byte budgets count returned text rather than the lookahead byte.

Writer startup rejects a symlink at the artifact leaf through
`symlink_metadata`; ancestor resolution and later opens remain ordinary
filesystem operations. A failed write can leave truncated or partial content;
there is no atomic replacement transaction.
The launch policy must confine filesystem access independently.

Digest canonicalization delegates to `chio-core-types`; it checks output
size after canonicalization. The shared transport decodes ordinary JSON
and performs no signature verification or duplicate-member validation.

## Dependencies

`serde_json` decodes requests and constructs result objects.
`sha2` and `hex` implement lowercase SHA-256 strings.
`chio-core-types` supplies RFC 8785 canonical JSON for the digest binary.
`tempfile` supplies integration-test directories through a dev dependency.
The package declares no Cargo features or network client dependency.

## Verification

Library tests cover handshake/listing, calls, notifications, refusals,
malformed frames, oversized-frame recovery, and exact argument parsing.
Frame-boundary tests use fragmented buffers, exact limits, and oversized EOF.
Binary integration tests exercise reader traversal and symlink refusal,
read budgets, pre-created artifact updates, refusal preservation, and digests.
These tests launch tools directly without the cage.

Run `cargo test -p chio-reference-tools --lib` for framing tests and
`cargo test -p chio-reference-tools --test tools` for binary interactions.
Cage launch, linkage checks, syscall profiles, and deployment acceptance
belong to process/runtime qualification with the actual launch policy.
