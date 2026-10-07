# Dynamic work delegation

Chio now has an experimental reusable path from a holder-authenticated work
allocation to a receiver-local native invocation. A work tree can be formed at
runtime, provider selection can change before sealing, and a sealed allocation
can be verified without contacting its issuer. Kernel capability authority,
durable custody, exact output checks and payment handling remain explicit.

- [Protocol and conditional argument](PROTOCOL.md)
- [Design](../../superpowers/specs/2026-10-02-dynamic-delegation-design.md)
- [Execution plan](../../superpowers/plans/2026-10-02-dynamic-delegation.md)
- Rust allocator: `crates/platform/chio-workflow/src/delegation/`
- Native adapter: `crates/kernel/chio-kernel/src/delegated_work.rs`
- Runnable example: `crates/kernel/chio-kernel/examples/dynamic_delegation.rs`

From the repository root on Linux:

    cargo test --locked -p chio-workflow
    cargo test --locked -p chio-kernel --features admission-test-support --test dynamic_delegation
    cargo run --locked -p chio-kernel --example dynamic_delegation

The example creates a root, delegates to a second holder, subdivides again,
selects one receiver, replaces it before sealing, executes through the selected
kernel, reopens durable state and replays the same receipt without another tool
call. An independent sibling also completes. The tests additionally take the
allocator offline before receiver execution, alter signed terms/identities,
race allocations and selection, and reject outputs before and after transforms.

This advances the implementation beyond fixed collaborations. It is not evidence
that conventional systems cannot implement the same protocol, that arbitrary
agent results are correct, or that independently operated markets improve cost
or quality. The manuscript distinguishes the new profile from historical funded
work, and retains open scientific/publication gates.
