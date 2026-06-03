# chio-web3-bindings Architecture

`chio-web3-bindings` owns the Rust Alloy binding surface and packaged JSON artifacts for the official Chio web3 contract family.

The crate is intentionally narrow: `src/interfaces.rs` invokes `alloy::sol!` against compiled interface artifacts and defines the hand-written `ChioMerkleProof` adapter, while `src/lib.rs` re-exports generated contract modules and embeds the implementation, interface, deployment, and local qualification JSON artifacts.

The trust boundary is package integrity. Callers depend on the included artifacts to match the Solidity package under `contracts/`, the standard web3 contract package, and the generated Alloy signatures. Drift must be caught at build or test time before settlement code can prepare calls against stale ABIs or empty implementation bytecode.

Current hardening: implementation artifacts are validated separately from interface artifacts, so packaged contracts must carry non-empty implementation bytecode while interface artifacts must not carry implementation bytecode.
