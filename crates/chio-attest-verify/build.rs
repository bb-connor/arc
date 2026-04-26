// owned-by: M09
//
// Build-time check that the embedded Sigstore TUF root materials exist on
// disk under `sigstore-root/`. We do NOT fetch over the network at build
// time: the canonical reproducibility story is to ship the trust root in
// tree and refresh it via the quarterly CODEOWNERS-reviewed re-bake job
// described in `.planning/trajectory/09-supply-chain-attestation.md`.
//
// The runtime constructor `SigstoreVerifier::with_embedded_root` consumes
// these files via `include_bytes!`. If either file is missing at compile
// time the build fails before any runtime path can dereference the
// embedded blobs.

use std::path::Path;

fn main() {
    let root_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("sigstore-root");
    let trusted_root = root_dir.join("trusted_root.json");
    let tuf_root = root_dir.join("root.json");

    for required in [&trusted_root, &tuf_root] {
        if !required.exists() {
            panic!(
                "chio-attest-verify build aborted: missing embedded Sigstore \
                 trust-root file `{}`. Run the quarterly re-bake job or copy \
                 the canonical files from sigstore-rs `trust_root/prod/`.",
                required.display()
            );
        }
        println!("cargo:rerun-if-changed={}", required.display());
    }

    println!("cargo:rerun-if-changed=build.rs");
}
