// Build-time check that the embedded Sigstore TUF root materials exist on
// disk under `sigstore-root/`. The trust root is shipped in-tree and refreshed
// via a quarterly CODEOWNERS-reviewed re-bake job; no network access at build time.

use std::path::PathBuf;

fn main() {
    // A cached build-script binary may have been compiled in another checkout.
    // Cargo supplies the current crate directory when it executes this script.
    let Some(manifest_dir) = std::env::var_os("CARGO_MANIFEST_DIR") else {
        panic!("chio-attest-verify build aborted: CARGO_MANIFEST_DIR is unavailable");
    };
    let root_dir = PathBuf::from(manifest_dir).join("sigstore-root");
    let trusted_root = root_dir.join("trusted_root.json");
    let tuf_root = root_dir.join("root.json");

    for required in [&trusted_root, &tuf_root] {
        if !required.exists() {
            panic!(
                "chio-attest-verify build aborted: missing embedded Sigstore \
                 trust-root file `{}`. Run the quarterly re-bake job or copy \
                 refreshed materials with `scripts/tuf-rebake.sh --write`.",
                required.display()
            );
        }
        println!("cargo:rerun-if-changed={}", required.display());
    }

    println!("cargo:rerun-if-changed=build.rs");
}
