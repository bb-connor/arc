//! Records the package directory for a build outside a workspace checkout,
//! so the fixtures that ride along in the package can be found at runtime.
//! A build inside a checkout records nothing: the checkout is found from the
//! executable at runtime, which keeps release binaries free of build-machine
//! paths and identical across checkout locations.

use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") else {
        return;
    };
    let inside_checkout = Path::new(&manifest_dir)
        .ancestors()
        .nth(3)
        .is_some_and(|root| {
            root.join("crates/tooling/chio-conformance/Cargo.toml")
                .is_file()
        });
    if !inside_checkout {
        println!("cargo:rustc-env=CHIO_CONFORMANCE_PACKAGE_DIR={manifest_dir}");
    }
}
