# TRJ4-032 Evidence - ChioKernel.xcframework

## PR1 status

Not completed in PR1. This remains a documented slip.

## Validation attempted

- `bash scripts/build-ios-framework.sh --test-only` passed.
- `rustup target add x86_64-apple-ios` completed.
- A local UniFFI CLI shim was built under `/tmp/chio-uniffi-cli` because the repo expects a `uniffi-bindgen` binary but the `uniffi` and `uniffi_bindgen` crates do not publish installable binaries for 0.28.3.
- Full `scripts/build-ios-framework.sh` was attempted with `PATH=/tmp/chio-uniffi-bin:$PATH`.

## Blocker

The full iOS staticlib build failed during the aarch64 iOS target build in `openssl-sys`:

```text
Could not find directory of OpenSSL installation
AARCH64_APPLE_IOS_OPENSSL_DIR unset
OPENSSL_DIR unset
pkg-config has not been configured to support cross-compilation
```

## Remaining gap

`target/release-qualification/mobile-kernel/ios/ChioKernel.xcframework` and reproducible-build `.intoto.jsonl` were not produced. The next PR must either provision an iOS OpenSSL sysroot and target-specific OpenSSL env vars, or remove OpenSSL from the mobile staticlib dependency graph before producing the xcframework.
