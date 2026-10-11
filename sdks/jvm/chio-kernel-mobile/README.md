# Chio Android Kernel Mobile

This module packages `chio-kernel-mobile` as an Android AAR. It is
distributed through GitHub Packages Maven by default.

## Platform

- `minSdk = 26`
- `targetSdk = 34`
- StrongBox is requested on API 28+ and falls back to TEE-backed
  Android Keystore with a degraded `software` trust marker.

## Build

From the repository root:

```bash
bash scripts/build-android-aar.sh
```

The script builds locked Rust shared libraries through `cargo ndk`, generates
Kotlin bindings with the workspace's locked UniFFI generator, and runs Gradle `assembleRelease`. The AAR
lands under `sdks/jvm/chio-kernel-mobile/build/outputs/aar/`.

The crate's `uniffi.toml` selects the actual `chio_kernel_mobile` library name
and maps error payload fields to `detail` in Kotlin. `Throwable.message` remains
available; the Rust error representation and FFI stay the same.

`bash scripts/check-kotlin-mobile.sh` compiles the real `ChioKernel` wrapper and
calls the native host library through generated Kotlin. It requires Rust and
Java 21. This host ABI check does not replace Android AAR, emulator or device
qualification, Play Integrity acceptance or hardware custody tests.
