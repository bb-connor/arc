# arc-kernel-mobile: operator bindings guide

This directory documents how to generate the Swift (iOS) and Kotlin
(Android) bindings for `arc-kernel-mobile` and link the static /
shared library into a mobile app. The crate itself ships pure Rust;
all language bindings are emitted at build time by the UniFFI
toolchain from `src/arc_kernel_mobile.udl`.

## Prerequisites

- Rust toolchain matching the workspace `rust-version` (1.93+).
- `uniffi-bindgen` binary. Not a default Cargo install because
  UniFFI publishes its binary under the namespaced crate
  `uniffi_bindgen`. On this repo install with:

  ```bash
  cargo install --git https://github.com/mozilla/uniffi-rs \
      --tag v0.28.3 --bin uniffi-bindgen uniffi_bindgen
  ```

  (Pinning to `v0.28.3` matches the `uniffi = "0.28"` dependency in
  `Cargo.toml`. If the workspace bumps the UniFFI version, bump the
  tag here in lockstep.)

  If your operator host has no Git access, build the binary from the
  workspace itself by adding a `[[bin]] name = "uniffi-bindgen"`
  target to `arc-kernel-mobile/Cargo.toml` (see
  `uniffi/docs/tutorial/foreign_language_bindings.md` upstream).

- iOS target: `rustup target add aarch64-apple-ios aarch64-apple-ios-sim
  x86_64-apple-ios`.
- Android target: `rustup target add aarch64-linux-android
  armv7-linux-androideabi i686-linux-android x86_64-linux-android`, plus
  the Android NDK (r25+) with a `cargo-ndk` wrapper or hand-rolled
  linker config pointing at the NDK-supplied clang.

## One-command qualification

Run the repo-local qualification lane from the workspace root:

```bash
./scripts/qualify-mobile-kernel.sh
```

It records four lane results under
`target/release-qualification/mobile-kernel/`:

- `host_ffi`: Rust-side JSON-in / JSON-out roundtrip tests
- `ios_device`: `aarch64-apple-ios` static library build
- `ios_sim`: `aarch64-apple-ios-sim` static library build when the target
  is installed
- `android_arm64`: `aarch64-linux-android` shared-library build when a
  real NDK toolchain is provisioned through `cargo-ndk`

Status values are explicit:

- `pass`: the lane ran on this host and succeeded
- `environment_dependent`: the host is missing the required SDK, target, or
  NDK tooling, so the script records that honestly instead of pretending the
  lane was qualified
- `fail`: the host had the required prerequisites and the lane still failed

## Generating the Swift bindings

```bash
# 1. Build the static library for every iOS architecture you ship for.
CARGO_TARGET_DIR=target/wave3k-mobile cargo build \
    --release --target aarch64-apple-ios -p arc-kernel-mobile
CARGO_TARGET_DIR=target/wave3k-mobile cargo build \
    --release --target aarch64-apple-ios-sim -p arc-kernel-mobile
CARGO_TARGET_DIR=target/wave3k-mobile cargo build \
    --release --target x86_64-apple-ios -p arc-kernel-mobile

# 2. Emit the Swift bindings.
mkdir -p out/swift
uniffi-bindgen generate \
    --language swift \
    --out-dir out/swift \
    crates/arc-kernel-mobile/src/arc_kernel_mobile.udl
```

`out/swift/arc_kernel_mobile.swift` is the module file to drop into
Xcode. `out/swift/arc_kernel_mobileFFI.h` is the matching C header;
package it together with a `.xcframework` that lipos the three
static libraries (`libarc_kernel_mobile.a`) from step 1.

### Linking in Xcode

1. Create an xcframework with `xcodebuild -create-xcframework`.
2. Add the framework to your app target's **Frameworks, Libraries,
   and Embedded Content** section.
3. Import the module in Swift: `import arc_kernel_mobile`.
4. Call the entry points directly -- `try evaluate(requestJson:)`,
   `try signReceipt(bodyJson:signingSeedHex:)`,
   `try verifyCapability(tokenJson:authorityPubHex:)`,
   `try verifyPassport(envelopeJson:issuerPubHex:nowSecs:)`.

## Generating the Kotlin bindings

```bash
# 1. Build the shared library for every Android ABI you ship for. Use
#    cargo-ndk (`cargo install cargo-ndk`) to hand the correct linker
#    to rustc automatically.
CARGO_TARGET_DIR=target/wave3k-mobile cargo ndk \
    --target aarch64-linux-android --target armv7-linux-androideabi \
    --target x86_64-linux-android --target i686-linux-android \
    -o android/jniLibs build --release -p arc-kernel-mobile

# 2. Emit the Kotlin bindings.
mkdir -p out/kotlin
uniffi-bindgen generate \
    --language kotlin \
    --out-dir out/kotlin \
    crates/arc-kernel-mobile/src/arc_kernel_mobile.udl
```

`out/kotlin/uniffi/arc_kernel_mobile/arc_kernel_mobile.kt` is the
module file to drop into the `src/main/java` tree of your Android
Gradle module. `android/jniLibs/<abi>/libarc_kernel_mobile.so` goes
into `src/main/jniLibs/<abi>/` alongside the module's resources.

### Linking in Gradle

1. Add `net.java.dev.jna:jna:5.14.0@aar` to the module dependencies
   (UniFFI-generated Kotlin uses JNA to load the shared library).
2. Confirm the JNI libs are packaged under `src/main/jniLibs`.
3. Import the module in Kotlin: `import uniffi.arc_kernel_mobile.*`.
4. Call the entry points directly -- `evaluate(requestJson)`,
   `signReceipt(bodyJson, signingSeedHex)`,
   `verifyCapability(tokenJson, authorityPubHex)`,
   `verifyPassport(envelopeJson, issuerPubHex, nowSecs)`.

## Offline receipt sync pattern

The Phase 14.3 acceptance criterion calls out an offline-first
workflow: an app caches a capability, evaluates tool calls locally
while disconnected, and syncs the resulting receipts to a backend
when connectivity returns. The FFI exposes the primitives for all
three halves:

1. **Cache** a capability token (JSON) to the device keystore
   (`KeychainService` on iOS, `EncryptedSharedPreferences` on Android).
2. **Gate** each tool call with `evaluate()` using the cached token
   and the device wall-clock (`MobileClock` is wired up automatically
   when `now_secs <= 0`).
3. **Sign** a receipt for each gated call with `signReceipt()` and
   append the returned JSON to a local queue (SQLite or the
   platform's durable key-value store).
4. **Sync** on reconnect: drain the queue and POST each receipt to
   the operator's `arc-siem` ingestion endpoint or Merkle-committed
   receipt log. The receipt's signature remains verifiable
   regardless of sync timing.

## Qualification artifacts

`./scripts/qualify-mobile-kernel.sh` emits:

- `target/release-qualification/mobile-kernel/report.md`
- `target/release-qualification/mobile-kernel/summary.json`
- one `*.log` file per lane

That output is the authoritative host-local record of which mobile lanes are
currently qualified versus environment-dependent.

## UniFFI bindgen invocation verification

`uniffi-bindgen` is NOT installed on every operator host. To run the
verification step during local development:

```bash
# After cargo install uniffi-bindgen (see Prerequisites):
uniffi-bindgen generate --language swift --out-dir out \
    crates/arc-kernel-mobile/src/arc_kernel_mobile.udl
uniffi-bindgen generate --language kotlin --out-dir out \
    crates/arc-kernel-mobile/src/arc_kernel_mobile.udl
```

The Swift / Kotlin files listed in this directory
(`bindings/swift/ArcKernel.md` and `bindings/kotlin/ArcKernel.md`)
are hand-authored API references that mirror the UDL interface
verbatim. They are the single source of truth for the Swift /
Kotlin surface; the generated files should match them shape-for-shape.
