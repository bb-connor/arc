# Chio C++ SDK Family Release Checklist

The Chio C++ surface ships as four sibling packages under `packages/sdk/`:

| SDK              | CMake target                       | Conan ref            | vcpkg name        |
|------------------|------------------------------------|----------------------|-------------------|
| `chio-cpp`       | `ChioCpp::chio_cpp`                | `chio-cpp/0.1.0`     | `chio-cpp`        |
| `chio-cpp-kernel`| `ChioCppKernel::chio_cpp_kernel`   | `chio-cpp-kernel/0.1.0` | `chio-cpp-kernel` |
| `chio-guard-cpp` | `ChioGuardCpp::chio_guard_cpp`     | `chio-guard-cpp/0.1.0`  | `chio-guard-cpp`  |
| `chio-drogon`    | `ChioDrogon::chio_drogon`          | `chio-drogon/0.1.0`  | `chio-drogon`     |

Each SDK is independently versionable but shares the C ABI invariant boundary
defined by `crates/chio-bindings-ffi` (used by `chio-cpp`) and
`crates/chio-cpp-kernel-ffi` (used by `chio-cpp-kernel`). The stable package
boundary for every SDK is native C++17 over a C ABI invariant layer; do not
expose Rust structs, CXX bridge types, session handles, callback handles, or
async runtime state as public API.

## Per-SDK release gates

Run the gate for an SDK from the repository root:

```bash
./scripts/check-chio-cpp-release.sh
./scripts/check-chio-cpp-kernel-release.sh
./scripts/check-chio-guard-cpp-release.sh
./scripts/check-chio-drogon-release.sh
```

All four are thin wrappers around `scripts/check-sdk-release.sh`. Each gate
covers, in order:

- Per-SDK CMake configure, build, CTest, and install smoke against the
  generated `find_package(... CONFIG REQUIRED)` config.
- Conan recipe smoke (`conan create .`) when `conan` is available. Set
  `CHIO_CPP_REQUIRE_PACKAGERS=1` (auto-set on CI) to fail closed if `conan` is
  missing.
- vcpkg manifest smoke (`vcpkg install --x-manifest-root=... --dry-run`) when
  `vcpkg` is on PATH or `VCPKG_ROOT` points at a `vcpkg` binary. Without
  vcpkg, the manifest is parsed and the `name` field is verified.

## Dependency ordering

`chio-drogon` depends on `chio-cpp` at the package-manager level. The Conan
gate for `chio-drogon` first runs `conan create` on `chio-cpp` to seed the
local Conan cache before creating the `chio-drogon` package. The vcpkg dry-run
relies on the eventual private overlay registry resolving `chio-cpp` to the
sibling port; it is a no-op until that registry is wired up.

`chio-cpp-kernel` does not depend on `chio-cpp`. The published Conan port
ships the `chio-cpp-kernel-ffi` Rust crate sources alongside the C++ tree and
builds them with `cargo build -p chio-cpp-kernel-ffi` during package build.
The vcpkg port is FFI-off; FFI builds remain a from-source CMake configure
that sets `CHIO_CPP_KERNEL_ENABLE_FFI=ON` with explicit
`CHIO_CPP_KERNEL_FFI_*` paths.

`chio-guard-cpp` is header-only, has no compiled artifact, and has no third
party runtime dependencies. The published port omits the optional
`wit-bindgen` and WASI component build paths; those remain available via the
from-source CMake options.

## Private registry placeholder

Until the private vcpkg overlay registry and Conan remote are stood up, the
`conan create` step seeds packages into the local Conan cache only and the
vcpkg dry-run uses the manifest format check for SDKs whose dependencies are
not in vcpkg upstream (`chio-cpp` for `chio-drogon`). When the registry lands,
update the gate to publish each artifact.
