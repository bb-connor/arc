# Chio C++ Release Checklist

Run the C++ SDK release gate from the repository root:

```bash
./scripts/check-chio-cpp-release.sh
```

The gate covers:

- Rust FFI unit tests for `crates/chio-bindings-ffi`.
- C ABI smoke compilation against `include/chio/chio_ffi.h`.
- CMake configure, build, CTest, and example compilation.
- CMake install plus `find_package(ChioCpp CONFIG REQUIRED)` consumer smoke.
- Conan recipe smoke when `conan` is available.
- vcpkg manifest smoke when `vcpkg` is available.

Release notes should state that the stable package boundary is native C++17
over a C ABI invariant layer. Do not expose Rust structs, CXX bridge types,
session handles, callback handles, or async runtime state as public SDK API.
