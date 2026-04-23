# Chio Guard C++ SDK

`chio-guard-cpp` is the separate C++17 guard authoring package for Chio WASM
guard components. It tracks `wit/chio-guard/world.wit` and stays independent
from `packages/sdk/chio-cpp` so client applications do not need WASI SDK or
component-model tools.

## Native Authoring Types

The header-only `chio::guard` namespace provides lightweight C++ structs for
the guard request and verdict model:

```cpp
#include "chio/guard.hpp"

class PathGuard final : public chio::guard::Guard {
 public:
  chio::guard::Verdict evaluate(const chio::guard::GuardRequest& request) override {
    if (request.extracted_path && request.extracted_path->find("..") != std::string::npos) {
      return chio::guard::Verdict::deny("path traversal denied");
    }
    return chio::guard::Verdict::allow();
  }
};
```

## WIT Bindings

Generate guest bindings when `wit-bindgen` is available:

```bash
./packages/sdk/chio-guard-cpp/scripts/generate-types.sh
```

Build scripts expect the WASI SDK for component builds:

```bash
WASI_SDK_PATH=/opt/wasi-sdk ./packages/sdk/chio-guard-cpp/scripts/build-guard.sh
```

This package intentionally avoids linking to the main C++ client SDK. Guard
components implement the WIT world; ordinary clients use `chio-cpp`.
