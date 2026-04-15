---
phase: 399-sdk-authority-and-evidence-convergence
status: passed
completed: 2026-04-14
---

# Phase 399 Verification

- `npm test` in `sdks/typescript/packages/node-http`
- `npm test` in `sdks/typescript/packages/express`
- `go test ./...` in `sdks/go/arc-go-http`
- `uv run --extra dev pytest tests/test_models.py tests/test_client.py` in `sdks/python/arc-sdk-python`
- `uv run --extra dev pytest tests/test_middleware.py` in `sdks/python/arc-asgi`
- `uv run --extra dev pytest tests/test_middleware.py` in `sdks/python/arc-django`
- `uv run --extra dev pytest tests/test_dependencies.py` in `sdks/python/arc-fastapi`
- `./gradlew test --no-daemon` in `sdks/jvm/arc-spring-boot`
- `dotnet test ArcMiddleware.sln` in `sdks/dotnet/ArcMiddleware`
- `git diff --check -- sdks/go/arc-go-http sdks/python/arc-sdk-python sdks/python/arc-asgi sdks/python/arc-django sdks/python/arc-fastapi sdks/typescript/packages/node-http sdks/typescript/packages/express sdks/jvm/arc-spring-boot sdks/dotnet/ArcMiddleware docs/sdk/GO.md docs/sdk/PYTHON.md docs/sdk/PLATFORM.md`
