#!/usr/bin/env bash
set -euo pipefail

EXAMPLE_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "${EXAMPLE_ROOT}"

exec dotnet run --project HelloArc.csproj --urls "http://127.0.0.1:${HELLO_DOTNET_PORT:-8019}"

