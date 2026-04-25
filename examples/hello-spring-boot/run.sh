#!/usr/bin/env bash
set -euo pipefail

EXAMPLE_ROOT="$(cd "$(dirname "$0")" && pwd)"
SDK_ROOT="$(cd "${EXAMPLE_ROOT}/../../sdks/jvm" && pwd)"

exec "${SDK_ROOT}/gradlew" --no-daemon -p "${EXAMPLE_ROOT}" bootRun

