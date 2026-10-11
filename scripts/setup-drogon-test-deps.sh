#!/usr/bin/env bash
set -euo pipefail

# Build the Conan recipe's Drogon version in an isolated prefix. Nothing is
# installed system-wide. stdout is only the prefix for CMAKE_PREFIX_PATH; build
# diagnostics go to stderr. The caller retains this temporary acceptance input.
# Linux hosts must provide OpenSSL, zlib and UUID development headers/libraries
# (libssl-dev, zlib1g-dev and uuid-dev on the Ubuntu qualification runners).
for tool in git cmake; do
  command -v "${tool}" >/dev/null
done
drogon_stage="$(mktemp -d "${TMPDIR:-/tmp}/chio-drogon-deps.XXXXXX")"
drogon_prefix="${drogon_stage}/prefix"

fetch_pinned() {
  local repository="$1" revision="$2" destination="$3"
  git init --quiet "${destination}" >&2
  git -C "${destination}" remote add origin "${repository}"
  git -C "${destination}" fetch --depth 1 origin "${revision}" >&2
  git -C "${destination}" -c advice.detachedHead=false checkout --detach FETCH_HEAD >&2
  test "$(git -C "${destination}" rev-parse HEAD)" = "${revision}"
}

# Drogon v1.9.12 and jsoncpp 1.9.6. Trantor is pinned by Drogon's gitlink.
fetch_pinned https://github.com/drogonframework/drogon.git \
  89aca8c7993c8194f2c109c1d06a3b45bf363d5d "${drogon_stage}/drogon"
git -C "${drogon_stage}/drogon" submodule update --init --depth 1 >&2
fetch_pinned https://github.com/open-source-parsers/jsoncpp.git \
  89e2973c754a9c02a49974d839779b151e95afd6 "${drogon_stage}/jsoncpp"

cmake -S "${drogon_stage}/jsoncpp" -B "${drogon_stage}/jsoncpp-build" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="${drogon_prefix}" \
  -DJSONCPP_WITH_TESTS=OFF -DJSONCPP_WITH_POST_BUILD_UNITTEST=OFF \
  -DBUILD_SHARED_LIBS=OFF >&2
cmake --build "${drogon_stage}/jsoncpp-build" --parallel 2 >&2
cmake --install "${drogon_stage}/jsoncpp-build" >&2
cmake -S "${drogon_stage}/drogon" -B "${drogon_stage}/drogon-build" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="${drogon_prefix}" \
  -DCMAKE_PREFIX_PATH="${drogon_prefix}" -DBUILD_TESTING=OFF \
  -DBUILD_EXAMPLES=OFF -DBUILD_CTL=OFF -DBUILD_ORM=OFF \
  -DBUILD_BROTLI=OFF -DBUILD_YAML_CONFIG=OFF >&2
cmake --build "${drogon_stage}/drogon-build" --parallel 2 >&2
cmake --install "${drogon_stage}/drogon-build" >&2
printf '%s\n' "${drogon_prefix}"
