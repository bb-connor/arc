# Release templates use the version tag for local package checks. Publishing
# replaces REPO, REF and SHA512 with the qualified repository, immutable
# commit and archive digest, and removes the moving HEAD_REF.
vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO backbay-labs/chio
    REF "cpp/v${VERSION}"
    SHA512 0
    HEAD_REF main
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}/sdks/cpp/chio-drogon"
    OPTIONS
        -DCHIO_DROGON_BUILD_TESTS=OFF
        -DCHIO_DROGON_REQUIRE_DEPS=ON
)

vcpkg_cmake_install()
vcpkg_cmake_config_fixup(PACKAGE_NAME ChioDrogon CONFIG_PATH lib/cmake/ChioDrogon)

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")

file(INSTALL "${SOURCE_PATH}/LICENSE"
    DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}"
    RENAME copyright
)
