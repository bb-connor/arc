cmake_minimum_required(VERSION 3.16)

project(ChioCpp VERSION 0.1.0 LANGUAGES CXX)

option(CHIO_CPP_BUILD_TESTS "Build chio-cpp tests" ON)
option(CHIO_CPP_BUILD_EXAMPLES "Build chio-cpp examples" ON)
option(CHIO_CPP_BUILD_RUST_FFI "Build the Rust chio-bindings-ffi library from CMake" ON)
option(CHIO_CPP_ENABLE_CURL "Build the optional libcurl transport" OFF)
option(CHIO_CPP_BUILD_CONFORMANCE_PEER "Build the optional C++ conformance peer" OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CHIO_CPP_REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../.." CACHE PATH
  "Path to the Chio repository root containing Cargo.toml"
)
if(NOT EXISTS "${CHIO_CPP_REPO_ROOT}/Cargo.toml")
  set(CHIO_CPP_REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}" CACHE PATH
    "Path to the Chio repository root containing Cargo.toml"
    FORCE
  )
endif()
set(CHIO_CPP_FFI_INCLUDE_DIR "${CHIO_CPP_REPO_ROOT}/crates/chio-bindings-ffi/include")

if(CMAKE_BUILD_TYPE STREQUAL "Release")
  set(CHIO_CPP_RUST_PROFILE_ARG "--release")
  set(CHIO_CPP_RUST_PROFILE_DIR "release")
else()
  set(CHIO_CPP_RUST_PROFILE_ARG "")
  set(CHIO_CPP_RUST_PROFILE_DIR "debug")
endif()

set(CHIO_CPP_RUST_LIB
  "${CHIO_CPP_REPO_ROOT}/target/${CHIO_CPP_RUST_PROFILE_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}chio_bindings_ffi${CMAKE_STATIC_LIBRARY_SUFFIX}"
)

if(CHIO_CPP_BUILD_RUST_FFI)
  add_custom_target(chio_bindings_ffi_build
    COMMAND cargo build -p chio-bindings-ffi ${CHIO_CPP_RUST_PROFILE_ARG}
    BYPRODUCTS "${CHIO_CPP_RUST_LIB}"
    WORKING_DIRECTORY "${CHIO_CPP_REPO_ROOT}"
    COMMENT "Building Rust chio-bindings-ffi"
    VERBATIM
  )
endif()

add_library(chio_bindings_ffi STATIC IMPORTED GLOBAL)
set_target_properties(chio_bindings_ffi PROPERTIES
  IMPORTED_LOCATION "${CHIO_CPP_RUST_LIB}"
)
if(CHIO_CPP_BUILD_RUST_FFI)
  add_dependencies(chio_bindings_ffi chio_bindings_ffi_build)
endif()

add_library(chio_cpp
  src/auth.cpp
  src/client.cpp
  src/dpop.cpp
  src/features.cpp
  src/http_substrate.cpp
  src/invariants.cpp
  src/receipt_query.cpp
  src/session.cpp
)

add_library(ChioCpp::chio_cpp ALIAS chio_cpp)

target_include_directories(chio_cpp
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
  PRIVATE
    "${CHIO_CPP_FFI_INCLUDE_DIR}"
)
target_link_libraries(chio_cpp PUBLIC chio_bindings_ffi)

if(APPLE)
  target_link_libraries(chio_cpp PUBLIC "-framework Security" "-framework CoreFoundation")
elseif(UNIX)
  target_link_libraries(chio_cpp PUBLIC dl pthread m)
endif()

if(CHIO_CPP_ENABLE_CURL)
  find_package(CURL REQUIRED)
  target_sources(chio_cpp PRIVATE src/curl_transport.cpp)
  target_link_libraries(chio_cpp PUBLIC CURL::libcurl)
  target_compile_definitions(chio_cpp PUBLIC CHIO_CPP_HAS_CURL=1)
endif()

if(CHIO_CPP_BUILD_TESTS)
  enable_testing()
  add_executable(chio_cpp_tests tests/sdk_tests.cpp)
  target_link_libraries(chio_cpp_tests PRIVATE chio_cpp)
  target_compile_definitions(chio_cpp_tests PRIVATE CHIO_CPP_REPO_ROOT="${CHIO_CPP_REPO_ROOT}")
  add_test(NAME chio_cpp_tests COMMAND chio_cpp_tests)
endif()

if(CHIO_CPP_BUILD_EXAMPLES)
  add_executable(chio_cpp_governed_hello examples/governed_hello.cpp)
  target_link_libraries(chio_cpp_governed_hello PRIVATE chio_cpp)
endif()

if(CHIO_CPP_BUILD_CONFORMANCE_PEER)
  if(NOT CHIO_CPP_ENABLE_CURL)
    message(FATAL_ERROR "CHIO_CPP_BUILD_CONFORMANCE_PEER requires CHIO_CPP_ENABLE_CURL=ON")
  endif()
  add_executable(chio_cpp_conformance_peer
    ../../../tests/conformance/peers/cpp/client.cpp
  )
  target_link_libraries(chio_cpp_conformance_peer PRIVATE chio_cpp)
endif()

include(CMakePackageConfigHelpers)

install(TARGETS chio_cpp
  EXPORT ChioCppTargets
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib
  RUNTIME DESTINATION bin
  INCLUDES DESTINATION include
)
install(FILES "${CHIO_CPP_RUST_LIB}" DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)
install(DIRECTORY "${CHIO_CPP_FFI_INCLUDE_DIR}/" DESTINATION include)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/ChioCppConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)
configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/ChioCppConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/ChioCppConfig.cmake"
  INSTALL_DESTINATION lib/cmake/ChioCpp
)
install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/ChioCppConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/ChioCppConfigVersion.cmake"
  DESTINATION lib/cmake/ChioCpp
)
install(EXPORT ChioCppTargets
  NAMESPACE ChioCpp::
  DESTINATION lib/cmake/ChioCpp
)
