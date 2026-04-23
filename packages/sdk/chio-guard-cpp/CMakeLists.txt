cmake_minimum_required(VERSION 3.16)

project(ChioGuardCpp VERSION 0.1.0 LANGUAGES CXX)

option(CHIO_GUARD_CPP_GENERATE "Generate C++ guest bindings with wit-bindgen" OFF)

add_library(chio_guard_cpp INTERFACE)
add_library(ChioGuardCpp::chio_guard_cpp ALIAS chio_guard_cpp)

target_compile_features(chio_guard_cpp INTERFACE cxx_std_17)
target_include_directories(chio_guard_cpp INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

set(CHIO_GUARD_CPP_WIT
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../wit/chio-guard/world.wit"
  CACHE FILEPATH
  "Path to the Chio guard world.wit file"
)

if(CHIO_GUARD_CPP_GENERATE)
  find_program(WIT_BINDGEN_EXECUTABLE wit-bindgen REQUIRED)
  set(CHIO_GUARD_CPP_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
  add_custom_command(
    OUTPUT "${CHIO_GUARD_CPP_GENERATED_DIR}/.generated"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${CHIO_GUARD_CPP_GENERATED_DIR}"
    COMMAND "${WIT_BINDGEN_EXECUTABLE}" cpp
      --world guard
      --out-dir "${CHIO_GUARD_CPP_GENERATED_DIR}"
      "${CHIO_GUARD_CPP_WIT}"
    COMMAND "${CMAKE_COMMAND}" -E touch "${CHIO_GUARD_CPP_GENERATED_DIR}/.generated"
    DEPENDS "${CHIO_GUARD_CPP_WIT}"
    VERBATIM
  )
  add_custom_target(chio_guard_cpp_generate DEPENDS "${CHIO_GUARD_CPP_GENERATED_DIR}/.generated")
endif()

install(TARGETS chio_guard_cpp EXPORT ChioGuardCppTargets)
install(DIRECTORY include/ DESTINATION include)
install(EXPORT ChioGuardCppTargets
  NAMESPACE ChioGuardCpp::
  DESTINATION lib/cmake/ChioGuardCpp
)
