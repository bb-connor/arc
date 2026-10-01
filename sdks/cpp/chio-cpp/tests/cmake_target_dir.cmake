# Configure-only regressions. Never build Rust or create a Cargo target tree.
cmake_minimum_required(VERSION 3.16)
foreach(required CHIO_CPP_SOURCE_DIR CHIO_CPP_REPO_ROOT CHIO_CPP_TEST_BINARY_DIR)
  if(NOT DEFINED ${required})
    message(FATAL_ERROR "Missing ${required}")
  endif()
endforeach()
get_filename_component(CHIO_CPP_REPO_ROOT "${CHIO_CPP_REPO_ROOT}" ABSOLUTE)
file(MAKE_DIRECTORY "${CHIO_CPP_TEST_BINARY_DIR}")

function(check_target_dir case_name expected environment)
  # The working directory is deliberately not the repository root. Untyped
  # command-line PATH entries must not be resolved against this directory.
  set(build_dir "${CHIO_CPP_TEST_BINARY_DIR}/${case_name}")
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env --unset=CARGO_TARGET_DIR ${environment}
      "${CMAKE_COMMAND}" -S "${CHIO_CPP_SOURCE_DIR}" -B "${build_dir}"
      -UCHIO_CPP_CARGO_TARGET_DIR
      "-DCHIO_CPP_REPO_ROOT=${CHIO_CPP_REPO_ROOT}"
      -DCHIO_CPP_BUILD_RUST_FFI=OFF -DCHIO_CPP_BUILD_TESTS=OFF
      -DCHIO_CPP_BUILD_EXAMPLES=OFF ${ARGN}
    WORKING_DIRECTORY "${CHIO_CPP_TEST_BINARY_DIR}"
    RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error
  )
  if(NOT result EQUAL 0)
    message(FATAL_ERROR "${case_name}: configure failed: ${output}\n${error}")
  endif()
  file(STRINGS "${build_dir}/CMakeCache.txt" actual
    REGEX "^CHIO_CPP_CARGO_TARGET_DIR:PATH=")
  if(NOT actual STREQUAL "CHIO_CPP_CARGO_TARGET_DIR:PATH=${expected}")
    message(FATAL_ERROR "${case_name}: expected ${expected}, got ${actual}")
  endif()
endfunction()

check_target_dir(default "${CHIO_CPP_REPO_ROOT}/target" "")
check_target_dir(untyped "${CHIO_CPP_REPO_ROOT}/relative-target" ""
  -DCHIO_CPP_CARGO_TARGET_DIR=relative-target)
check_target_dir(typed "${CHIO_CPP_REPO_ROOT}/relative-target" ""
  -DCHIO_CPP_CARGO_TARGET_DIR:PATH=relative-target)
check_target_dir(environment "${CHIO_CPP_REPO_ROOT}/environment-target"
  "CARGO_TARGET_DIR=environment-target")
check_target_dir(override "${CHIO_CPP_REPO_ROOT}/explicit-target"
  "CARGO_TARGET_DIR=environment-target" -DCHIO_CPP_CARGO_TARGET_DIR=explicit-target)
check_target_dir(absolute "${CHIO_CPP_TEST_BINARY_DIR}/absolute target" ""
  "-DCHIO_CPP_CARGO_TARGET_DIR=${CHIO_CPP_TEST_BINARY_DIR}/absolute target")
