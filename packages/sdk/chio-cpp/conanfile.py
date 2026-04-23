from pathlib import Path

from conan import ConanFile
from conan.tools.files import copy
from conan.tools.cmake import CMake, CMakeDeps, CMakeToolchain, cmake_layout


class ChioCppConan(ConanFile):
    name = "chio-cpp"
    version = "0.1.0"
    package_type = "library"
    license = "Apache-2.0"
    author = "Back Bay Labs"
    url = "https://github.com/backbay-labs/chio"
    description = "C++17 SDK for Chio hosted MCP and security invariants"
    settings = "os", "compiler", "build_type", "arch"
    options = {"with_curl": [True, False]}
    default_options = {"with_curl": False}

    def export_sources(self):
        package_dir = Path(self.recipe_folder)
        repo_root = package_dir.parents[2]
        for pattern in [
            "CMakeLists.txt",
            "cmake/*",
            "include/*",
            "src/*",
            "tests/*",
            "examples/*",
        ]:
            copy(self, pattern, src=package_dir, dst=self.export_sources_folder)
        copy(
            self,
            "*",
            src=repo_root / "crates",
            dst=Path(self.export_sources_folder) / "crates",
        )
        copy(self, "Cargo.toml", src=repo_root, dst=self.export_sources_folder)
        copy(self, "Cargo.lock", src=repo_root, dst=self.export_sources_folder)

    def layout(self):
        cmake_layout(self)

    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        toolchain = CMakeToolchain(self)
        toolchain.variables["CHIO_CPP_BUILD_TESTS"] = False
        toolchain.variables["CHIO_CPP_BUILD_EXAMPLES"] = False
        toolchain.variables["CHIO_CPP_ENABLE_CURL"] = self.options.with_curl
        toolchain.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.set_property("cmake_file_name", "ChioCpp")
        self.cpp_info.set_property("cmake_target_name", "ChioCpp::chio_cpp")
        self.cpp_info.libs = ["chio_cpp", "chio_bindings_ffi"]
