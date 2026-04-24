from pathlib import Path

from conan import ConanFile
from conan.tools.files import chdir, copy
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
    options = {"shared": [True, False], "with_curl": [True, False]}
    default_options = {"shared": False, "with_curl": False}

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
        for workspace_dir in ["examples", "formal", "tests"]:
            copy(
                self,
                "*",
                src=repo_root / workspace_dir,
                dst=Path(self.export_sources_folder) / workspace_dir,
            )
        copy(self, "Cargo.toml", src=repo_root, dst=self.export_sources_folder)
        copy(self, "Cargo.lock", src=repo_root, dst=self.export_sources_folder)

    def layout(self):
        cmake_layout(self)

    def requirements(self):
        if self.options.with_curl:
            self.requires("libcurl/8.15.0")

    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        toolchain = CMakeToolchain(self)
        toolchain.variables["CHIO_CPP_BUILD_TESTS"] = False
        toolchain.variables["CHIO_CPP_BUILD_EXAMPLES"] = False
        toolchain.variables["CHIO_CPP_BUILD_RUST_FFI"] = False
        toolchain.variables["CHIO_CPP_ENABLE_CURL"] = self.options.with_curl
        toolchain.variables["BUILD_SHARED_LIBS"] = self.options.shared
        toolchain.generate()

    def build(self):
        cargo = "cargo build -p chio-bindings-ffi"
        if str(self.settings.build_type) == "Release":
            cargo += " --release"
        with chdir(self, self.source_folder):
            self.run(cargo)
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
        if str(self.settings.os) == "Macos":
            self.cpp_info.frameworks = ["Security", "CoreFoundation"]
        elif str(self.settings.os) in ["Linux", "FreeBSD"]:
            self.cpp_info.system_libs = ["dl", "pthread", "m"]
        if self.options.with_curl:
            self.cpp_info.requires = ["libcurl::libcurl"]
