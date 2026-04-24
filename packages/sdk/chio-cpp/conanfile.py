from pathlib import Path

from conan import ConanFile
from conan.tools.files import chdir, copy, save
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

    _rust_workspace_members = [
        "chio-appraisal",
        "chio-autonomy",
        "chio-binding-helpers",
        "chio-bindings-ffi",
        "chio-core",
        "chio-core-types",
        "chio-credit",
        "chio-federation",
        "chio-governance",
        "chio-listing",
        "chio-manifest",
        "chio-market",
        "chio-open-market",
        "chio-underwriting",
        "chio-web3",
    ]

    _trimmed_cargo_toml = """[workspace]
resolver = "2"
members = [
    "crates/chio-appraisal",
    "crates/chio-autonomy",
    "crates/chio-binding-helpers",
    "crates/chio-bindings-ffi",
    "crates/chio-core",
    "crates/chio-core-types",
    "crates/chio-credit",
    "crates/chio-federation",
    "crates/chio-governance",
    "crates/chio-listing",
    "crates/chio-manifest",
    "crates/chio-market",
    "crates/chio-open-market",
    "crates/chio-underwriting",
    "crates/chio-web3",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
rust-version = "1.93"
license = "Apache-2.0"
repository = "https://github.com/backbay/chio"

[workspace.lints.clippy]
unwrap_used = "deny"
expect_used = "deny"

[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yml = "0.0.12"
tokio = { version = "1", features = ["full"] }
thiserror = "1"
chrono = "0.4"
ed25519-dalek = { version = "2", features = ["rand_core"] }
rand_core = { version = "0.6", features = ["getrandom"] }
tracing = "0.1"
hex = "0.4"
base64 = "0.22"
bs58 = "0.5"
ryu = "1"
sha2 = "0.10"
reqwest = { version = "0.13.2", default-features = false }
rusqlite = { version = "0.39", features = ["bundled"] }
uuid = "1"
url = "2"
proptest = "1.10"
criterion = "0.5"
tempfile = "3"
"""

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
        for crate in self._rust_workspace_members:
            copy(
                self,
                "*",
                src=repo_root / "crates" / crate,
                dst=Path(self.export_sources_folder) / "crates" / crate,
            )
        save(
            self,
            Path(self.export_sources_folder) / "Cargo.toml",
            self._trimmed_cargo_toml,
        )
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
        build_type = str(self.settings.build_type or "")
        if build_type and build_type != "Debug":
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
        elif str(self.settings.os) == "Windows":
            self.cpp_info.system_libs = ["ws2_32", "bcrypt", "userenv", "advapi32", "ntdll"]
        if self.options.with_curl:
            self.cpp_info.requires = ["libcurl::libcurl"]
