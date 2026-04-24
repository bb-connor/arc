import re
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

    _rust_workspace_roots = ["chio-bindings-ffi"]

    @staticmethod
    def _extract_manifest_section(manifest, header):
        start_marker = f"{header}\n"
        start = manifest.find(start_marker)
        if start == -1:
            raise ValueError(f"missing {header} in workspace Cargo.toml")
        section_name = header.strip("[]")
        lines = manifest[start:].splitlines()
        out = []
        for index, line in enumerate(lines):
            stripped = line.strip()
            if index > 0 and stripped.startswith("[") and stripped.endswith("]"):
                current = stripped.strip("[]")
                if current != section_name and not current.startswith(f"{section_name}."):
                    break
            out.append(line)
        return "\n".join(out).strip()

    @staticmethod
    def _path_dependency_crates(crate_manifest, repo_root):
        text = crate_manifest.read_text()
        crates_dir = (repo_root / "crates").resolve()
        crate_names = []
        for dependency_path in re.findall(r'path\s*=\s*"(\.\./[^"]+)"', text):
            dependency_dir = (crate_manifest.parent / dependency_path).resolve()
            if dependency_dir.parent == crates_dir:
                crate_names.append(dependency_dir.name)
        return crate_names

    def _rust_workspace_members(self, repo_root):
        members = set()
        pending = list(self._rust_workspace_roots)
        while pending:
            crate = pending.pop()
            if crate in members:
                continue
            crate_manifest = repo_root / "crates" / crate / "Cargo.toml"
            if not crate_manifest.exists():
                raise ValueError(f"missing Cargo.toml for Rust crate {crate}")
            members.add(crate)
            pending.extend(
                dependency
                for dependency in self._path_dependency_crates(crate_manifest, repo_root)
                if dependency not in members
            )
        return sorted(members)

    def _trimmed_workspace_manifest(self, repo_root):
        root_manifest = (repo_root / "Cargo.toml").read_text()
        workspace_members = self._rust_workspace_members(repo_root)
        members = "\n".join(
            f'    "crates/{crate}",' for crate in workspace_members
        )
        copied_sections = "\n\n".join(
            self._extract_manifest_section(root_manifest, header)
            for header in [
                "[workspace.package]",
                "[workspace.lints.clippy]",
                "[workspace.dependencies]",
            ]
        )
        return (
            "[workspace]\n"
            'resolver = "2"\n'
            "members = [\n"
            f"{members}\n"
            "]\n\n"
            f"{copied_sections}\n"
        )

    def export_sources(self):
        package_dir = Path(self.recipe_folder)
        repo_root = package_dir.parents[2]
        workspace_members = self._rust_workspace_members(repo_root)
        for pattern in [
            "CMakeLists.txt",
            "cmake/*",
            "include/*",
            "src/*",
            "tests/*",
            "examples/*",
        ]:
            copy(self, pattern, src=package_dir, dst=self.export_sources_folder)
        for crate in workspace_members:
            copy(
                self,
                "*",
                src=repo_root / "crates" / crate,
                dst=Path(self.export_sources_folder) / "crates" / crate,
            )
        save(
            self,
            Path(self.export_sources_folder) / "Cargo.toml",
            self._trimmed_workspace_manifest(repo_root),
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
