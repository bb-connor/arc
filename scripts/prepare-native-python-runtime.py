#!/usr/bin/env python3
"""Package an explicit CPython stdlib closure for enforced native demo tools.

The immutable stdlib archive is one retained resource. Native extensions and
ELF dependencies remain individual files. This creates no launch authority;
the native compiler still validates the complete application's resource budget.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import zipfile
from pathlib import Path

MAX_BYTES = 64 * 1024 * 1024
PROBE = r"""
import importlib, json, sys, sysconfig
for name in sys.argv[1:]:
    importlib.import_module(name)
print(json.dumps({
    'executable':sys.executable,
    'version':list(sys.version_info[:3]),
    'stdlib':sysconfig.get_path('stdlib'),
    'extensions':sorted({m.__file__ for m in sys.modules.values()
                         if getattr(m, '__file__', '').endswith('.so')}),
}))
"""


def trusted_file(path):
    path = Path(path).resolve(strict=True)
    info = path.stat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_mode & 0o022
        or info.st_uid not in {0, os.getuid()}
        or info.st_size > MAX_BYTES
    ):
        raise ValueError(f"Runtime input is not a protected bounded file: {path}")
    return path


def command(arguments):
    result = subprocess.run(arguments, capture_output=True, check=True, timeout=30)
    if len(result.stdout) > 65536:
        raise ValueError("Runtime discovery output exceeds 64 KiB")
    return result.stdout.decode()


def dependencies(path):
    result = set()
    for line in command(["ldd", str(path)]).splitlines():
        if "not found" in line:
            raise ValueError("Runtime ELF dependency is missing")
        fields = line.strip().split()
        if not fields:
            continue
        name = fields[2] if len(fields) >= 3 and fields[1] == "=>" else fields[0]
        if name.startswith("/"):
            result.add(trusted_file(name))
    return result


def prepare(python, directory, modules, module_paths):
    python = trusted_file(python)
    if any(re.fullmatch(r"[a-zA-Z_][a-zA-Z_0-9.]*", name) is None for name in modules):
        raise ValueError("Module names must be explicit Python identifiers")
    observed = json.loads(command([str(python), "-I", "-S", "-c", PROBE, *modules]))
    if observed["version"][:2] < [3, 11]:
        raise ValueError("CPython 3.11 or newer is required")
    stdlib = Path(observed["stdlib"]).resolve(strict=True)
    directory = directory.absolute()
    directory.mkdir(mode=0o700, exist_ok=False)
    target = directory / "python"
    shutil.copyfile(python, target)
    target.chmod(0o555)
    archive_path = directory / "stdlib.zip"
    total = 0
    with zipfile.ZipFile(archive_path, "x", compression=zipfile.ZIP_STORED) as archive:
        for source in sorted(stdlib.rglob("*.py")):
            relative = source.relative_to(stdlib)
            if relative.parts[0] in {
                "site-packages",
                "dist-packages",
                "test",
                "__pycache__",
            } or relative.name in {"sitecustomize.py", "usercustomize.py"}:
                continue
            source = trusted_file(source)
            if not source.is_relative_to(stdlib):
                raise ValueError("Stdlib entry escapes its selected source directory")
            total += source.stat().st_size
            if total > MAX_BYTES:
                raise ValueError("Runtime stdlib exceeds 64 MiB")
            archive.write(source, str(relative))
    archive_path.chmod(0o444)
    extensions = directory / "extensions"
    extensions.mkdir(mode=0o700)
    libraries = dependencies(python)
    for name in observed["extensions"]:
        source = trusted_file(name)
        destination = extensions / source.name
        if destination.exists():
            raise ValueError("Duplicate runtime extension basename")
        shutil.copyfile(source, destination)
        destination.chmod(0o444)
        libraries.update(dependencies(source))
    paths = [archive_path, extensions]
    for path in module_paths:
        path = path.resolve(strict=True)
        if not path.is_dir() or path == Path("/"):
            raise ValueError("Additional module paths must be explicit non-root directories")
        paths.append(path)
    if any("\n" in str(path) or "\r" in str(path) for path in paths):
        raise ValueError("Runtime paths cannot contain line separators")
    # CPython's isolated path file disables ambient site/PYTHONPATH/user imports.
    isolated_paths = directory / "python._pth"
    isolated_paths.write_text("".join(f"{path}\n" for path in paths))
    isolated_paths.chmod(0o444)
    inventory = sorted(path for path in directory.rglob("*") if path.is_file())
    # Bind executable Python bytes and import configuration as well as ELF
    # libraries. Ordinary read grants alone do not commit to file contents.
    runtime_files = directory / "runtime-files.txt"
    runtime_files.write_text(
        "".join(
            f"{path}\n"
            for path in sorted(
                libraries | set(extensions.iterdir()) | {archive_path, isolated_paths}
            )
        )
    )
    # The loader cache is a path lookup input, while every reachable library
    # must still be separately pinned by the compiler.
    cache = Path("/etc/ld.so.cache")
    if cache.exists():
        libraries.add(trusted_file(cache))
    # FileFinder enumerates the selected extension directory before opening a
    # module. Include that single protected directory in the resource budget.
    read_paths = [extensions, *inventory, *sorted(libraries)]
    if len(read_paths) > 60:
        raise ValueError("Runtime leaves fewer than four of 64 resources for the application")
    grants = directory / "read-paths.txt"
    grants.write_text("".join(f"{path}\n" for path in read_paths))
    check = json.loads(command([str(target), "-I", "-S", "-c", PROBE, *modules]))
    if set(check["extensions"]) != {str(extensions / Path(p).name) for p in observed["extensions"]}:
        raise ValueError("Packaged runtime did not retain exactly the selected extensions")
    manifest = {
        "schema": "chio.native-python-runtime.v1",
        "python_version": observed["version"],
        "modules": modules,
        "module_paths": [str(path) for path in paths[2:]],
        "source_python": str(python),
        "files": {
            str(path): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in [*inventory, *sorted(libraries)]
        },
        "read_paths_file": str(grants),
        "runtime_files_file": str(runtime_files),
        "syscall_profile": "native-standard-v1",
        "python": str(target),
    }
    (directory / "runtime.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--module", action="append", default=[])
    parser.add_argument("--module-path", type=Path, action="append", default=[])
    args = parser.parse_args()
    os.umask(0o077)
    result = prepare(args.python, args.output, args.module, args.module_path)
    print(
        json.dumps(
            {
                key: result[key]
                for key in ("schema", "python", "read_paths_file", "runtime_files_file")
            }
        )
    )


if __name__ == "__main__":
    main()
