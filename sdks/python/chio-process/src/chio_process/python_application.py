"""Explicit, content-bound application modules for an isolated native interpreter."""

import os
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath

from chio_process.launch import demo_python, provision_native_demo

MAX_APPLICATION_BYTES = 4 * 1024 * 1024


def package_modules(destination, modules):
    """Capture only the selected protected source files, with no directory grant."""
    if not isinstance(modules, dict) or not 1 <= len(modules) <= 128:
        raise ValueError("Select between one and 128 application modules")
    captured, size = {}, 0
    for name, source in sorted(modules.items()):
        relative = PurePosixPath(name)
        if (
            relative.is_absolute()
            or str(relative) != name
            or any(part in {"", ".", ".."} for part in relative.parts)
            or not name.endswith(".py")
            or "\\" in name
            or "\0" in name
        ):
            raise ValueError("Application entries must be literal relative Python paths")
        descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid not in {0, os.getuid()}
                or before.st_mode & 0o022
                or not 0 < before.st_size <= MAX_APPLICATION_BYTES - size
            ):
                raise ValueError("Application sources must be protected bounded regular files")
            data = stream.read(MAX_APPLICATION_BYTES - size + 1)
            after = os.fstat(stream.fileno())
            if len(data) != before.st_size or (
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError("Application source changed while being captured")
            captured[name] = data
            size += len(data)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
            for name, data in captured.items():
                entry = zipfile.ZipInfo(name)
                entry.external_attr = 0o100444 << 16
                archive.writestr(entry, data)
        stream.flush()
        os.fsync(stream.fileno())
    return Path(destination).resolve(strict=True)


def provision_native_python_demo(
    chio, server_id, module, modules, arguments, output_dir, working_directory, **permissions
):
    """Sign one explicit application archive into the reviewed Python runtime."""
    if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*(\.[A-Za-z_][A-Za-z_0-9]*)*", module) is None:
        raise ValueError("Application entrypoint must be a Python module name")
    if module.replace(".", "/") + ".py" not in modules:
        raise ValueError("Application entrypoint must be among the captured modules")
    output = Path(output_dir).absolute()
    archive = package_modules(output.with_name(output.name + ".application.zip"), modules)
    command = [
        demo_python(),
        "-I",
        "-B",
        "-c",
        f"import runpy,sys;sys.path.insert(0,{str(archive)!r});"
        f"runpy.run_module({module!r},run_name='__main__')",
        *arguments,
    ]
    return provision_native_demo(
        chio,
        server_id,
        command,
        output,
        working_directory,
        read_paths=[archive, *permissions.pop("read_paths", ())],
        runtime_files=[archive, *permissions.pop("runtime_files", ())],
        **permissions,
    )
