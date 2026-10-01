"""Protected installed files and exclusive native-host access for coding sessions."""

import contextlib
import fcntl
import hashlib
import importlib.util
import os
import stat
import sys
from pathlib import Path

from chio_mini_swe.operator import private_directory, protected_executable, protected_parent
from chio_mini_swe.repository_review import document, read_file


def read_private(path, maximum=1024 * 1024):
    path = Path(path)
    protected_parent(path.parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
            or metadata.st_size > maximum
        ):
            raise ValueError("Session input must be a bounded private regular file")
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("Session input exceeds its byte limit")
    return data


def read_document(path, *, private=False, maximum=1024 * 1024):
    return document((read_private if private else read_file)(path, maximum))


def file_hash(path, *, maximum=1024 * 1024, private=False):
    return hashlib.sha256((read_private if private else read_file)(path, maximum)).hexdigest()


def _protected(path):
    metadata = path.lstat()
    if metadata.st_uid not in {0, os.getuid()} or metadata.st_mode & 0o022:
        raise ValueError("The installed Python environment is writable by other users")
    if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
        raise ValueError("The installed Python environment contains a special file")


def environment_identity():
    """Check the trusted installation and pin Chio's installed Python source files.

    Dependency/interpreter contents remain trusted installation components.
    Permission checks do not claim that a launcher digest authenticates them.
    """
    if os.environ.get("PYTHONPATH") or os.environ.get("PYTHONHOME"):
        raise ValueError("Installed sessions refuse Python import-path overrides")
    prefix = Path(sys.prefix).resolve(strict=True)
    if sys.prefix == sys.base_prefix:
        raise ValueError("Coding sessions require an installed private virtual environment")
    protected_parent(prefix)
    interpreter = Path(sys.executable).resolve(strict=True)
    protected_executable(interpreter)
    # Walk without following directory symlinks. Each symlink target is checked
    # separately; a directory alias is refused except the standard lib64 alias.
    count = 0
    for directory, subdirectories, files in os.walk(prefix, followlinks=False):
        _protected(Path(directory))
        for name in [*subdirectories, *files]:
            count += 1
            if count > 100000:
                raise ValueError("The installed Python environment exceeds its entry bound")
            path = Path(directory) / name
            if path.is_symlink():
                target = path.resolve(strict=True)
                protected_parent(target.parent)
                _protected(target)
                if target.is_dir() and not (path == prefix / "lib64" and target == prefix / "lib"):
                    raise ValueError("Installed Python directory aliases are not supported")
            else:
                _protected(path)
    launchers = {}
    for name in ("chio-mini-swe", "chio-mini-swe-model", "chio-mini-swe-repository"):
        path = (prefix / "bin" / name).resolve(strict=True)
        if not path.is_relative_to(prefix):
            raise ValueError("Coding launchers must belong to the installed virtual environment")
        protected_executable(path)
        launchers[name] = {"path": str(path), "sha256": file_hash(path)}
    sources = {}
    for package in ("chio_mini_swe", "chio_process"):
        specification = importlib.util.find_spec(package)
        if specification is None or specification.origin is None:
            raise ValueError("Both Chio Python packages must be installed")
        root = Path(specification.origin).resolve(strict=True).parent
        if not root.is_relative_to(prefix):
            raise ValueError("Coding sessions require installed packages without editable sources")
        entries = sorted(root.rglob("*.py"))
        if not entries or len(entries) > 256:
            raise ValueError("Invalid installed Chio source inventory")
        for path in entries:
            sources[f"{package}/{path.relative_to(root)}"] = file_hash(path)
    return {
        "prefix": str(prefix),
        "interpreter": str(interpreter),
        "launchers": launchers,
        "sources": sources,
    }


@contextlib.contextmanager
def exclusive_lock(path, *, create=False):
    """Use Linux flock, matching the native process host's File::try_lock."""
    path = Path(path)
    private_directory(path.parent)
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(path, flags | (os.O_CREAT if create else 0), 0o600)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
        ):
            raise ValueError("Session and host locks must be private regular files")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise BlockingIOError(
                "Stop the active session or host before this operation"
            ) from error
        current = path.lstat()
        if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise ValueError("Session or host lock identity changed")
        yield
    finally:
        os.close(descriptor)


@contextlib.contextmanager
def stopped_host(state):
    host = Path(state) / "run" / "host"
    if os.path.lexists(host):
        with exclusive_lock(host / "host.lock"):
            yield
    else:
        yield
