"""Protect a copied virtual environment through verified, non-following descriptors."""

import contextlib
import json
import os
import stat
import sys
from pathlib import Path

from chio_mini_swe.operator import protected_executable, protected_parent
from chio_mini_swe.session_security import environment_identity

MAX_ENTRIES = 100000
MAX_DEPTH = 128


def _identity(metadata):
    return metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode)


def _validate(metadata):
    if (
        metadata.st_uid != os.getuid()
        or not (
            stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
        )
        or (stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1)
    ):
        raise ValueError("Use an operator-owned environment installed with --link-mode copy")


def _same(metadata, expected):
    _validate(metadata)
    if _identity(metadata) != expected:
        raise ValueError("The installation changed during permission preparation")


def _open(parent, name, expected):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    if expected[2] == stat.S_IFDIR:
        flags |= os.O_DIRECTORY
    descriptor = os.open(name, flags, dir_fd=parent)
    try:
        _same(os.fstat(descriptor), expected)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _inventory(root):
    """Refuse pre-existing shared files before changing any permissions."""
    inventory = {}

    def visit(directory, relative):
        metadata = os.fstat(directory)
        _validate(metadata)
        inventory[relative] = _identity(metadata)
        if len(relative) >= MAX_DEPTH:
            raise ValueError("The installation exceeds its directory depth bound")
        for name in sorted(os.listdir(directory)):
            path = (*relative, name)
            metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
            _validate(metadata)
            expected = _identity(metadata)
            if len(inventory) >= MAX_ENTRIES:
                raise ValueError("The installation exceeds its entry bound")
            if stat.S_ISDIR(metadata.st_mode):
                descriptor = _open(directory, name, expected)
                try:
                    visit(descriptor, path)
                finally:
                    os.close(descriptor)
            else:
                inventory[path] = expected

    visit(root, ())
    return inventory


@contextlib.contextmanager
def _entry(root, relative, inventory):
    """Pin each ancestor while traversing it, never following a directory alias."""
    with contextlib.ExitStack() as opened:
        descriptor = root
        _same(os.fstat(root), inventory[()])
        for depth, name in enumerate(relative, 1):
            parent = descriptor
            path = relative[:depth]
            expected = inventory[path]
            _same(os.stat(name, dir_fd=parent, follow_symlinks=False), expected)
            if expected[2] == stat.S_IFLNK:
                if depth != len(relative):
                    raise ValueError("Refusing an installation directory alias")
                yield None
                return
            descriptor = _open(parent, name, expected)
            opened.callback(os.close, descriptor)
            # A swap between stat and open cannot redirect chmod to a different
            # inode. Recheck the directory entry before returning the pinned fd.
            _same(os.stat(name, dir_fd=parent, follow_symlinks=False), expected)
        yield descriptor


def _verify(root, inventory):
    """Check the captured inventory afresh, without applying its old modes."""
    children = {path: set() for path, value in inventory.items() if value[2] == stat.S_IFDIR}
    for path in inventory:
        if path:
            children[path[:-1]].add(path[-1])
    for path in sorted(inventory):
        with _entry(root, path, inventory) as descriptor:
            if descriptor is not None and path in children:
                if set(os.listdir(descriptor)) != children[path]:
                    raise ValueError("The installation inventory changed during preparation")


def _remove_write(descriptor, expected):
    metadata = os.fstat(descriptor)
    _same(metadata, expected)
    current = stat.S_IMODE(metadata.st_mode)
    if not current & 0o022:
        return 0
    # Only remove bits from the current descriptor's mode. Never restore read,
    # execute or write permissions from a stale inventory snapshot.
    os.fchmod(descriptor, current & ~0o022)
    _same(os.fstat(descriptor), expected)
    return 1


def protect():
    prefix = Path(sys.prefix).resolve(strict=True)
    if sys.prefix == sys.base_prefix:
        raise ValueError("Create a dedicated virtual environment first")
    protected_parent(prefix.parent)
    protected_executable(Path(sys.executable).resolve(strict=True))
    with contextlib.ExitStack() as opened:
        parent = os.open(prefix.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        opened.callback(os.close, parent)
        metadata = os.stat(prefix.name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("The virtual environment must be an existing directory")
        root = _open(parent, prefix.name, _identity(metadata))
        opened.callback(os.close, root)
        inventory = _inventory(root)
        _verify(root, inventory)
        updates = 0
        # Protect directories from the top down before touching regular files.
        # Verified parent descriptors and removed group/other directory writes
        # prevent another user from redirecting subsequent pathname traversal.
        directories = sorted(
            (path for path, value in inventory.items() if value[2] == stat.S_IFDIR),
            key=lambda path: (len(path), path),
        )
        for path in directories:
            _same(os.stat(prefix.name, dir_fd=parent, follow_symlinks=False), inventory[()])
            with _entry(root, path, inventory) as descriptor:
                updates += _remove_write(descriptor, inventory[path])
        _verify(root, inventory)
        for path, expected in sorted(inventory.items()):
            if expected[2] == stat.S_IFREG:
                _same(os.stat(prefix.name, dir_fd=parent, follow_symlinks=False), inventory[()])
                with _entry(root, path, inventory) as descriptor:
                    updates += _remove_write(descriptor, expected)
        _verify(root, inventory)
    # A concurrent mutation can make a later check fail after earlier entries
    # were protected. Keep that dedicated installation for diagnosis; no bits
    # are restored and no alternate paths are chmodded to complete the batch.
    identity = environment_identity()
    return {
        "prefix": str(prefix),
        "protected_entries": updates,
        "interpreter": identity["interpreter"],
    }


if __name__ == "__main__":
    print(json.dumps(protect()))
