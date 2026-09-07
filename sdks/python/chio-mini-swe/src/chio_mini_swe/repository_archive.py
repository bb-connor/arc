"""Bounded, canonical workspace snapshots and review-only Git patches."""

import hashlib
import io
import os
import posixpath
import re
import shutil
import stat
import tarfile
import tempfile
from collections import deque
from pathlib import Path, PurePosixPath

from chio_mini_swe.repository_transport import run

MAX_ARCHIVE = 80 * 1024 * 1024
MAX_CONTENT = 64 * 1024 * 1024
MAX_FILE = 16 * 1024 * 1024
MAX_FILES = 8192


def path_name(value, *, allow_git=False):
    value = value.removeprefix("./").rstrip("/")
    parts = PurePosixPath(value).parts
    if (
        not parts
        or value.startswith("/")
        or any(p in {".", ".."} or (p.lower() == ".git" and not allow_git) for p in parts)
        or str(PurePosixPath(value)) != value
        or len(value.encode()) > 1024
        or any(ord(c) < 32 or ord(c) == 127 or c == "\\" for c in value)
    ):
        raise ValueError("Workspace archive contains an unsafe path")
    return value


def entries(data, *, allow_git=False):
    if len(data) > MAX_ARCHIVE:
        raise ValueError("Workspace archive exceeds its byte limit")
    files, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        for member in archive:
            if member.name in {".", "./"} and member.isdir():
                continue
            name = path_name(member.name, allow_git=allow_git)
            if name in files or len(files) >= MAX_FILES or member.size > MAX_FILE:
                raise ValueError("Duplicate or oversized workspace entry")
            if member.isdir():
                value = ("directory", 0o755, b"")
            elif member.issym():
                target = member.linkname
                resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
                if (
                    not target
                    or target.startswith("/")
                    or len(target.encode()) > 1024
                    or any(ord(c) < 32 or ord(c) == 127 or c == "\\" for c in target)
                ):
                    raise ValueError("Unsafe workspace symlink")
                if resolved != ".":
                    path_name(resolved, allow_git=allow_git)
                value = ("symlink", 0o777, target.encode())
            elif member.isfile() and not member.sparse:
                total += member.size
                if total > MAX_CONTENT:
                    raise ValueError("Workspace contents exceed their byte limit")
                stream = archive.extractfile(member)
                content = stream.read(MAX_FILE + 1)
                if len(content) != member.size:
                    raise ValueError("Truncated workspace file")
                value = ("file", 0o755 if member.mode & 0o111 else 0o644, content)
            else:
                raise ValueError("Workspace entry must be a file, directory or relative symlink")
            files[name] = value
    for name in files:
        for parent in PurePosixPath(name).parents:
            if str(parent) in files and files[str(parent)][0] != "directory":
                raise ValueError("Workspace entry traverses a non-directory")
    for name, (kind, _, target) in files.items():
        if kind == "symlink":
            resolve_link(name, target.decode(), files)
    return files


def resolve_link(name, target, files):
    resolved = list(PurePosixPath(name).parent.parts)
    pending = deque(target.split("/"))
    expansions = 0
    while pending:
        part = pending.popleft()
        if part in {"", "."}:
            continue
        if part == "..":
            if not resolved:
                raise ValueError("Workspace symlink chain escapes its root")
            resolved.pop()
            continue
        resolved.append(part)
        entry = files.get("/".join(resolved))
        if entry and entry[0] == "symlink":
            expansions += 1
            if expansions > 40:
                raise ValueError("Workspace symlink chain is cyclic or too deep")
            resolved.pop()
            pending.extendleft(reversed(entry[2].decode().split("/")))


def canonical(data, *, allow_git=False):
    return encode_entries(entries(data, allow_git=allow_git))


def encode_entries(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, (kind, mode, content) in sorted(files.items()):
            member = tarfile.TarInfo(name)
            member.mode, member.uid, member.gid = mode, 65534, 65534
            if kind == "directory":
                member.type = tarfile.DIRTYPE
            elif kind == "symlink":
                member.type, member.linkname = tarfile.SYMTYPE, content.decode()
            else:
                member.size = len(content)
            archive.addfile(member, io.BytesIO(content) if kind == "file" else None)
    result = output.getvalue()
    if len(result) > MAX_ARCHIVE:
        raise ValueError("Canonical workspace exceeds its byte limit")
    return result


def contents(data):
    # Container-controlled Git metadata stays opaque in private snapshots. It
    # is never extracted onto the host or used by the host's patch generator.
    files = entries(data, allow_git=True)
    files = {
        name: value
        for name, value in files.items()
        if not any(part.lower() == ".git" for part in PurePosixPath(name).parts)
    }
    return canonical(encode_entries(files))


def with_git(data):
    with tempfile.TemporaryDirectory(prefix="chio-repository-seed-") as temporary:
        directory = Path(temporary)
        git("init", "--quiet", "--template=", cwd=directory)
        materialize(data, directory)
        git("add", "--force", "--all", cwd=directory)
        git(
            "-c",
            "user.name=Chio",
            "-c",
            "user.email=chio@localhost",
            "commit",
            "--quiet",
            "--allow-empty",
            "-m",
            "Imported repository snapshot",
            cwd=directory,
        )
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
            archive.add(directory, arcname=".")
        return canonical(output.getvalue(), allow_git=True)


def git(*arguments, cwd, limit=MAX_ARCHIVE):
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(cwd),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }
    return run(
        [
            "/usr/bin/git",
            "--no-optional-locks",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "commit.gpgsign=false",
            *arguments,
        ],
        cwd=cwd,
        environment=environment,
        limit=limit,
    )[1]


def import_revision(repository, revision):
    repository = Path(repository).resolve(strict=True)
    # These discovery commands only read repository paths and refs. Resolve the
    # requested revision and read its objects under a fresh configuration so
    # source filters, archive commands and promisor remotes cannot run on import.
    object_format = git("rev-parse", "--show-object-format", cwd=repository).decode().strip()
    if object_format not in {"sha1", "sha256"}:
        raise ValueError("Unsupported repository object format")
    object_directory = Path(
        git("rev-parse", "--path-format=absolute", "--git-path", "objects", cwd=repository)
        .decode()
        .removesuffix("\n")
    ).resolve(strict=True)
    refs = git("for-each-ref", "--format=%(objectname) %(refname)", cwd=repository)
    head = git("rev-parse", "--revs-only", "--end-of-options", "HEAD", cwd=repository).strip()
    oid_pattern = rb"[a-f0-9]{40}" if object_format == "sha1" else rb"[a-f0-9]{64}"
    if head and re.fullmatch(oid_pattern, head) is None:
        raise ValueError("Invalid repository HEAD")
    for line in refs.splitlines():
        identifier, separator, reference = line.partition(b" ")
        if (
            not separator
            or re.fullmatch(oid_pattern, identifier) is None
            or not reference.startswith(b"refs/")
            or any(byte <= 32 or byte == 127 for byte in reference)
        ):
            raise ValueError("Invalid repository reference")
    with tempfile.TemporaryDirectory(prefix="chio-repository-import-") as temporary:
        directory = Path(temporary)
        git(
            "init",
            "--quiet",
            "--bare",
            "--template=",
            "--object-format=" + object_format,
            cwd=directory,
        )
        # A fixed relative alternate avoids quoting arbitrary operator paths in
        # Git's line-based alternates format. The source object store is read-only.
        (directory / "objects/source").symlink_to(object_directory, target_is_directory=True)
        (directory / "objects/info/alternates").write_bytes(b"source\n")
        (directory / "packed-refs").write_bytes(refs)
        if head:
            (directory / "HEAD").write_bytes(head + b"\n")
        commit = (
            git(
                "--no-replace-objects",
                "rev-parse",
                "--verify",
                "--end-of-options",
                revision + "^{commit}",
                cwd=directory,
            )
            .decode()
            .strip()
        )
        if re.fullmatch(oid_pattern, commit.encode()) is None:
            raise ValueError("Repository revision did not resolve to a commit")
        tree = git("--no-replace-objects", "ls-tree", "-rz", commit, cwd=directory)
        if any(entry.startswith(b"160000 ") for entry in tree.split(b"\0")):
            raise ValueError(
                "Repository submodules must be materialized in the selected image or tree"
            )
        data = canonical(
            git("--no-replace-objects", "archive", "--format=tar", commit, cwd=directory)
        )
        return commit, data


def materialize(data, directory):
    files = entries(data)
    # All parents were validated before creating anything. Symlinks are last.
    for name, (kind, mode, content) in sorted(
        files.items(), key=lambda item: item[1][0] == "symlink"
    ):
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if kind == "directory":
            target.mkdir(exist_ok=True)
        elif kind == "symlink":
            target.symlink_to(content.decode())
        else:
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)


def patch(before, after):
    with tempfile.TemporaryDirectory(prefix="chio-repository-patch-") as temporary:
        directory = Path(temporary)
        git("init", "--quiet", "--template=", cwd=directory)
        materialize(before, directory)
        git("add", "--force", "--all", "--", ".", cwd=directory)
        git(
            "-c",
            "user.name=Chio",
            "-c",
            "user.email=chio@localhost",
            "commit",
            "--quiet",
            "--allow-empty",
            "-m",
            "snapshot",
            cwd=directory,
        )
        for child in directory.iterdir():
            if child.name == ".git":
                continue
            if stat.S_ISDIR(child.lstat().st_mode):
                shutil.rmtree(child)
            else:
                child.unlink()
        materialize(after, directory)
        git("add", "--all", "--", ".", cwd=directory)
        return git(
            "diff",
            "--cached",
            "--binary",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "HEAD",
            "--",
            cwd=directory,
            limit=2 * MAX_ARCHIVE,
        )


def digest(data):
    return hashlib.sha256(data).hexdigest()
