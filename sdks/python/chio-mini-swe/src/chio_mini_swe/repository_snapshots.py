"""Private immutable archive segments with bounded, digest-verified indexes."""

import io
import json
import os
import re
import stat
import tarfile

from chio_mini_swe.operator import private_directory
from chio_mini_swe.provider_config import reject_constant, unique_object
from chio_mini_swe.repository_archive import MAX_ARCHIVE, MAX_FILES, digest, entries

STORAGE_SCHEMA = "chio.repository.workspace.v2"
INDEX_SCHEMA = "chio.repository.snapshot.v2"
MAX_STORAGE = 256 * 1024 * 1024
MAX_COMMANDS = 128
MAX_CHUNKS = 2 * MAX_FILES + 1
MAX_INDEX = 4 * 1024 * 1024
# Charge small files at least one allocation unit, bounding inode growth as
# well as payload bytes. This is an accounting limit, not a filesystem quota.
MIN_FILE_CHARGE = 4096
MAX_RESERVATION = MAX_ARCHIVE + MAX_CHUNKS * MIN_FILE_CHARGE + MAX_INDEX


def identity(value):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("Invalid repository snapshot digest")
    return value


def metadata_valid(metadata, limit):
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o077
        or metadata.st_size > limit
    ):
        raise ValueError("Repository snapshot storage must use bounded private regular files")


def read_private(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        metadata_valid(metadata, limit)
        data = stream.read(limit + 1)
    if len(data) != metadata.st_size or len(data) > limit:
        raise ValueError("Repository snapshot storage changed while reading")
    return data


def segments(data):
    """Keep exact archive bytes while sharing member bodies across snapshots."""
    entries(data, allow_git=True)
    result = []
    cursor = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        for member in archive:
            start, end = member.offset_data, member.offset_data + member.size
            if not cursor <= start <= end <= len(data):
                raise ValueError("Invalid repository snapshot archive offsets")
            for first, last in ((cursor, start), (start, end)):
                if first != last:
                    result.append(data[first:last])
            cursor = end
    if cursor < len(data):
        result.append(data[cursor:])
    if not 1 <= len(result) <= MAX_CHUNKS:
        raise ValueError("Repository snapshot segment count exceeds its bound")
    return result


class SnapshotStore:
    """Used under the workspace lock; failed writes remain charged and retained."""

    def __init__(self, root, writer):
        self.root = private_directory(root)
        self.objects = private_directory(root / "objects")
        self.writer = writer

    @classmethod
    def create(cls, root, writer):
        root.mkdir(mode=0o700)
        (root / "objects").mkdir(mode=0o700)
        return cls(root, writer)

    def usage(self):
        private_directory(self.root)
        private_directory(self.objects)
        charged = 0
        for directory, limit, maximum in (
            (self.root, MAX_INDEX, MAX_COMMANDS + 2),
            (self.objects, MAX_ARCHIVE, MAX_STORAGE // MIN_FILE_CHARGE),
        ):
            count = 0
            for path in directory.iterdir():
                if directory == self.root and path.name == "objects":
                    continue
                count += 1
                if count > maximum:
                    raise ValueError("Repository snapshot file count exceeds its bound")
                identity(path.name)
                metadata = path.lstat()
                metadata_valid(metadata, limit)
                charged += max(MIN_FILE_CHARGE, metadata.st_size)
                if charged > MAX_STORAGE:
                    raise ValueError("Repository snapshot storage budget is exhausted")
        return charged

    def load(self, sha256):
        identity(sha256)
        private_directory(self.root)
        private_directory(self.objects)
        index = json.loads(
            read_private(self.root / sha256, MAX_INDEX),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
        if (
            not isinstance(index, dict)
            or set(index) != {"schema", "sha256", "bytes", "chunks"}
            or index["schema"] != INDEX_SCHEMA
            or index["sha256"] != sha256
            or type(index["bytes"]) is not int
            or not 0 < index["bytes"] <= MAX_ARCHIVE
            or not isinstance(index["chunks"], list)
            or not 1 <= len(index["chunks"]) <= MAX_CHUNKS
        ):
            raise ValueError("Invalid repository snapshot index")
        size = 0
        for chunk in index["chunks"]:
            if (
                not isinstance(chunk, list)
                or len(chunk) != 2
                or type(chunk[1]) is not int
                or not 0 < chunk[1] <= MAX_ARCHIVE
            ):
                raise ValueError("Invalid repository snapshot segment")
            identity(chunk[0])
            size += chunk[1]
            if size > MAX_ARCHIVE:
                raise ValueError("Repository snapshot reconstruction exceeds its bound")
        if size != index["bytes"]:
            raise ValueError("Repository snapshot index has inconsistent byte counts")
        data = bytearray()
        for key, length in index["chunks"]:
            chunk = read_private(self.objects / key, length)
            if len(chunk) != length or digest(chunk) != key:
                raise ValueError("Repository snapshot segment is missing or corrupt")
            data.extend(chunk)
        if digest(data) != sha256:
            raise ValueError("Repository snapshot is missing or corrupt")
        return bytes(data)

    def put(self, data, maximum=MAX_STORAGE):
        if type(maximum) is not int or not 0 <= maximum <= MAX_STORAGE:
            raise ValueError("Invalid repository snapshot storage budget")
        sha256 = digest(data)
        charged = self.usage()
        if charged > maximum:
            raise ValueError("Repository snapshot storage budget is exhausted")
        target = self.root / sha256
        if target.exists():
            if self.load(sha256) != data:
                raise ValueError("Repository snapshot index differs from its archive")
            return sha256
        chunks = segments(data)
        unique = {digest(chunk): chunk for chunk in chunks}
        index = json.dumps(
            {
                "schema": INDEX_SCHEMA,
                "sha256": sha256,
                "bytes": len(data),
                "chunks": [[digest(chunk), len(chunk)] for chunk in chunks],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        if len(index) > MAX_INDEX:
            raise ValueError("Repository snapshot index exceeds its byte bound")
        missing = {}
        additional = max(MIN_FILE_CHARGE, len(index))
        for key, chunk in unique.items():
            path = self.objects / key
            if path.exists():
                existing = read_private(path, len(chunk))
                if digest(existing) != key:
                    raise ValueError("Repository snapshot segment is missing or corrupt")
            else:
                missing[key] = chunk
                additional += max(MIN_FILE_CHARGE, len(chunk))
        if charged + additional > maximum:
            raise ValueError("Repository snapshot storage budget is exhausted")
        # Every object and its directory are durable before publishing the index.
        # The workspace journal only advances after the caller also cleans up its lease.
        for key, chunk in missing.items():
            self.writer(self.objects / key, chunk)
        self.writer(target, index)
        return sha256
