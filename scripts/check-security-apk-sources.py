#!/usr/bin/env python3
"""Bind the vendored security evidence APKs to their in-repository corresponding source.

deploy/docker/security-evidence-apk-sources/ holds, for the archives in
deploy/docker/security-evidence-apks/, the exact aports recipe of every
origin, the recipe and source of every abuild revision that built them, the
upstream sources of every origin, license notices for every origin, and an
attribution inventory derived from those sources. MANIFEST.json ties each
archive digest to those files. This check reads local files only and fails
closed when:

- MANIFEST.json does not match EXPECTED_SOURCES_MANIFEST_SHA256, or names an
  archive manifest or provenance file other than the ones in the tree;
- the directory holds anything but the regular files SHA256SUMS lists (and
  SHA256SUMS), a file differs from its digest or exceeds the per-file bound,
  or the manifest references a different file set;
- any path component beneath the root is a symlink, or a directory is
  replaced while the tree is read (paths resolve one no-follow component at a
  time from a root descriptor, with directory identity recorded);
- a provenance record is missing, duplicated or moved to another origin, or
  the .PKGINFO in its archive's control segment names another origin,
  commit, version or license, or the control or signature segment holds a
  link, sparse entry, repeated name or member over its bound (the signature
  member name is a shape check; apk add verifies the RSA signature);
- an upstream source of an origin or abuild revision is not vendored here
  exactly once (as one file or as split chunks), an origin that ships an
  archive whose license names GPL, LGPL, AGPL, MPL or Artistic has no
  upstream source, or a split archive does not rebuild to its recorded
  length, sha256 and sha512;
- a recipe file differs from its sha256 or git blob id, or the recipe files
  are not exactly the blobs of main/<origin> (or main/abuild) reached from
  the aports commit through retained raw commit and tree objects, each
  checked against its id;
- an APKBUILD, read as text and never executed, gives another version or a
  sha512sums block that differs from the manifest's sources, or an upstream
  URL that its top-level source= block names through plain parameter
  expansion differs from the manifest (url_check records which URLs that
  static expansion reaches; the rest are acquisition metadata, their
  content pinned by sha512 only);
- an abuild revision named by a .PKGINFO has no recipe and source;
- a notice does not name an upstream source of its origin, or is not exactly
  one plain regular member of that vendored source (or the leading bytes of
  one, or the whole source file) with the same bytes; an origin without
  notices has no upstream source at all;
- an origin with upstream sources has no attributions/<origin>.tsv, or that
  inventory is not exactly the distinct copyright/attribution lines (and the
  unscanned binary heads) that the checker derives from the heads of the
  vendored upstream files and of its Alpine-local sources
  (ATTRIBUTION_METHOD);
- an origin's license field is
  not the APKBUILD license= value as written, or its license tokens are not
  split exactly into identifiers on the vendored SPDX license list (each with
  its text) and unrecognized tokens, each listed as unresolved with nothing
  inferred from it.
"""

from __future__ import annotations

import argparse
import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
import re
import stat
import sys
import tarfile
import zlib
from collections import deque
from pathlib import Path

SOURCES_DIR = Path("deploy/docker/security-evidence-apk-sources")
SOURCES = SOURCES_DIR.as_posix()
APK_DIR = Path("deploy/docker/security-evidence-apks")
APK_MANIFEST = APK_DIR / "SHA256SUMS"
APK_PROVENANCE = Path("deploy/docker/security-evidence-apk-archives.json")
APK_LOCK = Path("deploy/docker/security-evidence-apk.lock")
LOCK_ENTRY = re.compile(r"(.+)-([0-9][^-]*-r[0-9]+)")
SCHEMA = "chio.security-evidence-apk-sources.v1"
MANIFEST_KEYS = frozenset({
    "schema", "binary_manifest", "binary_provenance", "readme", "aports_repository", "abuild_repository",
    "source_obligation_rule", "max_file_bytes", "spdx", "unrecognized_license_tokens", "attribution_method",
    "build_tools", "origins", "chunked",
})
APORTS_REPOSITORY = "https://gitlab.alpinelinux.org/alpine/aports"
ABUILD_REPOSITORY = "https://gitlab.alpinelinux.org/alpine/abuild"
SOURCE_OBLIGATION_RULE = (
    "source_obligation marks an origin with an archive whose license expression matches GPL|MPL|Artistic; "
    "the upstream sources of every origin are vendored either way"
)
CHUNK_SCHEMA = "chio.split-archive.v1"
EXPECTED_SOURCES_MANIFEST_SHA256 = (
    "d719ae7431228377d71edc4e2bd68eadd3d4f979121205eac95177c48ea19719"
)
MAX_FILE_BYTES = 95 * 1024 * 1024
MAX_APK_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_CONTROL_BYTES = 1024 * 1024
MAX_PKGINFO_BYTES = 64 * 1024
MAX_SIGNATURE_BYTES = 1024
MAX_NOTICE_BYTES = 1024 * 1024
SIGNATURE_MEMBER = ".SIGN.RSA.alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub"
COPYLEFT = re.compile(r"GPL|MPL|Artistic")
LICENSE_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]*")
LICENSE_OPERATORS = frozenset({"AND", "OR", "WITH"})
SUMS_LINE = re.compile(r"([0-9a-f]{64})  ([A-Za-z0-9._+@=,-]+(?:/[A-Za-z0-9._+@=,-]+)*)")
APK_SUMS_LINE = re.compile(r"([0-9a-f]{64})  ([a-z0-9][a-z0-9._+-]*\.apk)")
APKBUILD_SUM = re.compile(r"([0-9a-f]{128})  (\S+)")
HEX40 = re.compile(r"[0-9a-f]{40}")
GIT_FILE_MODES = frozenset({"100644", "100755", "120000"})


class SourcesError(RuntimeError):
    """The in-repository corresponding source does not bind the vendored archives."""


class Tree:
    """Reads files beneath one root without following any symlink below it.

    Each path is resolved one component at a time from a descriptor of the
    root, with O_NOFOLLOW on every directory and on the file, so a symlinked
    ancestor such as deploy/ is refused instead of followed out of the root.
    The device and inode of every directory are recorded the first time it is
    opened; a later open that finds a different directory at the same path is
    refused, so the walk and the reads see one directory tree.
    """

    def __init__(self, root: Path):
        try:
            self.root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        except OSError as error:
            raise SourcesError("source root is not a directory") from error
        self.identities: dict[str, tuple[int, int]] = {"": self.identity(self.root_fd)}

    def close(self) -> None:
        os.close(self.root_fd)

    @staticmethod
    def identity(descriptor: int) -> tuple[int, int]:
        metadata = os.fstat(descriptor)
        return metadata.st_dev, metadata.st_ino

    @staticmethod
    def parts(relative: str) -> list[str]:
        parts = relative.split("/")
        if any(part in ("", ".", "..") for part in parts):
            raise SourcesError(f"path is not a plain relative path: {relative}")
        return parts

    def directory(self, parts: list[str]) -> int:
        descriptor = os.dup(self.root_fd)
        walked: list[str] = []
        try:
            for part in parts:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                walked.append(part)
                key = "/".join(walked)
                identity = self.identity(descriptor)
                if self.identities.setdefault(key, identity) != identity:
                    raise SourcesError(f"directory {key} changed while the tree was being read")
        except OSError as error:
            os.close(descriptor)
            raise SourcesError(f"{'/'.join(parts)} is not a directory beneath the source root") from error
        except SourcesError:
            os.close(descriptor)
            raise
        return descriptor

    def open(self, relative: str, description: str) -> int:
        parts = self.parts(relative)
        parent = self.directory(parts[:-1])
        try:
            descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        except OSError as error:
            raise SourcesError(f"{description} is unavailable") from error
        finally:
            os.close(parent)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise SourcesError(f"{description} is not a regular file")
        return descriptor

    def read(self, relative: str, limit: int, description: str) -> bytes:
        descriptor = self.open(relative, description)
        try:
            if os.fstat(descriptor).st_size > limit:
                raise SourcesError(f"{description} exceeds {limit} bytes")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                content = stream.read(limit + 1)
        finally:
            os.close(descriptor)
        if len(content) > limit:
            raise SourcesError(f"{description} exceeds {limit} bytes")
        return content

    def digest(self, relative: str, limit: int, description: str) -> tuple[int, str, str]:
        descriptor = self.open(relative, description)
        sha256 = hashlib.sha256()
        sha512 = hashlib.sha512()
        length = 0
        try:
            if os.fstat(descriptor).st_size > limit:
                raise SourcesError(f"{description} exceeds {limit} bytes")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                for block in iter(lambda: stream.read(1 << 20), b""):
                    length += len(block)
                    if length > limit:
                        raise SourcesError(f"{description} exceeds {limit} bytes")
                    sha256.update(block)
                    sha512.update(block)
        finally:
            os.close(descriptor)
        return length, sha256.hexdigest(), sha512.hexdigest()

    def walk(self, relative: str) -> list[str]:
        files = []
        pending = [relative]
        while pending:
            current = pending.pop()
            descriptor = self.directory(self.parts(current))
            try:
                with os.scandir(descriptor) as entries:
                    listing = [(entry.name, entry.stat(follow_symlinks=False).st_mode) for entry in entries]
            finally:
                os.close(descriptor)
            for name, mode in listing:
                child = f"{current}/{name}"
                inside = child[len(relative) + 1:]
                if stat.S_ISDIR(mode):
                    pending.append(child)
                elif stat.S_ISREG(mode):
                    files.append(inside)
                else:
                    raise SourcesError(f"corresponding-source entry is not a regular file: {inside}")
        return files


def git_blob_id(content: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(content) + content).hexdigest()


def parse_sha256sums(content: bytes) -> dict[str, str]:
    if not content.endswith(b"\n"):
        raise SourcesError("corresponding-source SHA256SUMS is not canonical")
    entries = []
    for line in content.decode("ascii").splitlines():
        match = SUMS_LINE.fullmatch(line)
        if match is None or any(part in (".", "..") for part in match.group(2).split("/")):
            raise SourcesError("corresponding-source SHA256SUMS is not canonical")
        entries.append((match.group(2), match.group(1)))
    names = [name for name, _digest in entries]
    if names != sorted(names) or len(set(names)) != len(names) or "SHA256SUMS" in names:
        raise SourcesError("corresponding-source SHA256SUMS is not canonical")
    return dict(entries)


def gzip_members(content: bytes, count: int, limit: int, description: str) -> list[bytes]:
    members = []
    offset = 0
    while len(members) < count:
        if offset >= len(content):
            raise SourcesError(f"{description} is truncated")
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            output = decoder.decompress(content[offset:], limit + 1)
        except zlib.error as error:
            raise SourcesError(f"{description} is not an APK") from error
        if len(output) > limit or not decoder.eof:
            raise SourcesError(f"{description} control data is not bounded")
        members.append(output)
        offset = len(content) - len(decoder.unused_data)
    return members


def plain_members(raw: bytes, description: str) -> tuple[tarfile.TarFile, list[tarfile.TarInfo]]:
    try:
        archive = tarfile.open(fileobj=io.BytesIO(raw), mode="r:")
        members = archive.getmembers()
    except tarfile.TarError as error:
        raise SourcesError(f"{description} is not a readable tar segment") from error
    names = [member.name for member in members]
    if len(set(names)) != len(names):
        raise SourcesError(f"{description} repeats a member name")
    for member in members:
        if (
            member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)
            or member.issparse()
            or any(key.startswith("GNU.sparse") for key in member.pax_headers)
            or "/" in member.name
        ):
            raise SourcesError(f"{description} member {member.name} is not a plain regular file")
    return archive, members


def read_member(archive: tarfile.TarFile, member: tarfile.TarInfo, limit: int, description: str) -> bytes:
    if member.size > limit:
        raise SourcesError(f"{description} member {member.name} exceeds {limit} bytes")
    stream = archive.extractfile(member)
    if stream is None:
        raise SourcesError(f"{description} member {member.name} is not a regular file")
    content = stream.read(member.size + 1)
    if len(content) != member.size:
        raise SourcesError(f"{description} member {member.name} does not hold its recorded length")
    return content


def read_pkginfo(content: bytes, description: str) -> dict[str, str]:
    """Read .PKGINFO from an APK's control segment.

    The signature segment is checked for shape only: one plain member named
    for the pinned Alpine key, of bounded size. This function does not verify
    the RSA signature; apk add does that during the image build.
    """
    signature, control = gzip_members(content, 2, MAX_CONTROL_BYTES, description)
    signature_tar, signature_members = plain_members(signature, f"{description} signature segment")
    if [m.name for m in signature_members] != [SIGNATURE_MEMBER]:
        raise SourcesError(f"{description} signature member is not named for the pinned Alpine key")
    read_member(signature_tar, signature_members[0], MAX_SIGNATURE_BYTES, f"{description} signature segment")
    control_tar, control_members = plain_members(control, f"{description} control segment")
    pkginfo = [m for m in control_members if m.name == ".PKGINFO"]
    if len(pkginfo) != 1:
        raise SourcesError(f"{description} control segment does not hold exactly one .PKGINFO")
    try:
        text = read_member(control_tar, pkginfo[0], MAX_PKGINFO_BYTES, f"{description} control segment").decode("utf-8")
    except UnicodeDecodeError as error:
        raise SourcesError(f"{description} .PKGINFO is not UTF-8") from error
    fields: dict[str, list[str]] = {}
    abuild = None
    for line in text.splitlines():
        if line.startswith("# Generated by abuild "):
            abuild = line.removeprefix("# Generated by abuild ").strip()
        if line.startswith("#") or " = " not in line:
            continue
        key, value = line.split(" = ", 1)
        fields.setdefault(key, []).append(value)
    info = {}
    for key in ("pkgname", "pkgver", "origin", "commit", "license"):
        values = fields.get(key, [])
        if len(values) != 1:
            raise SourcesError(f"{description} .PKGINFO does not name exactly one {key}")
        info[key] = values[0]
    if abuild is None:
        raise SourcesError(f"{description} .PKGINFO does not name its abuild revision")
    info["abuild"] = abuild
    return info


def apkbuild_fields(text: str, description: str) -> tuple[str, dict[str, str], str]:
    pkgver = re.findall(r"^pkgver=([^\s#\"'$]+)[ \t]*(?:#.*)?$", text, re.M)
    pkgrel = re.findall(r"^pkgrel=([0-9]+)[ \t]*(?:#.*)?$", text, re.M)
    blocks = re.findall(r"^sha512sums=([\"'])(.*?)\1[ \t]*$", text, re.M | re.S)
    licenses = re.findall(r"^license=([\"'])(.*?)\1[ \t]*(?:#.*)?$", text, re.M | re.S)
    if len(pkgver) != 1 or len(pkgrel) != 1 or len(blocks) > 1 or len(licenses) != 1 or "$" in licenses[0][1]:
        raise SourcesError(f"{description} does not give a literal pkgver, pkgrel, license and sha512sums")
    sums: dict[str, str] = {}
    for line in (blocks[0][1] if blocks else "").splitlines():
        line = line.strip()
        if not line:
            continue
        match = APKBUILD_SUM.fullmatch(line)
        if match is None or match.group(2) in sums:
            raise SourcesError(f"{description} sha512sums block is not literal")
        sums[match.group(2)] = match.group(1)
    return f"{pkgver[0]}-r{pkgrel[0]}", sums, licenses[0][1]


class Unexpanded(Exception):
    """A shell construct the static source expansion does not evaluate."""


ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
REFERENCE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)((?:%%|%|##|#|//|/)[^}]*)?\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def glob_regex(pattern: str) -> str:
    out = []
    for char in pattern:
        out.append(".*" if char == "*" else "." if char == "?" else re.escape(char))
    if any(c in pattern for c in "[]\\"):
        raise Unexpanded(pattern)
    return "".join(out)


def expand(value: str, variables: dict[str, str]) -> str:
    """Expand $name, ${name} and ${name%pat}, %%, #, ##, /pat/rep, //pat/rep; anything else is Unexpanded."""
    if "$(" in value or "`" in value or "$((" in value:
        raise Unexpanded(value)

    def substitute(match: re.Match) -> str:
        name = match.group(1) or match.group(3)
        if name not in variables:
            raise Unexpanded(name)
        current = variables[name]
        operation = match.group(2)
        if not operation:
            return current
        for op in ("%%", "##", "//", "%", "#", "/"):
            if operation.startswith(op):
                argument = operation[len(op):]
                break
        if "$" in argument:
            raise Unexpanded(argument)
        if op in ("%", "%%"):
            regex = glob_regex(argument)
            candidates = [i for i in range(len(current) + 1) if re.fullmatch(regex, current[i:], re.S)]
            if not candidates:
                return current
            return current[: (max(candidates) if op == "%" else min(candidates))]
        if op in ("#", "##"):
            regex = glob_regex(argument)
            candidates = [i for i in range(len(current) + 1) if re.fullmatch(regex, current[:i], re.S)]
            if not candidates:
                return current
            return current[(min(candidates) if op == "#" else max(candidates)):]
        pattern, _, replacement = argument.partition("/")
        if any(c in pattern for c in "*?["):
            raise Unexpanded(argument)
        return current.replace(pattern, replacement) if op == "//" else current.replace(pattern, replacement, 1)

    expanded = REFERENCE.sub(substitute, value)
    if "$" in expanded:
        raise Unexpanded(value)
    return expanded


def static_sources(text: str) -> dict[str, str]:
    """Map source file names to the URLs the APKBUILD's top-level source= block names.

    Only the first top-level source="..." block is read, with variables from
    top-level literal assignments that precede it. Entries added later (in
    loops or conditionals) and entries whose expansion needs anything beyond
    plain parameter expansion are absent from the result.
    """
    variables: dict[str, str] = {}
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        match = ASSIGNMENT.match(line)
        if match and match.group(1) == "source":
            body = match.group(2)
            if not body.startswith('"'):
                return {}
            body = body[1:]
            while '"' not in body and index + 1 < len(lines):
                index += 1
                body += "\n" + lines[index]
            body = body[: body.index('"')]
            found = {}
            for token in body.split():
                try:
                    expanded = expand(token, variables)
                except Unexpanded:
                    continue
                name, separator, url = expanded.partition("::")
                if not separator:
                    url, name = expanded, expanded.rsplit("/", 1)[-1]
                if "://" in url:
                    found[name] = url
            return found
        if match and not line.startswith((" ", "\t")):
            value = match.group(2).split(" #", 1)[0].strip()
            quote = value[:1] if value[:1] in "\"'" else ""
            if quote and (len(value) < 2 or value[-1] != quote):
                variables.pop(match.group(1), None)
                index += 1
                continue
            if quote:
                value = value[1:-1]
            try:
                variables[match.group(1)] = value if quote == "'" else expand(value, variables)
            except Unexpanded:
                variables.pop(match.group(1), None)
        index += 1
    return {}


def license_tokens(expression: str) -> set[str]:
    return {token for token in LICENSE_TOKEN.findall(expression) if token not in LICENSE_OPERATORS}


class Context:
    def __init__(self, tree: Tree, max_file_bytes: int):
        self.tree = tree
        self.max_file_bytes = max_file_bytes
        self.files: dict[str, tuple[int, str, str]] = {}
        self.referenced: set[str] = {"MANIFEST.json"}
        self.chunk_targets: dict[str, tuple] = {}
        self.chunk_files: dict[str, list[str]] = {}
        self.archive_members: dict[str, dict[str, list[dict]]] = {}
        self.streamed = 0

    def reference(self, path: object, description: str) -> str:
        if not isinstance(path, str) or path not in self.files:
            raise SourcesError(f"{description} names a file outside SHA256SUMS: {path}")
        self.referenced.add(path)
        return path

    def check_file(self, entry: dict, description: str) -> str:
        path = self.reference(entry.get("path"), description)
        length, sha256, _sha512 = self.files[path]
        if entry.get("sha256") != sha256 or entry.get("length") != length:
            raise SourcesError(f"{description} digest differs from {path}")
        return path

    def read(self, path: str) -> bytes:
        return self.tree.read(f"{SOURCES}/{path}", self.max_file_bytes, f"corresponding-source file {path}")


def git_object(context: Context, object_id: object, kind: str, description: str) -> bytes:
    if not isinstance(object_id, str) or not HEX40.fullmatch(object_id):
        raise SourcesError(f"{description} names no git object id")
    path = context.reference(f"aports-objects/{object_id}", f"{description} git {kind}")
    content = context.read(path)
    if hashlib.sha1(f"{kind} {len(content)}".encode() + b"\0" + content).hexdigest() != object_id:
        raise SourcesError(f"{description} git {kind} {object_id} does not hash to its id")
    return content


def tree_entries(content: bytes, description: str) -> dict[str, tuple[str, str]]:
    entries: dict[str, tuple[str, str]] = {}
    offset = 0
    while offset < len(content):
        space = content.find(b" ", offset)
        nul = content.find(b"\0", space + 1)
        if space < 0 or nul < 0 or nul + 21 > len(content):
            raise SourcesError(f"{description} is not a git tree")
        mode = content[offset:space].decode("ascii")
        name = content[space + 1:nul].decode("utf-8")
        if name in entries:
            raise SourcesError(f"{description} repeats {name}")
        entries[name] = (mode, content[nul + 1:nul + 21].hex())
        offset = nul + 21
    return entries


def verify_membership(context: Context, entry: dict, directory: list[str], blobs: dict[str, tuple[str, str]],
                      description: str) -> None:
    """Prove the recipe files are exactly the blobs of <directory> at the aports commit.

    Walks retained raw git objects from the commit id (which the archives'
    .PKGINFO name) through the root tree and each directory tree, checking
    every object against its id. A git symlink (mode 120000) is kept as the
    blob git stores for it, the link target text, and recorded with its mode.
    """
    proof = entry.get("aports_proof")
    if not isinstance(proof, dict) or set(proof) != {"trees"} or not isinstance(proof["trees"], list):
        raise SourcesError(f"{description} has no aports tree proof")
    commit = git_object(context, entry["aports_commit"], "commit", description)
    match = re.match(rb"tree ([0-9a-f]{40})\n", commit)
    if match is None or len(proof["trees"]) != len(directory) + 1 or proof["trees"][0] != match.group(1).decode():
        raise SourcesError(f"{description} aports tree proof does not start at the commit's tree")
    for depth, name in enumerate(directory):
        entries = tree_entries(git_object(context, proof["trees"][depth], "tree", description), description)
        if entries.get(name) != ("40000", proof["trees"][depth + 1]):
            raise SourcesError(f"{description} aports tree proof does not reach {'/'.join(directory[:depth + 1])}")
    leaf = tree_entries(git_object(context, proof["trees"][-1], "tree", description), description)
    if any(mode not in GIT_FILE_MODES for mode, _object_id in leaf.values()):
        raise SourcesError(f"{description} aports directory holds an entry that is not a file or symlink")
    if leaf != blobs:
        raise SourcesError(f"{description} recipe files are not the blobs of {'/'.join(directory)} at the aports commit")


def validate_recipe(context: Context, entry: dict, prefix: str, aports_prefix: str,
                    version: str, description: str, vendored_prefix: str) -> None:
    commit = entry.get("aports_commit")
    if not isinstance(commit, str) or not HEX40.fullmatch(commit):
        raise SourcesError(f"{description} has no exact aports commit")
    recipe = entry.get("recipe")
    if not isinstance(recipe, list) or not recipe:
        raise SourcesError(f"{description} has no recipe files")
    paths = []
    apkbuild = None
    for item in recipe:
        path = context.check_file(item, f"{description} recipe file")
        if not path.startswith(prefix) or item.get("aports_path") != aports_prefix + path[len(prefix):]:
            raise SourcesError(f"{description} recipe file is outside its aports directory: {path}")
        content = context.read(path)
        if item.get("git_blob_sha1") != git_blob_id(content):
            raise SourcesError(f"{description} recipe file differs from its aports blob: {path}")
        paths.append(path)
        if path == prefix + "APKBUILD":
            apkbuild = content
    present = sorted(p for p in context.files if p.startswith(prefix))
    if sorted(paths) != present or len(set(paths)) != len(paths):
        raise SourcesError(f"{description} recipe directory does not match its manifest")
    if apkbuild is None:
        raise SourcesError(f"{description} recipe has no APKBUILD")
    if any(item.get("git_mode") not in GIT_FILE_MODES for item in recipe):
        raise SourcesError(f"{description} recipe file has no git file mode")
    verify_membership(context, entry, aports_prefix.rstrip("/").split("/"),
                      {item["path"][len(prefix):]: (item["git_mode"], item["git_blob_sha1"]) for item in recipe},
                      description)
    try:
        text = apkbuild.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SourcesError(f"{description} APKBUILD is not text") from error
    recipe_version, sums, raw_license = apkbuild_fields(text, f"{description} APKBUILD")
    if recipe_version != version:
        raise SourcesError(f"{description} APKBUILD version {recipe_version} is not {version}")
    if entry.get("license") != raw_license:
        raise SourcesError(f"{description} license is not the APKBUILD license field as written")
    sources = entry.get("sources")
    if not isinstance(sources, list):
        raise SourcesError(f"{description} has no source list")
    names = [s.get("name") for s in sources if isinstance(s, dict)]
    if len(names) != len(sources) or sorted(names) != sorted(sums) or len(set(names)) != len(names):
        raise SourcesError(f"{description} sources differ from the APKBUILD sha512sums block")
    expanded = static_sources(text)
    for source in sources:
        name = source["name"]
        if source.get("sha512") != sums[name]:
            raise SourcesError(f"{description} source {name} sha512 differs from the APKBUILD")
        if source.get("kind") == "upstream":
            status = "expanded" if name in expanded else "not-expanded"
            if source.get("url_check") != status:
                raise SourcesError(f"{description} source {name} url_check is not {status}")
            if status == "expanded" and source.get("url") != expanded[name]:
                raise SourcesError(f"{description} source {name} url differs from the APKBUILD source= entry")
        kind = source.get("kind")
        if kind == "aports":
            path = context.reference(source.get("path"), f"{description} source {name}")
            if path != prefix + name or context.files[path][2] != sums[name]:
                raise SourcesError(f"{description} recipe file {name} does not match the APKBUILD sha512")
        elif kind == "upstream":
            if not isinstance(source.get("url"), str) or "://" not in source["url"]:
                raise SourcesError(f"{description} source {name} has no upstream URL")
            path, chunks = source.get("path"), source.get("chunks")
            if (path is None) == (chunks is None):
                raise SourcesError(f"{description} upstream source {name} is not vendored exactly once")
            if path is not None:
                context.check_file(source, f"{description} source {name}")
                if path != vendored_prefix + name or context.files[path][2] != sums[name]:
                    raise SourcesError(f"{description} upstream source {name} does not match the APKBUILD sha512")
            else:
                context.reference(chunks, f"{description} source {name} reconstruction manifest")
                context.chunk_targets[chunks] = (name, sums[name], source.get("sha256"), source.get("length"),
                                                 vendored_prefix)
        else:
            raise SourcesError(f"{description} source {name} has an unknown kind")


NOTICE_KEYS = frozenset({"path", "from_source", "from_member", "extract", "sha256", "length"})


def validate_notices(context: Context, entry: dict, origin: str) -> None:
    """Bind each notice to a member of a named upstream source.

    A notice is a whole archive member ("member"), the leading bytes of one
    ("prefix"), or a whole source file that is itself a notice ("file", for
    example sqlite's LICENSE.md). Every upstream source is vendored, so a
    "file" notice must be that source's bytes, and the archive of any other
    notice is streamed later, where the member must exist exactly once as a
    plain regular file whose bytes match. An origin may have no notice only
    when it has no upstream source at all.
    """
    description = f"origin {origin}"
    notices = entry.get("notices")
    if not isinstance(notices, list):
        raise SourcesError(f"{description} has no notice list")
    if "notices_absent_reason" in entry:
        raise SourcesError(f"{description} carries a free-text notice absence reason")
    upstream = {s["name"]: s for s in entry["sources"] if s.get("kind") == "upstream"}
    for notice in notices:
        if not isinstance(notice, dict) or set(notice) != NOTICE_KEYS:
            raise SourcesError(f"{description} notice record is not exact")
        path = context.check_file(notice, f"{description} notice")
        source = upstream.get(notice["from_source"])
        member = notice["from_member"]
        if source is None:
            raise SourcesError(f"{description} notice {path} names a source the origin does not have")
        if (
            not path.startswith(f"licenses/{origin}/")
            or not isinstance(member, str)
            or not member
            or member.startswith("/")
            or ".." in member.split("/")
            or notice["extract"] not in ("member", "prefix", "file")
            or (notice["extract"] == "file") != (member == notice["from_source"])
        ):
            raise SourcesError(f"{description} notice {path} does not name a plain member")
        if notice["extract"] == "file":
            if (notice["sha256"], notice["length"]) != (source.get("sha256"), source.get("length")):
                raise SourcesError(f"{description} notice {path} is not the whole source {member}")
        else:
            vendored = source.get("path") or source.get("chunks")
            context.archive_members.setdefault(vendored, {}).setdefault(member, []).append(notice)
    paths = [n["path"] for n in notices]
    if sorted(paths) != sorted(p for p in context.files if p.startswith(f"licenses/{origin}/")):
        raise SourcesError(f"{description} notice directory does not match its manifest")
    if not notices:
        if entry.get("notices_absent") != "no-upstream-source" or upstream:
            raise SourcesError(f"{description} has no notice file and does not lack upstream source")
    elif "notices_absent" in entry:
        raise SourcesError(f"{description} records notices and a notice absence")


class ChainReader(io.RawIOBase):
    """Reads several descriptors as one stream (a split archive's chunks in order)."""

    def __init__(self, descriptors: list[int]):
        self.descriptors = descriptors
        self.index = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        while self.index < len(self.descriptors):
            data = os.read(self.descriptors[self.index], len(buffer))
            if data:
                buffer[: len(data)] = data
                return len(data)
            self.index += 1
        return 0

    def close(self) -> None:
        for descriptor in self.descriptors:
            os.close(descriptor)
        self.descriptors = []
        super().close()


def open_retained(context: Context, retained: str) -> io.BufferedReader:
    paths = context.chunk_files[retained] if retained in context.chunk_files else [retained]
    descriptors = []
    try:
        for path in paths:
            descriptors.append(context.tree.open(f"{SOURCES}/{path}", f"corresponding-source file {path}"))
    except SourcesError:
        for descriptor in descriptors:
            os.close(descriptor)
        raise
    return io.BufferedReader(ChainReader(descriptors), 1 << 20)


ATTRIBUTION_METHOD = {
    "id": "chio.attribution-lines.v8",
    "scope": "every regular member of each upstream tar archive (reading every gzip member, xz stream and bzip2 "
             "stream of the source), each upstream file that is not a tar archive (as one file), and each "
             "Alpine-local source file of the origin, each read to its end",
    "binary_probe_bytes": 8192,
    "read_block_bytes": 1048576,
    "max_line_bytes": 1048576,
    "max_member_bytes": 67108864,
    "max_source_bytes": 2147483648,
    "max_total_bytes": 8589934592,
    "marker": "(?i)copyright|\\(c\\)[ \\t]{0,64}(?:19|20)\\d\\d|\\u00a9",
    "line": "the exact bytes of every line (split on LF) that contains the marker",
    "field": "escape_field: UTF-8 text as written, except that a backslash, tab, CR or LF becomes \\\\, \\t, "
             "\\r or \\n, and a byte that is not UTF-8, each byte of a character in ESCAPED_CODE_POINTS (C0 and "
             "C1 controls, DEL, non-space separators, every Unicode 15.1 format character (category Cf, which "
             "includes the bidirectional controls), surrogates, "
             "noncharacters) and a trailing space become \\xNN; the set is fixed here, not taken from the "
             "interpreter's Unicode database; unescape_field restores the exact bytes",
    "gaps": "a file whose first binary_probe_bytes hold a NUL byte is not scanned and is listed as a binary head; "
            "a file over max_member_bytes is not scanned and is listed as over the member limit; a line longer "
            "than max_line_bytes is not recorded, and when it carries the marker (searched across the whole line, "
            "including the part not held) its file is listed with the number of such lines; a member that holds "
            "data but is not a "
            "plain regular file (sparse, or of an unknown type) is not scanned and is listed as an unscanned "
            "member; a source whose decompressed stream holds anything but zero bytes after its tar archive ends, "
            "or that holds anything after an xz stream but stream padding (zero bytes, a multiple of four) and "
            "further streams, or anything after a bzip2 stream but further streams, "
            "a source over max_source_bytes, or a closure over max_total_bytes (the sizes of all members "
            "streamed) fails the check",
}
ATTRIBUTION_MARK = re.compile(rb"(?i)copyright|\(c\)[ \t]{0,64}(?:19|20)\d\d|\xc2\xa9")
MARK_SPAN = 128
ATTRIBUTION_KEYS = frozenset({"status", "path", "sha256", "length"})
FIELD_ESCAPES = {"\\": "\\\\", "\t": "\\t", "\r": "\\r", "\n": "\\n"}
ESCAPED_CODE_POINTS = (
    (0x0000, 0x001F), (0x007F, 0x00A0), (0x00AD, 0x00AD), (0x0600, 0x0605), (0x061C, 0x061C),
    (0x06DD, 0x06DD), (0x070F, 0x070F), (0x0890, 0x0891), (0x08E2, 0x08E2), (0x1680, 0x1680),
    (0x180E, 0x180E), (0x2000, 0x200F), (0x2028, 0x202F), (0x205F, 0x206F), (0x3000, 0x3000),
    (0xD800, 0xDFFF), (0xFDD0, 0xFDEF), (0xFEFF, 0xFEFF), (0xFFF9, 0xFFFB), (0x110BD, 0x110BD),
    (0x110CD, 0x110CD), (0x13430, 0x1343F), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A), (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
)


def escaped_code_point(code: int) -> bool:
    return (code & 0xFFFE) == 0xFFFE or any(low <= code <= high for low, high in ESCAPED_CODE_POINTS)
FIELD_UNESCAPES = {"\\": b"\\", "t": b"\t", "r": b"\r", "n": b"\n"}
HEX2 = re.compile(r"[0-9a-f]{2}")


def escape_field(raw: bytes) -> str:
    """Write bytes as one TSV field holding no tab, CR, LF or trailing space; unescape_field inverts it."""
    out = []
    for char in raw.decode("utf-8", "surrogateescape"):
        code = ord(char)
        if 0xDC80 <= code <= 0xDCFF:
            out.append(f"\\x{code - 0xDC00:02x}")
        elif char in FIELD_ESCAPES:
            out.append(FIELD_ESCAPES[char])
        elif escaped_code_point(code):
            out.extend(f"\\x{byte:02x}" for byte in char.encode("utf-8", "surrogatepass"))
        else:
            out.append(char)
    text = "".join(out)
    kept = text.rstrip(" ")
    return kept + "\\x20" * (len(text) - len(kept))


def unescape_field(text: str) -> bytes:
    out = bytearray()
    index = 0
    while index < len(text):
        char = text[index]
        if char != "\\":
            out += char.encode("utf-8")
            index += 1
        elif text[index + 1:index + 2] in FIELD_UNESCAPES:
            out += FIELD_UNESCAPES[text[index + 1]]
            index += 2
        elif text[index + 1:index + 2] == "x" and HEX2.fullmatch(text[index + 2:index + 4]):
            out.append(int(text[index + 2:index + 4], 16))
            index += 4
        else:
            raise SourcesError("attribution field holds an unknown escape")
    return bytes(out)


class Prefixed:
    """Yields bytes already read from a stream, then the rest of that stream."""

    def __init__(self, head: bytes, rest):
        self.head = head
        self.rest = rest

    def read(self, size: int) -> bytes:
        if self.head:
            piece, self.head = self.head[:size], self.head[size:]
            return piece
        return self.rest.read(size)


class Attribution:
    """Distinct copyright/attribution lines, as exact bytes, in the whole of an origin's source files."""

    def __init__(self):
        self.lines: dict[bytes, list] = {}
        self.files = 0
        self.with_lines = 0
        self.binary: list[str] = []
        self.oversized: list[str] = []
        self.unscanned: list[str] = []
        self.long_lines: dict[str, int] = {}

    def unscanned_member(self, label: str) -> None:
        self.files += 1
        self.unscanned.append(escape_field(label.encode("utf-8", "surrogateescape")))

    def collect(self, region: bytes, label: str) -> tuple[bool, int]:
        """Record the marked lines of a region that ends at a line end; returns (found, marked long lines)."""
        found, long_lines, last = False, 0, -1
        for match in ATTRIBUTION_MARK.finditer(region):
            start = region.rfind(b"\n", 0, match.start()) + 1
            if start == last:
                continue
            last = start
            end = region.find(b"\n", match.end())
            line = region[start:len(region) if end < 0 else end]
            if len(line) > ATTRIBUTION_METHOD["max_line_bytes"]:
                long_lines += 1
                continue
            self.lines.setdefault(line, [0, label])[0] += 1
            found = True
        return found, long_lines

    def scan(self, label: str, stream, size: int) -> None:
        """Scan one file of the given size from its stream to its end.

        At most max_line_bytes of an unfinished line are held. Past that the
        line is only searched for the marker, piece by piece with an overlap
        of MARK_SPAN bytes, so whether a long line is listed depends on its
        content alone, not on how its bytes arrive.
        """
        method = ATTRIBUTION_METHOD
        label = escape_field(label.encode("utf-8", "surrogateescape"))
        self.files += 1
        if size > method["max_member_bytes"]:
            self.oversized.append(label)
            return
        head = b""
        while len(head) < method["binary_probe_bytes"]:
            block = stream.read(method["read_block_bytes"])
            if not block:
                break
            head += block
        if b"\0" in head[: method["binary_probe_bytes"]]:
            self.binary.append(label)
            return
        found, long_lines, carry, skipping, skipped_marked, pending = False, 0, b"", False, False, head
        while True:
            block, pending = (pending, b"") if pending else (stream.read(method["read_block_bytes"]), b"")
            if not block:
                break
            data = carry + block
            if skipping:
                newline = data.find(b"\n")
                skipped_marked = skipped_marked or bool(ATTRIBUTION_MARK.search(data if newline < 0 else data[:newline]))
                if newline < 0:
                    carry = data[-MARK_SPAN:]
                    continue
                long_lines += skipped_marked
                data, skipping, skipped_marked = data[newline + 1:], False, False
            cut = data.rfind(b"\n") + 1
            marked, long_marked = self.collect(data[:cut], label)
            found, long_lines, carry = found or marked, long_lines + long_marked, data[cut:]
            if len(carry) > method["max_line_bytes"]:
                skipping, skipped_marked, carry = True, bool(ATTRIBUTION_MARK.search(carry)), carry[-MARK_SPAN:]
        if skipping:
            long_lines += skipped_marked
        elif carry:
            marked, long_marked = self.collect(carry, label)
            found, long_lines = found or marked, long_lines + long_marked
        if long_lines:
            self.long_lines[label] = self.long_lines.get(label, 0) + long_lines
        self.with_lines += found

    def render(self, origin: str) -> bytes:
        rows = [f"# {ATTRIBUTION_METHOD['id']} origin={origin} files={self.files} files_with_lines={self.with_lines} "
                f"binary_heads={len(self.binary)} over_member_limit={len(self.oversized)} "
                f"unscanned_members={len(self.unscanned)} files_with_long_lines={len(self.long_lines)}\n"]
        for line, (count, first) in sorted(self.lines.items()):
            rows.append(f"line\t{count}\t{first}\t{escape_field(line)}\n")
        rows.extend(f"binary-head\t{label}\n" for label in sorted(self.binary))
        rows.extend(f"over-member-limit\t{label}\n" for label in sorted(self.oversized))
        rows.extend(f"unscanned-member\t{label}\n" for label in sorted(self.unscanned))
        rows.extend(f"long-lines\t{count}\t{label}\n" for label, count in sorted(self.long_lines.items()))
        return "".join(rows).encode()


DATALESS_TYPES = frozenset({tarfile.DIRTYPE, tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE,
                            tarfile.FIFOTYPE})
TAIL_BYTES = 65536


def plain_member(member: tarfile.TarInfo) -> bool:
    return (
        member.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.CONTTYPE)
        and not member.issparse()
        and not any(key.startswith("GNU.sparse") for key in member.pax_headers)
    )


STREAM_MAGIC = {"xz": b"\xfd7zXZ\x00", "bzip2": b"BZh"}


class Streams(io.RawIOBase):
    """Decodes every concatenated xz or bzip2 stream of a source in turn.

    After an xz stream only stream padding (zero bytes, a multiple of four)
    and further streams may follow; after a bzip2 stream only further
    streams. Anything else is refused rather than skipped, so bytes after a
    stream cannot hide a later one.
    """

    def __init__(self, raw, kind: str):
        self.raw = raw
        self.kind = kind
        self.decoder = self.start()
        self.input = b""
        self.done = False

    def start(self):
        return lzma.LZMADecompressor(lzma.FORMAT_XZ) if self.kind == "xz" else bz2.BZ2Decompressor()

    def readable(self) -> bool:
        return True

    def more(self) -> bool:
        chunk = self.raw.read(1 << 16)
        self.input += chunk
        return bool(chunk)

    def next_stream(self) -> None:
        padding = 0
        while self.input or self.more():
            if self.kind == "xz":
                kept = self.input.lstrip(b"\0")
                padding += len(self.input) - len(kept)
                self.input = kept
            if self.input:
                break
        if padding % 4:
            raise SourcesError(f"{self.kind} stream padding is not a multiple of four bytes")
        if not self.input:
            self.done = True
            return
        magic = STREAM_MAGIC[self.kind]
        while len(self.input) < len(magic) and self.more():
            continue
        if not self.input.startswith(magic):
            raise SourcesError(f"{self.kind} source holds data after a stream that is not another stream")
        self.decoder = self.start()

    def readinto(self, buffer) -> int:
        while not self.done:
            if self.decoder.eof:
                self.input = self.decoder.unused_data + self.input
                self.next_stream()
                continue
            if self.decoder.needs_input:
                if not self.input and not self.more():
                    raise SourcesError(f"{self.kind} source ends inside a stream")
                data, self.input = self.decoder.decompress(self.input, len(buffer)), b""
            else:
                data = self.decoder.decompress(b"", len(buffer))
            if data:
                buffer[: len(data)] = data
                return len(data)
        return 0


def decompressed(stream: io.BufferedReader):
    """The whole decompressed content of a source: every gzip member, xz stream or bzip2 stream in turn."""
    magic = stream.peek(6)[:6]
    if magic.startswith(b"\x1f\x8b"):
        return gzip.GzipFile(fileobj=stream, mode="rb")
    for kind, prefix in STREAM_MAGIC.items():
        if magic.startswith(prefix):
            return Streams(stream, kind)
    return stream


class Tracked(io.RawIOBase):
    """Passes a stream through, counting its bytes and holding the most recent ones."""

    def __init__(self, raw):
        self.raw = raw
        self.delivered = 0
        self.recent: deque[bytes] = deque()
        self.held = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        data = self.raw.read(len(buffer))
        buffer[: len(data)] = data
        self.delivered += len(data)
        self.recent.append(data)
        self.held += len(data)
        while self.held - len(self.recent[0]) >= TAIL_BYTES:
            self.held -= len(self.recent.popleft())
        return len(data)

    def since(self, offset: int, description: str) -> bytes:
        count = self.delivered - offset
        if not 0 <= count <= self.held:
            raise SourcesError(f"{description} ends its tar archive outside the bytes still held")
        return b"".join(self.recent)[self.held - count:]


def account(context: Context, retained: str, source_bytes: int, size: int) -> int:
    """Charge one streamed file against the per-source and closure limits of the attribution scan."""
    context.streamed += size
    source_bytes += size
    if source_bytes > ATTRIBUTION_METHOD["max_source_bytes"] or context.streamed > ATTRIBUTION_METHOD["max_total_bytes"]:
        raise SourcesError(f"{retained} exceeds the attribution scan byte limits")
    return source_bytes


def scan_retained(context: Context, retained: str, name: str, attribution: Attribution) -> None:
    """Stream one vendored source once: verify its notice members and scan every regular member to its end.

    The source is decompressed as a whole (all of its gzip members, xz streams
    or bzip2 streams). After the tar archive ends, the rest of the decompressed
    stream must hold only zero bytes, so a stop of the tar reader cannot hide
    a later member.
    """
    wanted = context.archive_members.get(retained, {})
    seen: set[str] = set()
    source_bytes = 0
    stream = open_retained(context, retained)
    try:
        tracked = Tracked(decompressed(stream))
        try:
            archive = tarfile.open(fileobj=tracked, mode="r|")
        except tarfile.ReadError:
            archive = None
        if archive is None:
            if wanted:
                raise SourcesError(f"{retained} is not a tar archive but notices name members of it")
            stream.close()
            stream = open_retained(context, retained)
            size = sum(os.fstat(descriptor).st_size for descriptor in stream.raw.descriptors)
            account(context, retained, source_bytes, size)
            attribution.scan(name, stream, size)
            return
        with archive:
            for member in archive:
                source_bytes = account(context, retained, source_bytes, max(member.size, 0))
                if member.name in wanted:
                    if member.name in seen:
                        raise SourcesError(f"{retained} holds {member.name} more than once")
                    seen.add(member.name)
                    if not plain_member(member):
                        raise SourcesError(f"{retained} member {member.name} is not a plain regular file")
                if not plain_member(member):
                    if member.type not in DATALESS_TYPES:
                        attribution.unscanned_member(f"{name}:{member.name}")
                    continue
                records = wanted.get(member.name, [])
                need = max([0, *(member.size if r["extract"] == "member" else r["length"] for r in records)])
                if need > MAX_NOTICE_BYTES:
                    raise SourcesError(f"{retained} member {member.name} exceeds {MAX_NOTICE_BYTES} bytes")
                handle = archive.extractfile(member)
                if handle is None:
                    raise SourcesError(f"{retained} member {member.name} is not readable")
                data = handle.read(need) if need else b""
                for record in records:
                    exact = record["extract"] == "member"
                    piece = data[: member.size] if exact else data[: record["length"]]
                    if (
                        (exact and member.size != record["length"])
                        or len(piece) != record["length"]
                        or hashlib.sha256(piece).hexdigest() != record["sha256"]
                    ):
                        raise SourcesError(f"notice {record['path']} does not match {member.name} in {retained}")
                attribution.scan(f"{name}:{member.name}", Prefixed(data, handle), member.size)
            rest = tracked.since(archive.offset, retained)
            while rest:
                if rest.strip(b"\0"):
                    raise SourcesError(f"{retained} holds data after the end of its tar archive")
                rest = tracked.raw.read(ATTRIBUTION_METHOD["read_block_bytes"])
    except (tarfile.TarError, OSError, EOFError, lzma.LZMAError, zlib.error) as error:
        raise SourcesError(f"{retained} is not a readable source archive") from error
    finally:
        stream.close()
    missing = sorted(set(wanted) - seen)
    if missing:
        raise SourcesError(f"notice member {missing[0]} is not a member of {retained}")


def verify_attributions(context: Context, manifest: dict) -> int:
    """Re-derive each origin's attribution inventory from its vendored sources.

    An origin with no upstream source has no inventory. Every other origin's
    inventory is re-derived here, byte for byte, in the same pass over its
    vendored sources that checks their notice members. Returns the number of
    inventories re-derived.
    """
    if manifest.get("attribution_method") != ATTRIBUTION_METHOD:
        raise SourcesError("corresponding-source attribution method is not the checker's")
    scanned: set[str] = set()
    derived = 0
    for entry in manifest["origins"]:
        origin = entry["origin"]
        record = entry.get("attribution")
        upstream = [s for s in entry["sources"] if s.get("kind") == "upstream"]
        if not isinstance(record, dict):
            raise SourcesError(f"origin {origin} has no attribution record")
        if not upstream:
            if entry["source_obligation"]:
                raise SourcesError(f"origin {origin} ships a copyleft archive but has no upstream source")
            if record != {"status": "no-upstream-source"}:
                raise SourcesError(f"origin {origin} attribution record is not no-upstream-source")
            continue
        path = f"attributions/{origin}.tsv"
        if set(record) != ATTRIBUTION_KEYS or record["status"] != "derived" or record["path"] != path:
            raise SourcesError(f"origin {origin} attribution record is not a derived inventory at {path}")
        context.check_file(record, f"origin {origin} attribution inventory")
        attribution = Attribution()
        for source in sorted(entry["sources"], key=lambda s: s["name"]):
            if source["kind"] == "aports":
                content = context.read(source["path"])
                account(context, source["path"], 0, len(content))
                attribution.scan(f"recipe:{source['name']}", io.BytesIO(content), len(content))
            else:
                vendored = source.get("path") or source["chunks"]
                scan_retained(context, vendored, source["name"], attribution)
                scanned.add(vendored)
        if context.read(path) != attribution.render(origin):
            raise SourcesError(f"origin {origin} attribution inventory differs from its vendored sources")
        derived += 1
    unread = sorted(set(context.archive_members) - scanned)
    if unread:
        raise SourcesError(f"notices name members of {unread[0]}, which no attribution pass read")
    return derived


def validate_chunks(context: Context, manifest: dict) -> int:
    declared = manifest.get("chunked")
    if not isinstance(declared, list):
        raise SourcesError("corresponding-source manifest has no chunk list")
    by_path = {}
    for item in declared:
        if not isinstance(item, dict) or item.get("reconstruction_manifest") in by_path:
            raise SourcesError("corresponding-source chunk list is not exact")
        by_path[item.get("reconstruction_manifest")] = item
    if set(by_path) != set(context.chunk_targets):
        raise SourcesError("corresponding-source chunk list does not match the split sources")
    for path, (name, sha512, sha256, length, prefix) in sorted(context.chunk_targets.items()):
        item = by_path[path]
        try:
            document = json.loads(context.read(path))
        except json.JSONDecodeError as error:
            raise SourcesError(f"reconstruction manifest {path} is not JSON") from error
        base = path.rsplit("/", 1)[0] + "/"
        if (
            document.get("schema") != CHUNK_SCHEMA
            or document.get("name") != name
            or path != f"{prefix}{name}.chunks.json"
            or document.get("sha512") != sha512
            or document.get("sha256") != sha256
            or document.get("length") != length
            or item.get("name") != name
            or item.get("sha512") != sha512
            or item.get("sha256") != sha256
            or item.get("length") != length
            or document.get("chunks") != item.get("chunks")
        ):
            raise SourcesError(f"reconstruction manifest {path} does not bind {name}")
        chunks = document["chunks"]
        if not isinstance(chunks, list) or len(chunks) < 2:
            raise SourcesError(f"reconstruction manifest {path} has no chunk sequence")
        offset = 0
        whole256 = hashlib.sha256()
        whole512 = hashlib.sha512()
        for index, chunk in enumerate(chunks, start=1):
            if not isinstance(chunk, dict) or chunk.get("offset") != offset:
                raise SourcesError(f"reconstruction manifest {path} chunk {index} is out of order")
            chunk_path = base + str(chunk.get("path"))
            if chunk.get("path") != f"{name}.part-{index:03d}":
                raise SourcesError(f"reconstruction manifest {path} chunk {index} is misnamed")
            context.check_file({**chunk, "path": chunk_path}, f"chunk {chunk_path}")
            content = context.read(chunk_path)
            if hashlib.sha512(content).hexdigest() != chunk.get("sha512"):
                raise SourcesError(f"chunk {chunk_path} sha512 differs")
            whole256.update(content)
            whole512.update(content)
            offset += len(content)
        if offset != length or whole256.hexdigest() != sha256 or whole512.hexdigest() != sha512:
            raise SourcesError(f"chunks of {name} do not rebuild the APKBUILD archive")
        context.chunk_files[path] = [base + str(chunk["path"]) for chunk in chunks]
    return len(by_path)


def validate(root: Path, expected_manifest_sha256: str = EXPECTED_SOURCES_MANIFEST_SHA256,
             max_file_bytes: int = MAX_FILE_BYTES) -> dict[str, int]:
    tree = Tree(root)
    try:
        return validate_tree(tree, expected_manifest_sha256, max_file_bytes)
    finally:
        tree.close()


def validate_tree(tree: Tree, expected_manifest_sha256: str, max_file_bytes: int) -> dict[str, int]:
    context = Context(tree, max_file_bytes)
    manifest_bytes = tree.read(f"{SOURCES}/MANIFEST.json", MAX_MANIFEST_BYTES, "corresponding-source manifest")
    if hashlib.sha256(manifest_bytes).hexdigest() != expected_manifest_sha256:
        raise SourcesError("corresponding-source manifest digest ratchet changed")
    manifest = json.loads(manifest_bytes)
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        raise SourcesError("corresponding-source manifest schema is not exact")
    if (
        set(manifest) != MANIFEST_KEYS
        or manifest["aports_repository"] != APORTS_REPOSITORY
        or manifest["abuild_repository"] != ABUILD_REPOSITORY
        or manifest["source_obligation_rule"] != SOURCE_OBLIGATION_RULE
        or manifest["max_file_bytes"] != MAX_FILE_BYTES
    ):
        raise SourcesError("corresponding-source manifest header is not exact")

    apk_manifest = tree.read(APK_MANIFEST.as_posix(), 1024 * 1024, "security APK archive manifest")
    provenance_bytes = tree.read(APK_PROVENANCE.as_posix(), 4 * 1024 * 1024, "security APK provenance")
    if manifest.get("binary_manifest") != {
        "path": APK_MANIFEST.as_posix(), "sha256": hashlib.sha256(apk_manifest).hexdigest()
    } or manifest.get("binary_provenance") != {
        "path": APK_PROVENANCE.as_posix(), "sha256": hashlib.sha256(provenance_bytes).hexdigest()
    }:
        raise SourcesError("corresponding-source manifest is bound to another archive closure")
    archive_digests = {}
    for line in apk_manifest.decode("ascii").splitlines():
        match = APK_SUMS_LINE.fullmatch(line)
        if match is None:
            raise SourcesError("security APK archive manifest is not canonical")
        archive_digests[match.group(2)] = match.group(1)
    listed_archives = sorted(tree.walk(APK_DIR.as_posix()))
    if listed_archives != sorted([*archive_digests, APK_MANIFEST.name]):
        missing = sorted(set(archive_digests) - set(listed_archives))[:3]
        extra = sorted(set(listed_archives) - set(archive_digests) - {APK_MANIFEST.name})[:3]
        raise SourcesError(f"security APK archive directory does not match its manifest (missing {missing}, extra {extra})")
    records = json.loads(provenance_bytes).get("archives")
    if not isinstance(records, list) or sorted(r.get("file") for r in records) != sorted(archive_digests):
        raise SourcesError("security APK provenance does not match the archive manifest")

    lock = tree.read(APK_LOCK.as_posix(), 1024 * 1024, "security APK inventory lock").decode("ascii").splitlines()
    lock_revisions: dict[str, set[str]] = {}
    for line in lock:
        match = LOCK_ENTRY.fullmatch(line)
        if match is None:
            raise SourcesError(f"security APK inventory lock entry is not a package revision: {line!r}")
        lock_revisions.setdefault(match.group(1), set()).add(line)
    for record in records:
        installed = record["file"][: -len(".apk")]
        if installed not in lock:
            raise SourcesError(f"security APK inventory lock does not list archive {installed}")
        if lock_revisions[record["name"]] != {installed}:
            raise SourcesError(f"security APK inventory lock lists another revision of {record['name']}")

    sums = parse_sha256sums(tree.read(f"{SOURCES}/SHA256SUMS", 4 * 1024 * 1024,
                                      "corresponding-source SHA256SUMS"))
    present = sorted(tree.walk(SOURCES))
    if present != sorted([*sums, "SHA256SUMS"]):
        missing = sorted(set(sums) - set(present))[:3]
        extra = sorted(set(present) - set(sums) - {"SHA256SUMS"})[:3]
        raise SourcesError(f"corresponding-source directory does not match SHA256SUMS (missing {missing}, extra {extra})")
    for path, digest in sums.items():
        context.files[path] = tree.digest(f"{SOURCES}/{path}", max_file_bytes, f"corresponding-source file {path}")
        if context.files[path][1] != digest:
            raise SourcesError(f"corresponding-source file digest ratchet changed: {path}")
    context.reference(manifest.get("readme"), "corresponding-source README")

    spdx = manifest.get("spdx")
    if not isinstance(spdx, dict) or set(spdx) != {"repository", "tag", "commit", "index", "texts"}:
        raise SourcesError("corresponding-source SPDX record is not exactly its index and texts")
    known_ids: set[str] = set()
    index_paths = {"licenses/SPDX/licenses.json": ("licenses", "licenseId"),
                   "licenses/SPDX/exceptions.json": ("exceptions", "licenseExceptionId")}
    if not isinstance(spdx["index"], list) or sorted(i.get("path") for i in spdx["index"]) != sorted(index_paths):
        raise SourcesError("corresponding-source SPDX index is not the license and exception lists")
    for item in spdx["index"]:
        path = context.check_file(item, "SPDX index")
        listing, key = index_paths[path]
        try:
            entries = json.loads(context.read(path))[listing]
            known_ids.update(entry[key] for entry in entries)
        except (ValueError, KeyError, TypeError) as error:
            raise SourcesError(f"SPDX index {path} is not a license-list-data index") from error
    spdx_ids = set()
    for text in spdx["texts"]:
        identifier = text.get("id") if isinstance(text, dict) else None
        if (
            not isinstance(identifier, str)
            or identifier in spdx_ids
            or identifier not in known_ids
            or text.get("path") != f"licenses/SPDX/{identifier}.txt"
        ):
            raise SourcesError("corresponding-source SPDX text list is not exact")
        context.check_file(text, f"SPDX text {identifier}")
        spdx_ids.add(identifier)
    if sorted(p for p in context.files if p.startswith("licenses/SPDX/")) != sorted(
        [*(f"licenses/SPDX/{i}.txt" for i in spdx_ids), *index_paths]
    ):
        raise SourcesError("corresponding-source SPDX directory does not match its manifest")
    unrecognized_named: dict[str, list[str]] = {}

    def classify_tokens(item: dict, expressions: list[str], label: str) -> None:
        tokens = set().union(*(license_tokens(e) for e in expressions))
        recognized, unrecognized = tokens & known_ids, tokens - known_ids
        for identifier in sorted(recognized - spdx_ids):
            raise SourcesError(f"{label} names {identifier}, an SPDX identifier, without its SPDX text")
        if (
            item.get("license_tokens") != sorted(tokens)
            or item.get("spdx_ids") != sorted(recognized)
            or item.get("unrecognized_license_tokens") != sorted(unrecognized)
        ):
            raise SourcesError(f"{label} license tokens are not split into SPDX ids with texts and unrecognized tokens")
        for token in unrecognized:
            unrecognized_named.setdefault(token, []).append(label)

    by_origin: dict[str, list[dict]] = {}
    for record in records:
        by_origin.setdefault(record.get("source_package"), []).append(record)
    origins = manifest.get("origins")
    if not isinstance(origins, list) or [o.get("origin") for o in origins] != sorted(by_origin):
        raise SourcesError("corresponding-source manifest does not cover every archive origin exactly once")

    abuild_revisions = set()
    obligation_count = 0
    for entry in origins:
        origin = entry["origin"]
        description = f"origin {origin}"
        own = sorted(by_origin[origin], key=lambda r: r["file"])
        commits = {r.get("source_commit") for r in own}
        versions = {r.get("version") for r in own}
        if commits != {entry.get("aports_commit")} or versions != {entry.get("version")}:
            raise SourcesError(f"{description} commit or version differs from the archive provenance")
        expected_binaries = [
            {"file": r["file"], "sha256": r["sha256"], "length": r["length"], "version": r["version"],
             "license": r["license"]}
            for r in own
        ]
        if entry.get("binaries") != expected_binaries:
            raise SourcesError(f"{description} binaries differ from the archive provenance")
        for record in own:
            content = tree.read(f"{APK_DIR.as_posix()}/{record['file']}", MAX_APK_BYTES,
                                f"security APK archive {record['file']}")
            digest = hashlib.sha256(content).hexdigest()
            if digest != archive_digests[record["file"]] or digest != record["sha256"]:
                raise SourcesError(f"security APK archive digest ratchet changed: {record['file']}")
            info = read_pkginfo(content, f"security APK archive {record['file']}")
            if (
                info["origin"] != origin
                or info["commit"] != entry["aports_commit"]
                or info["pkgver"] != record["version"]
                or info["license"] != record["license"]
                or f"{info['pkgname']}-{info['pkgver']}.apk" != record["file"]
            ):
                raise SourcesError(f".PKGINFO of {record['file']} differs from the manifest")
            abuild_revisions.add(info["abuild"])
        copyleft = any(COPYLEFT.search(r["license"]) for r in own)
        if entry.get("source_obligation") is not copyleft:
            raise SourcesError(f"{description} source obligation flag does not follow its archive licenses")
        obligation_count += copyleft
        validate_recipe(context, entry, f"recipes/{origin}/", f"main/{origin}/", entry["version"],
                        description, f"sources/{origin}/")

        validate_notices(context, entry, origin)
        classify_tokens(entry, [entry["license"], *(r["license"] for r in own)], origin)

    tools = manifest.get("build_tools")
    if not isinstance(tools, list) or sorted(t.get("version") for t in tools if isinstance(t, dict)) != sorted(abuild_revisions):
        raise SourcesError("corresponding-source build tools do not cover every recorded abuild revision")
    for tool in tools:
        version = tool["version"]
        if tool.get("name") != "abuild":
            raise SourcesError(f"build tool {version} is not abuild")
        validate_recipe(context, tool, f"build-tools/abuild/{version}/", "main/abuild/", version,
                        f"abuild {version}", "build-tools/abuild/sources/")
        classify_tokens(tool, [tool["license"]], f"abuild {version}")
    expected_unrecognized = [
        {"token": token, "status": "unresolved", "named_by": sorted(labels)}
        for token, labels in sorted(unrecognized_named.items())
    ]
    if manifest.get("unrecognized_license_tokens") != expected_unrecognized:
        raise SourcesError("corresponding-source unrecognized license tokens are not listed exactly as unresolved")
    split = validate_chunks(context, manifest)
    inventories = verify_attributions(context, manifest)

    if context.referenced != set(context.files):
        unreferenced = sorted(set(context.files) - context.referenced)[:3]
        raise SourcesError(f"corresponding-source manifest does not reference every file (for example {unreferenced})")
    return {
        "origins": len(origins),
        "source_obligation_origins": obligation_count,
        "upstream_sources": sum(1 for e in origins for s in e["sources"] if s.get("kind") == "upstream"),
        "notices": sum(len(e["notices"]) for e in origins),
        "attribution_inventories": inventories,
        "archives": len(records),
        "abuild_revisions": len(tools),
        "files": len(context.files),
        "split_archives": split,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        summary = validate(args.root.resolve())
    except (SourcesError, ValueError, KeyError, TypeError, AttributeError) as error:
        print(f"security APK corresponding source failed: {error}", file=sys.stderr)
        return 1
    print(
        "security APK corresponding source binds {archives} archives from {origins} origins "
        "(copyleft origins: {source_obligation_origins}; vendored upstream sources: {upstream_sources}; "
        "notices: {notices}; attribution inventories: {attribution_inventories}; abuild revisions: "
        "{abuild_revisions}; split archives: {split_archives}; files: {files})".format(**summary)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
