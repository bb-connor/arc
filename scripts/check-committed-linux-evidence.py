#!/usr/bin/env python3

import argparse
import fcntl
import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path


EVIDENCE_RELATIVE_DIRECTORY = Path("audits/evidence/enterprise-linux")
EVIDENCE_FILES = frozenset(
    {
        "enterprise-migration-binding-digest.txt",
        "enterprise-migration-canary.json",
        "enterprise-migration-canary.json.sha256",
    }
)
MAX_EVIDENCE_COMMITS = 32
MAX_VERIFIER_BYTES = 256 * 1024 * 1024
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
BINDING_DIGEST_PATTERN = re.compile(r"^0x[0-9a-f]{64}\n$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class EvidenceError(ValueError):
    pass


def git(root: Path, *arguments: str) -> bytes:
    environment = os.environ.copy()
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=False,
        capture_output=True,
        env=environment,
    )
    if result.returncode != 0:
        error = result.stderr.decode("utf-8", errors="replace").strip()
        raise EvidenceError(f"git {' '.join(arguments)} failed: {error}")
    return result.stdout


def resolve_commit(root: Path, commit: str, label: str) -> str:
    if COMMIT_PATTERN.fullmatch(commit) is None:
        raise EvidenceError(f"{label} is not an exact lowercase commit identifier")
    resolved = git(root, "rev-parse", "--verify", f"{commit}^{{commit}}")
    try:
        resolved_text = resolved.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise EvidenceError(f"{label} did not resolve to ASCII") from error
    if resolved_text != commit:
        raise EvidenceError(f"{label} did not resolve exactly")
    return resolved_text


def validate_linear_evidence_descendant(
    root: Path, source_commit: str, evidence_commit: str
) -> None:
    if source_commit == evidence_commit:
        raise EvidenceError("Linux evidence must be committed after the source commit")
    allowed_paths = {
        (EVIDENCE_RELATIVE_DIRECTORY / name).as_posix() for name in EVIDENCE_FILES
    }
    cursor = evidence_commit
    commit_count = 0
    while cursor != source_commit:
        commit_count += 1
        if commit_count > MAX_EVIDENCE_COMMITS:
            raise EvidenceError("Linux evidence descendant chain is too long")
        parent_line = git(root, "rev-list", "--parents", "-n", "1", cursor)
        try:
            parts = parent_line.decode("ascii").strip().split()
        except UnicodeDecodeError as error:
            raise EvidenceError("Linux evidence ancestry was not ASCII") from error
        if len(parts) != 2 or parts[0] != cursor:
            raise EvidenceError("Linux evidence descendant chain is not linear")
        parent = parts[1]
        changed = git(
            root,
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "--no-renames",
            "-r",
            "-z",
            parent,
            cursor,
        )
        changed_paths = {item.decode("utf-8") for item in changed.split(b"\0") if item}
        if not changed_paths:
            raise EvidenceError("Linux evidence descendant contains an empty commit")
        unexpected = changed_paths - allowed_paths
        if unexpected:
            rendered = ", ".join(sorted(unexpected))
            raise EvidenceError(
                f"Linux evidence descendant changed paths outside the evidence surface: {rendered}"
            )
        cursor = parent


def validate_tree_inventory(root: Path, evidence_commit: str) -> None:
    expected_paths = {
        (EVIDENCE_RELATIVE_DIRECTORY / name).as_posix() for name in EVIDENCE_FILES
    }
    tree = git(
        root,
        "ls-tree",
        "-r",
        "-z",
        "--full-tree",
        evidence_commit,
        "--",
        EVIDENCE_RELATIVE_DIRECTORY.as_posix(),
    )
    observed_paths = set()
    for raw_entry in tree.split(b"\0"):
        if not raw_entry:
            continue
        try:
            metadata, raw_path = raw_entry.split(b"\t", maxsplit=1)
            mode, object_type, _object_id = metadata.decode("ascii").split()
            path = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as error:
            raise EvidenceError(
                "committed Linux evidence tree entry is malformed"
            ) from error
        if mode != "100644" or object_type != "blob":
            raise EvidenceError(
                f"committed Linux evidence tree mode is not 100644: {path}"
            )
        observed_paths.add(path)
    if observed_paths != expected_paths:
        raise EvidenceError("committed Linux evidence Git tree inventory is not exact")


def validate_checked_out_commit(root: Path, evidence_commit: str) -> None:
    head = git(root, "rev-parse", "--verify", "HEAD").decode("ascii").strip()
    if head != evidence_commit:
        raise EvidenceError(
            "checked-out HEAD is not the declared Linux evidence commit"
        )
    status = git(
        root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--",
        EVIDENCE_RELATIVE_DIRECTORY.as_posix(),
    )
    if status:
        raise EvidenceError("committed Linux evidence surface has working-tree changes")


def validate_file_inventory(root: Path) -> Path:
    directory = root / EVIDENCE_RELATIVE_DIRECTORY
    try:
        directory_metadata = directory.lstat()
    except OSError as error:
        raise EvidenceError("committed Linux evidence directory is missing") from error
    if not stat.S_ISDIR(directory_metadata.st_mode):
        raise EvidenceError("committed Linux evidence path is not a real directory")
    observed = set()
    for entry in directory.iterdir():
        try:
            metadata = entry.lstat()
        except OSError as error:
            raise EvidenceError(
                "committed Linux evidence entry cannot be inspected"
            ) from error
        if not stat.S_ISREG(metadata.st_mode):
            raise EvidenceError("committed Linux evidence contains a non-regular file")
        observed.add(entry.name)
    if observed != EVIDENCE_FILES:
        missing = ", ".join(sorted(EVIDENCE_FILES - observed)) or "none"
        extra = ", ".join(sorted(observed - EVIDENCE_FILES)) or "none"
        raise EvidenceError(
            "committed Linux evidence file inventory is not exact; "
            f"missing: {missing}; extra: {extra}"
        )
    return directory


def read_pinned_verifier(path: Path, expected_sha256: str) -> bytes:
    if SHA256_PATTERN.fullmatch(expected_sha256) is None:
        raise EvidenceError("enterprise evidence verifier SHA-256 is invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise EvidenceError(
            "enterprise evidence verifier cannot be opened safely"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > MAX_VERIFIER_BYTES
            or metadata.st_mode & 0o111 == 0
        ):
            raise EvidenceError(
                "enterprise evidence verifier is not a bounded executable regular file"
            )
        chunks = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise EvidenceError(
                    "enterprise evidence verifier changed while it was read"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise EvidenceError(
                "enterprise evidence verifier changed while it was read"
            )
    finally:
        os.close(descriptor)
    verifier_bytes = b"".join(chunks)
    digest = hashlib.sha256()
    digest.update(verifier_bytes)
    if digest.hexdigest() != expected_sha256:
        raise EvidenceError(
            "enterprise evidence verifier SHA-256 does not match the pin"
        )
    return verifier_bytes


def immutable_verifier_snapshot(verifier_bytes: bytes) -> tuple[int, Path, Path | None]:
    use_memfd = hasattr(os, "memfd_create") and Path("/proc/self/fd").is_dir()
    if use_memfd:
        flags = getattr(os, "MFD_CLOEXEC", 0) | getattr(os, "MFD_ALLOW_SEALING", 0)
        descriptor = os.memfd_create("chio-enterprise-evidence", flags)
        verifier_path = Path("/proc/self/fd") / str(descriptor)
        cleanup_directory = None
    else:
        import tempfile

        cleanup_directory = Path(tempfile.mkdtemp(prefix="chio-enterprise-evidence-"))
        cleanup_directory.chmod(0o700)
        verifier_path = cleanup_directory / "chio-enterprise-evidence"
        descriptor = os.open(
            verifier_path,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o500,
        )
    try:
        offset = 0
        while offset < len(verifier_bytes):
            written = os.write(descriptor, verifier_bytes[offset:])
            if written <= 0:
                raise EvidenceError(
                    "immutable enterprise evidence verifier write failed"
                )
            offset += written
        os.fchmod(descriptor, 0o500)
        os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        if use_memfd:
            seals = (
                getattr(fcntl, "F_SEAL_SEAL", 0)
                | getattr(fcntl, "F_SEAL_SHRINK", 0)
                | getattr(fcntl, "F_SEAL_GROW", 0)
                | getattr(fcntl, "F_SEAL_WRITE", 0)
            )
            add_seals = getattr(fcntl, "F_ADD_SEALS", None)
            if add_seals is None or seals == 0:
                raise EvidenceError("immutable verifier sealing is unavailable")
            fcntl.fcntl(descriptor, add_seals, seals)
        return descriptor, verifier_path, cleanup_directory
    except Exception:
        os.close(descriptor)
        if cleanup_directory is not None:
            shutil.rmtree(cleanup_directory, ignore_errors=True)
        raise


def run_verifier(args: argparse.Namespace, evidence_directory: Path) -> str:
    verifier_path = args.verifier
    if not verifier_path.is_absolute():
        verifier_path = args.root / verifier_path
    verifier_bytes = read_pinned_verifier(verifier_path, args.verifier_sha256)
    verifier_descriptor, verifier, cleanup_directory = immutable_verifier_snapshot(
        verifier_bytes
    )
    command = [
        str(verifier),
        "verify-committed-linux-evidence",
        "--evidence-directory",
        str(evidence_directory),
        "--runner-public-key",
        args.runner_public_key,
        "--expected-source-commit",
        args.source_commit,
        "--expected-runner-name",
        args.expected_runner_name,
        "--expected-runner-os",
        args.expected_runner_os,
        "--expected-runner-arch",
        args.expected_runner_arch,
        "--expected-runner-labels-digest",
        args.expected_runner_labels_digest,
        "--expected-configuration-digest",
        args.expected_configuration_digest,
        "--expected-inventory-digest",
        args.expected_inventory_digest,
        "--expected-runner-contract-digest",
        args.expected_runner_contract_digest,
        "--expected-key-log-transparency-digest",
        args.expected_key_log_transparency_digest,
        "--expected-broker-boundary-digest",
        args.expected_broker_boundary_digest,
        "--expected-cage-enforcement-digest",
        args.expected_cage_enforcement_digest,
        "--expected-committed-adversarial-evidence-digest",
        args.expected_committed_adversarial_evidence_digest,
        "--expected-linux-adversarial-controls-digest",
        args.expected_linux_adversarial_controls_digest,
        "--expected-migration-state-store-digest",
        args.expected_migration_state_store_digest,
        "--expected-binding-digest",
        args.expected_binding_digest,
        "--generated-at-not-before-unix-ms",
        str(args.generated_at_not_before_unix_ms),
        "--generated-at-not-after-unix-ms",
        str(args.generated_at_not_after_unix_ms),
    ]
    try:
        result = subprocess.run(
            command,
            cwd=args.root,
            check=False,
            capture_output=True,
            text=True,
            pass_fds=(verifier_descriptor,),
        )
    finally:
        os.close(verifier_descriptor)
        if cleanup_directory is not None:
            shutil.rmtree(cleanup_directory, ignore_errors=True)
    if result.returncode != 0:
        error = result.stderr.strip() or "no diagnostic"
        raise EvidenceError(f"committed Linux evidence verifier failed: {error}")
    if BINDING_DIGEST_PATTERN.fullmatch(result.stdout) is None:
        raise EvidenceError("committed Linux evidence verifier output is malformed")
    return result.stdout.strip()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify the exact committed Linux evidence descendant with externally pinned "
            "runner, verifier, source, freshness, configuration, inventory, and gate bindings."
        )
    )
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parent.parent
    )
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--verifier-sha256", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--evidence-commit", required=True)
    parser.add_argument("--runner-public-key", required=True)
    parser.add_argument("--expected-runner-name", required=True)
    parser.add_argument("--expected-runner-os", required=True)
    parser.add_argument("--expected-runner-arch", required=True)
    parser.add_argument("--expected-runner-labels-digest", required=True)
    parser.add_argument("--expected-configuration-digest", required=True)
    parser.add_argument("--expected-inventory-digest", required=True)
    parser.add_argument("--expected-runner-contract-digest", required=True)
    parser.add_argument("--expected-key-log-transparency-digest", required=True)
    parser.add_argument("--expected-broker-boundary-digest", required=True)
    parser.add_argument("--expected-cage-enforcement-digest", required=True)
    parser.add_argument(
        "--expected-committed-adversarial-evidence-digest", required=True
    )
    parser.add_argument("--expected-linux-adversarial-controls-digest", required=True)
    parser.add_argument("--expected-migration-state-store-digest", required=True)
    parser.add_argument("--expected-binding-digest", required=True)
    parser.add_argument("--generated-at-not-before-unix-ms", type=int, required=True)
    parser.add_argument("--generated-at-not-after-unix-ms", type=int, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.root = args.root.resolve()
    if not args.root.is_dir():
        print("repository root is not a directory", file=sys.stderr)
        return 1
    try:
        source_commit = resolve_commit(args.root, args.source_commit, "source commit")
        evidence_commit = resolve_commit(
            args.root, args.evidence_commit, "evidence commit"
        )
        args.source_commit = source_commit
        validate_linear_evidence_descendant(args.root, source_commit, evidence_commit)
        validate_tree_inventory(args.root, evidence_commit)
        validate_checked_out_commit(args.root, evidence_commit)
        evidence_directory = validate_file_inventory(args.root)
        binding_digest = run_verifier(args, evidence_directory)
    except (EvidenceError, OSError, UnicodeDecodeError) as error:
        print(error, file=sys.stderr)
        return 1
    print(f"committed Linux evidence verified: {binding_digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
