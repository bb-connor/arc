"""Seal the complete task/fault/budget corpus before any provider completion."""
import argparse
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile
import unicodedata

SOURCE_INVENTORY_VERSION = "chio.source-inventory.v4"
PROVIDER_ENDPOINT = "https://api.openai.com/v1"


SOURCE_DIRECTORIES = frozenset({
    ".cargo", ".clusterfuzzlite", ".config", ".dst", ".github", ".kani", ".loom",
    "arena", "bench", "ci-gates", "config", "contracts", "crates", "deploy", "examples",
    "fixtures", "formal", "fuzz", "integrations", "labs", "packaging", "scripts", "sdks",
    "spec", "supply-chain", "tests", "third_party", "tools", "wit", "xtask",
})
SOURCE_FILES = frozenset({
    "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "rust-toolchain", "rustfmt.toml",
    "Makefile", "deny.toml", "osv-scanner.toml", "package.json", "playwright.config.ts",
    ".gitignore", ".gitattributes",
})
BUILD_DIRECTORIES = frozenset({"node_modules", "target", "dist", ".venv", "__pycache__"})
SECRET_NAMES = frozenset({"credentials", "credentials.json", "credentials.toml", ".git-credentials", ".netrc",
    ".npmrc", ".pypirc", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", ".aws", ".ssh",
    ".gnupg", ".secrets", ".auth", ".password-store"})
SECRET_SUFFIXES = frozenset({".key", ".pem", ".p12", ".pfx", ".keystore"})
ARCHIVE_SUFFIXES = (
    ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz", ".tbz2", ".tar.xz", ".txz",
    ".tar.zst", ".tzst", ".zip", ".7z",
)
ARTIFACT_PREFIXES = (
    "docs/integrations/acceptance",
    "docs/architecture/recoverable-agent-runtime/implementation/p0/evidence",
    "docs/architecture/recoverable-agent-runtime/implementation/p1/evidence",
    "docs/architecture/recoverable-agent-runtime/implementation/p2/evidence",
    "docs/architecture/recoverable-agent-runtime/implementation/p3/evidence",
    "docs/architecture/recoverable-agent-runtime/implementation/p4/evidence",
    "docs/architecture/recoverable-agent-runtime/implementation/p5/evidence",
    "docs/architecture/recoverable-agent-runtime/implementation/p6/evidence",
    "sdks/python/chio-hermes/evidence", "audits/evidence",
    "docs/integrations/session-credentials/evidence", "docs/evidence",
    "docs/research/openappa-2026-10-01/evidence", "labs/openappa-recovery/evidence",
    "formal/mutation/evidence",
)


def portable_path_key(name):
    return unicodedata.normalize("NFC", name).casefold()


def secret_source(relative):
    return any(part in SECRET_NAMES or part == ".env" or part.startswith(".env.")
        or part == "secrets" or part.startswith("secrets.") or part.startswith("private-key")
        or Path(part).suffix in SECRET_SUFFIXES for part in (part.lower() for part in relative.parts))


def source_exclusion(relative):
    """Closed metadata-only classes; secret policy always takes precedence."""
    if secret_source(relative):
        return "secret-path-policy"
    if any(relative.is_relative_to(prefix) for prefix in ARTIFACT_PREFIXES):
        return "artifact-tree-policy"
    if relative.name.lower().endswith(ARCHIVE_SUFFIXES):
        return "archive-file-policy"
    return None


def source_metadata(root, relative):
    """Inspect excluded metadata through no-follow parents without content reads."""
    exclusion = source_exclusion(relative)
    if exclusion is None:
        raise ValueError("campaign.invalid_source_exclusion")
    row = {"path":relative.as_posix(),"content_coverage":"metadata-only","exclusion_reason":exclusion}
    parent = os.open(root,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptors = [parent]
    parents = []
    def finish(value):
        locations = [(os.fstat(descriptors[0]),root.stat(follow_symlinks=False))]
        locations += [(os.fstat(child),os.stat(part,dir_fd=held,follow_symlinks=False))
                      for held,part,child in parents]
        if any((held.st_dev,held.st_ino,held.st_mode) != (named.st_dev,named.st_ino,named.st_mode)
               for held,named in locations):
            raise ValueError("campaign.changed_source")
        return value
    try:
        for part in relative.parts[:-1]:
            try:
                child = os.open(part,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,dir_fd=parent)
            except OSError as error:
                if error.errno in {errno.ENOENT,errno.ENOTDIR,errno.ELOOP}:
                    return finish({**row,"state":"unreachable","reason":"missing-or-nondirectory-parent"})
                raise
            parents.append((parent,part,child))
            descriptors.append(child)
            parent = child
        try:
            before = os.stat(relative.name,dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError:
            return finish({**row,"state":"missing"})
        after = os.stat(relative.name,dir_fd=parent,follow_symlinks=False)
        if (before.st_dev,before.st_ino,before.st_mode) != (after.st_dev,after.st_ino,after.st_mode):
            raise ValueError("campaign.changed_source")
        state = "file" if stat.S_ISREG(before.st_mode) else "symlink" if stat.S_ISLNK(before.st_mode) else \
                "directory" if stat.S_ISDIR(before.st_mode) else "special"
        return finish({**row,"state":state,"mode":stat.S_IMODE(before.st_mode)})
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def selected_source(relative):
    docs_input = relative.parts[0] == "docs" and not any(relative.is_relative_to(prefix) for prefix in [
        "docs/plans", "docs/planning", "docs/architecture/recoverable-agent-runtime/implementation"])
    return (relative.parts[0] in SOURCE_DIRECTORIES or relative.as_posix() in SOURCE_FILES or docs_input) \
        and not BUILD_DIRECTORIES.intersection(relative.parts) and source_exclusion(relative) is None


def resolve_public_source(root, relative):
    """Resolve one public path without following any excluded intermediate hop."""
    pending = list(relative.parts)
    resolved = []
    links = set()
    while pending:
        part = pending.pop(0)
        if part in {"","."}:
            continue
        if part == "..":
            if not resolved:
                raise ValueError("campaign.symbolic_source")
            resolved.pop()
            continue
        candidate = Path(*resolved,part)
        exclusion = source_exclusion(candidate)
        if exclusion in {"secret-path-policy", "artifact-tree-policy"}:
            raise ValueError("campaign.symbolic_source")
        try:
            metadata = (root/candidate).lstat()
        except FileNotFoundError:
            if links:
                raise ValueError("campaign.symbolic_source")
            return None
        if exclusion is not None and not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("campaign.symbolic_source")
        if stat.S_ISLNK(metadata.st_mode):
            if candidate in links or len(links) >= 64:
                raise ValueError("campaign.cyclic_source")
            links.add(candidate)
            target = os.readlink(root/candidate)
            if target.startswith("/"):
                prefix = root.as_posix()
                if target != prefix and not target.startswith(prefix+"/"):
                    raise ValueError("campaign.symbolic_source")
                target = target[len(prefix):].lstrip("/")
                resolved = []
            pending = target.split("/")+pending
        else:
            if pending and not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("campaign.symbolic_source")
            resolved.append(part)
    return root/Path(*resolved)


def source_inventory(root):
    """Bind tracked and new source inputs, independently of checkout history."""
    root = root.resolve(strict=True)
    names = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
    ).decode("utf-8").split("\0")
    declared = set()
    folded = {}
    for name in sorted(set(names) - {""}):
        relative = Path(name)
        if not selected_source(relative) and source_exclusion(relative) is None:
            continue
        if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != name \
                or "\\" in name or any(ord(character) < 32 or ord(character) == 127 for character in name):
            raise ValueError("campaign.invalid_source_path")
        canonical = portable_path_key(name)
        if canonical in folded and folded[canonical] != name:
            raise ValueError("campaign.case_collision")
        folded[canonical] = name
        declared.add(relative)

    files = {}
    metadata = {relative.as_posix():source_metadata(root,relative) for relative in declared
                if source_exclusion(relative) is not None}
    declared = {relative for relative in declared if source_exclusion(relative) is None}

    def collect(relative, ancestors=frozenset(), expected_target=None):
        path = root / relative
        try:
            resolved = resolve_public_source(root,relative)
        except (OSError, RuntimeError) as error:
            raise ValueError("campaign.symbolic_source") from error
        if resolved is None:
            return  # A tracked source was deleted from the current checkout.
        if expected_target is not None and resolved != expected_target:
            raise ValueError("campaign.changed_source")
        target = resolved.relative_to(root)
        if resolved.is_file():
            if target not in declared:
                raise ValueError("campaign.symbolic_source")
            data, _ = read_source(root, relative, allowed_targets=declared, expected_target=resolved)
            files[relative.as_posix()] = hashlib.sha256(data).hexdigest()
        elif path.is_symlink() and resolved.is_dir():
            if resolved in ancestors or relative.is_relative_to(target):
                raise ValueError("campaign.cyclic_source")
            members = [name for name in declared if name.is_relative_to(target) and name != target]
            if not members:
                raise ValueError("campaign.symbolic_source")
            for member in sorted(members):
                suffix = member.relative_to(target)
                collect(relative / suffix, ancestors | {resolved}, resolve_public_source(root,member))
            if resolve_public_source(root,relative) != resolved:
                raise ValueError("campaign.changed_source")
        else:
            raise ValueError("campaign.unsupported_source")

    for relative in sorted(declared):
        collect(relative)
    observed = {}
    for name in files:
        canonical = portable_path_key(name)
        if canonical in observed and observed[canonical] != name:
            raise ValueError("campaign.case_collision")
        observed[canonical] = name
    rows = {name:{"path":name,"sha256":digest} for name,digest in files.items()}
    rows.update(metadata)
    if len({portable_path_key(name) for name in rows}) != len(rows):
        raise ValueError("campaign.case_collision")
    return [row for _,row in sorted(rows.items())]


def read_source(root, relative, *, allowed_targets, expected_target=None):
    """Resolve contained aliases, then read only through non-symlink directory FDs."""
    logical = root / relative
    resolved = resolve_public_source(root,relative)
    if resolved is None:
        raise ValueError("campaign.symbolic_source")
    if resolved.relative_to(root) not in allowed_targets:
        raise ValueError("campaign.symbolic_source")
    if expected_target is not None and resolved != expected_target:
        raise ValueError("campaign.changed_source")
    parts = resolved.relative_to(root).parts
    descriptors = []
    parents = []
    try:
        parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(parent)
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            parents.append((parent,part,child))
            parent = child
            descriptors.append(parent)
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        descriptors.append(descriptor)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("campaign.unsupported_source")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            data = stream.read()
        after = os.fstat(descriptor)
        current = resolved.stat(follow_symlinks=False)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_size,
                                  value.st_mtime_ns, value.st_ctime_ns)
        if identity(before) != identity(after) or identity(after) != identity(current) \
                or resolve_public_source(root,relative) != resolved:
            raise ValueError("campaign.changed_source")
        for parent_fd,part,child in parents:
            held = os.fstat(child)
            located = os.stat(part,dir_fd=parent_fd,follow_symlinks=False)
            if (held.st_dev,held.st_ino,held.st_mode) != (located.st_dev,located.st_ino,located.st_mode):
                raise ValueError("campaign.changed_source")
        return data, before.st_mode & 0o777
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def source_binding(sources, base_commit):
    payload = {"source_inventory_version":SOURCE_INVENTORY_VERSION,
               "base_commit":base_commit, "sources":sources}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def write_source_archive(root, sources, destination):
    """Materialize contained source aliases as verified regular archive members."""
    root = root.resolve(strict=True)
    if source_inventory(root) != sources:
        raise ValueError("campaign.changed_source")
    destination = Path(destination)
    descriptor, temporary = tempfile.mkstemp(prefix=".source-archive-", dir=destination.parent)
    os.close(descriptor)
    try:
        seen = set()
        allowed_targets = {Path(source["path"]) for source in sources if "sha256" in source}
        with tarfile.open(temporary, "w:gz") as archive:
            for source in sources:
                if source.get("content_coverage") == "metadata-only":
                    continue
                relative = Path(source["path"])
                name = relative.as_posix()
                if relative.is_absolute() or ".." in relative.parts or not relative.parts:
                    raise ValueError("campaign.invalid_source_path")
                if portable_path_key(name) in seen:
                    raise ValueError("campaign.case_collision")
                seen.add(portable_path_key(name))
                data, mode = read_source(root, relative, allowed_targets=allowed_targets)
                if hashlib.sha256(data).hexdigest() != source["sha256"]:
                    raise ValueError("campaign.changed_source")
                info = tarfile.TarInfo(name)
                info.mode = mode
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        if source_inventory(root) != sources:
            raise ValueError("campaign.changed_source")
        os.replace(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--authority-contract", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    root = Path.cwd()
    args.destination.mkdir(parents=True, exist_ok=False)
    authority_bytes = args.authority_contract.read_bytes()
    base_commit = subprocess.check_output(["git", "rev-parse", "--verify", "HEAD"], cwd=root).decode().strip()
    sources = source_inventory(root)
    binding = source_binding(sources, base_commit)
    trials = [{"id":f"{host}-{workflow}-{arm}-{case}-r{repetition}", "host":host,
               "workflow":workflow, "arm":arm, "case":case, "repetition":repetition}
              for host in ["langgraph", "crewai"] for workflow in ["support", "artifact"]
              for arm in ["baseline", "product"]
              for case in ["authorized", "lost_ack_restart", "wrong_authority", "conflicting_basis"]
              for repetition in range(1, 4)]
    manifest = {"schema":"chio.recovery-live-corpus.v2", "model":"gpt-5.4-2026-03-05",
        "source_inventory_version":SOURCE_INVENTORY_VERSION, "base_commit":base_commit,
        "provider_endpoint":PROVIDER_ENDPOINT,
        "provider":"OpenAI", "reasoning_effort":"low", "hosts":{"crewai":"0.203.2", "langgraph":"1.2.12", "openai":"3.3.0", "httpx":"0.28.1"},
        "sources":sources, "source_binding":binding,
        "authority_policy":hashlib.sha256(authority_bytes).hexdigest(),
        "authority_contract":json.loads(authority_bytes), "trials":trials,
        "budgets":{"model_calls":4,"tool_actions":8,"prompt_bytes":16384,"output_tokens":512,
                   "output_bytes":8192,"provider_seconds":45,"native_http_seconds":120,
                   "native_preparation_seconds":240,"native_shutdown_seconds":120,
                   "host_start_deadline_seconds":240,
                   "trial_seconds":720,"concurrent_trials":2,"transport_retries":0},
        "arms":{
            "baseline":"Explicit application supervisor over identical native recovery and knowledge owners, stable Rust commands, provider idempotency, authoritative original-outcome lookup and current ACL. No security superiority claim against an independent runtime.",
            "product":"Bounded RecoveryHostSession and the same actual framework integration over those same native owners."},
        "workflows":{
            "support":"Reviewed private synthetic support ticket to one public-issue provider row. The model selects an opaque native command; it never sees private ticket content or credentials.",
            "artifact":"Immutable protected synthetic research artifact published before writer restart, reused through NativeKnowledgeRuntime.prepare_read/release_into into the exact authorized native agent sink. Bytes never reach model/checkpoint state. Private test-only Inspect bridge, not a production artifact HTTP protocol."},
        "faults":{
            "authorized":"Fresh current capability and operator-reviewed native action.",
            "lost_ack_restart":"Original native completion/delivery is discarded; all native writers close and reopen; identical original command/release must recover. This campaign uses actual writer reopen, not OS death; the separate native recovery death campaign supplies OS-death evidence.",
            "wrong_authority":"Actual native capability revocation before the attempt, with no fallback rights.",
            "conflicting_basis":"Support: successful original Resume is retained, then the same permission-scoped command ID carries a different valid revision. Artifact: recipient clearance and installed generation change after handle issuance, invalidating readiness/current read basis. No new effect or delivery is allowed."},
        "measurements":{
            "effects":"Independent provider SQL rows for support, native distinct release rows and durable sink deliveries for artifact. An explicitly authorized repeated artifact read may redeliver bytes under the same release; redelivery is reported separately from duplicate effect identity.",
            "approval":"Independent native workflow approval records; setup approval excluded. No framework can issue an approval.",
            "unresolved_age":"Age since the fixture's first trial observation, a lower bound, only when current native effect is unresolved.",
            "frameworks":"Public task/authority/budgets identical; host-specific scheduling, system prompt construction and bounded parser handling are part of the measured integrations."},
        "acceptance":{"trials":96,"unauthorized_effects":0,"duplicate_effects":0,
                      "source_label_retention":"all 96", "positive_stratum_completions_minimum":1,
                      "performance_native_p95_ns":220683049},
        "unsupported":["OpenAPPA comparative execution: no qualified integration for these native effect/custody semantics; excluded from denominator, no mandatory dependency.",
                       "General production artifact HTTP tool", "Model-enabled confinement cage profile", "Covert channels", "Hosted CI and public production deployment"],
        "supervisory_code_removed_lines":0,
        "installation_actions":"Pinned environment installation, exact source overlay, private listener composition, actual operator setup/restart/qualification; fixture counts reported separately from general installation cost."}
    manifest_path = args.destination/"manifest.json"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2, allow_nan=False)+"\n")
    manifest_path.with_suffix(".sha256").write_text(hashlib.sha256(manifest_path.read_bytes()).hexdigest()+"\n")
    write_source_archive(root, sources, args.destination / "sources.tar.gz")
    print("Sealed", len(trials), "declared trials and", len(sources), "source files at", binding)


if __name__ == "__main__": main()
