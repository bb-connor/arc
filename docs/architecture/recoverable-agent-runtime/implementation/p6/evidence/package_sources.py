"""Read-only archive verification; never extract an untrusted member to disk."""
import hashlib
import io
import json
import tarfile

from inventory import PHASE, ROOT, sha
from package_audit import refuse


def archive_inventory(archive):
    observed = {}
    for entry in archive.getmembers():
        refuse(entry.isfile() and entry.name not in observed, "archive_member")
        data = archive.extractfile(entry)
        refuse(data is not None, "archive_bytes")
        observed[entry.name] = hashlib.sha256(data.read()).hexdigest()
    return observed


def audit_archive(path, expected):
    with tarfile.open(path, "r:gz") as archive:
        observed = archive_inventory(archive)
    required = {row["path"]: row["sha256"] for row in expected}
    refuse(len(required) == len(expected) and observed == required, "archive_inventory")
    return len(required)


def audit_predecessor():
    baseline = json.loads((PHASE / "source-baseline.json").read_bytes())
    for row in baseline["artifacts"]:
        refuse(sha(ROOT / row["path"]) == row["sha256"], "predecessor_artifact")
    path = PHASE / baseline["archive"]
    refuse(sha(path) == baseline["archive_sha256"], "predecessor_archive")
    prefix = "docs/architecture/recoverable-agent-runtime/implementation/p5/"
    with tarfile.open(path, "r:gz") as archive:
        observed = archive_inventory(archive)
        refuse(observed == {row["path"]: row["sha256"] for row in baseline["artifacts"]},
               "predecessor_archive_inventory")
        snapshot = baseline["p5_source_snapshot"]
        member = archive.extractfile(prefix + snapshot["source_archive"])
        refuse(member is not None, "predecessor_source_snapshot")
        payload = member.read()
        refuse(hashlib.sha256(payload).hexdigest() == snapshot["source_archive_sha256"],
               "predecessor_source_archive")
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as sources:
            refuse(archive_inventory(sources) == {row["path"]: row["sha256"] for row in baseline["sources"]},
                   "predecessor_sources")
    return {"artifacts": len(baseline["artifacts"]), "sources": len(baseline["sources"]),
            "source_binding": baseline["source_binding"], "archive_sha256": baseline["archive_sha256"]}
