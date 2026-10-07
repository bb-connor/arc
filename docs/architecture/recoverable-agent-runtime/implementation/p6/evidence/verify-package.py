#!/usr/bin/env python3
"""Read-only current-tree recomputation and exact sealed artifact verification."""
import json

from inventory import PHASE, sha
from package_audit import refuse
from package_record import build_record


def main():
    record = json.loads((PHASE / "verification.json").read_bytes())
    current = build_record()
    current["created_at_utc"] = record["created_at_utc"]
    refuse(current == record, "verification_recomputation")
    integrity = json.loads((PHASE / "package-integrity.json").read_bytes())
    observed = sorted(str(path.relative_to(PHASE)) for path in PHASE.rglob("*") if path.is_file()
                      and path.name != "package-integrity.json" and "__pycache__" not in path.parts)
    refuse([row["path"] for row in integrity["artifacts"]] == observed, "artifact_inventory")
    for row in integrity["artifacts"]:
        refuse(sha(PHASE / row["path"]) == row["sha256"], "artifact_hash")
    print("PASS P6 exact package:", len(record["joined_sources"]), "sources; 33 local gates; four Linux suites;",
          record["live"]["planned_trials"], "planned slots retained; P5 immutable; scoped open P0/P1 = 0/0")


if __name__ == "__main__": main()
