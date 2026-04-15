#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v python3 >/dev/null 2>&1; then
  echo "bounded ARC qualification requires python3 on PATH" >&2
  exit 1
fi

output_root="target/release-qualification/bounded-arc"
log_root="${output_root}/logs"
manifest_path="${output_root}/artifact-manifest.json"
checksum_path="${output_root}/SHA256SUMS"
report_path="${output_root}/qualification-report.md"
matrix_src="docs/standards/ARC_BOUNDED_ARC_QUALIFICATION_MATRIX.json"
matrix_snapshot="${output_root}/ARC_BOUNDED_ARC_QUALIFICATION_MATRIX.json"
profile_src="docs/standards/ARC_BOUNDED_OPERATIONAL_PROFILE.md"
profile_snapshot="${output_root}/ARC_BOUNDED_OPERATIONAL_PROFILE.md"
checklist_src="docs/review/14-bounded-arc-pre-ship-checklist.md"
checklist_snapshot="${output_root}/bounded-arc-pre-ship-checklist.md"

rm -rf "${output_root}"
mkdir -p "${log_root}"

python3 -m json.tool "${matrix_src}" >/dev/null
cp "${matrix_src}" "${matrix_snapshot}"
cp "${profile_src}" "${profile_snapshot}"
cp "${checklist_src}" "${checklist_snapshot}"

python3 - <<'PY' >"${log_root}/doc-claim-discipline.log"
from pathlib import Path

checks = [
    (
        "README.md",
        [
            "Lean 4 verified",
            "formally verified protocol specification",
            "Merkle-committed append-only log",
        ],
    ),
    (
        "docs/COMPETITIVE_LANDSCAPE.md",
        [
            "proven in Lean 4",
            "making stolen tokens useless",
            "signed, append-only receipt log provides continuous, cryptographically verifiable attestation",
        ],
    ),
]

for rel_path, forbidden in checks:
    text = Path(rel_path).read_text()
    for phrase in forbidden:
        if phrase in text:
            raise SystemExit(f"forbidden bounded-release phrase still present in {rel_path}: {phrase}")
    print(f"ok: {rel_path}")
PY

python3 - <<'PY' >"${log_root}/planning-truth.log"
from pathlib import Path

checks = {
    ".planning/PROJECT.md": [
        "Latest completed milestone:** v3.18 Bounded ARC Ship Readiness Closure",
    ],
    ".planning/STATE.md": [
        "Status: `v3.18` is now the latest completed milestone and bounded ARC",
        "ship-readiness lane.",
    ],
    ".planning/REQUIREMENTS.md": [
        "after completing the v3.18 bounded ARC ship-readiness closure",
    ],
    ".planning/ROADMAP.md": [
        "| 417 | v3.18 | Claim Discipline and Planning Truth Closure | Complete |",
        "| 421 | v3.18 | Bounded Operational Profile and Release Gate | Complete |",
    ],
}

for rel_path, required in checks.items():
    text = Path(rel_path).read_text()
    for needle in required:
        if needle not in text:
            raise SystemExit(f"missing planning truth in {rel_path}: {needle}")
    print(f"ok: {rel_path}")
PY

cat >"${report_path}" <<'EOF'
# Bounded ARC Qualification Gate

This bundle records the current ship-facing release boundary.

Decision:

- ARC is qualified locally as a bounded governance and evidence control plane.
- The current bounded release excludes stronger recursive delegation,
  verifier-bound runtime, transparency-log, consensus-HA, and market-position
  claims.

Executed checks:

- JSON validation of `ARC_BOUNDED_ARC_QUALIFICATION_MATRIX.json`
- bounded claim-discipline grep checks over README and competitive-positioning
  copy
- planning-truth checks over `.planning/*`

Supporting documents:

- `ARC_BOUNDED_ARC_QUALIFICATION_MATRIX.json`
- `ARC_BOUNDED_OPERATIONAL_PROFILE.md`
- `bounded-arc-pre-ship-checklist.md`
EOF

python3 - <<'PY' "${output_root}" "${checksum_path}" "${manifest_path}"
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

output_root = Path(sys.argv[1])
checksum_path = Path(sys.argv[2])
manifest_path = Path(sys.argv[3])

entries = []
for artifact in sorted(output_root.rglob("*")):
    if not artifact.is_file():
        continue
    if artifact in {checksum_path, manifest_path}:
        continue
    payload = artifact.read_bytes()
    entries.append(
        {
            "path": artifact.relative_to(output_root).as_posix(),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "bytes": len(payload),
        }
    )

checksum_path.write_text(
    "".join(f"{entry['sha256']}  {entry['path']}\n" for entry in entries)
)

manifest = {
    "generatedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "scope": "bounded_arc_release_qualification",
    "decision": "bounded_arc_release_qualified_stronger_claims_demoted_to_addenda",
    "claimLevel": "bounded_arc_release_candidate",
    "artifacts": entries,
}

manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
PY
