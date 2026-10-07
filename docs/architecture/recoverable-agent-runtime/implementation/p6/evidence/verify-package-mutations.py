#!/usr/bin/env python3
"""Bounded deliberate corruptions, each restored before a positive audit."""
import json
import subprocess
import sys

from inventory import PHASE, ROOT


def audit():
    return subprocess.run([sys.executable, str(PHASE / "evidence/verify-package.py")],
                          cwd=ROOT, capture_output=True, text=True)


def change_json(path, edit):
    value = json.loads(path.read_bytes())
    edit(value)
    path.write_text(json.dumps(value, indent=2) + "\n")


def main():
    before = audit()
    if before.returncode:
        raise SystemExit("Starting package is invalid: " + before.stderr[-1000:])
    results = []
    predecessor = json.loads((ROOT / "docs/architecture/recoverable-agent-runtime/implementation/p5/evidence/linux-acceptance.result.json").read_bytes())
    mutants = [
        ("failed-gate", "evidence/local-gates.json", lambda rows: rows[0].update(exit_code=1)),
        ("stale-gate", "evidence/local-gates.json", lambda rows: rows[0].update(source_binding="stale")),
        ("missing-gate", "evidence/local-gates.json", lambda rows: rows.pop()),
        ("changed-command", "evidence/local-gates.json", lambda rows: rows[0].update(command=["true"])),
        ("raised-ceiling", "evidence/performance.json", lambda row: row.update(native_p95_ceiling_ns=220683050)),
        ("empty-native-performance", "evidence/performance.json", lambda row: row["native"].update(samples=0)),
        ("unknown-effects-hidden", "evidence/initial-interruption.json", lambda row: row.update(measurement_status="measured_zero")),
        ("interrupted-slots-omitted", "evidence/initial-interruption.json", lambda row: row.update(not_started=[])),
        ("open-important-review", "review-manifest.json", lambda row: row.update(open_p1=1)),
        ("foreign-review-source", "review-manifest.json", lambda row: row.update(reviewed_source_binding="stale")),
        ("missing-obligation", "requirements-coverage.json", lambda row: row["requirements"].pop()),
        ("whole-system-proof-claim", "evidence/assurance-map.json", lambda row: row.update(full_system_proof=True)),
        ("old-linux-challenge", "evidence/final-linux-postfix/profile.json", lambda row: row.update(cage_challenge=predecessor["cage_challenge"])),
    ]
    for name, relative, edit in mutants:
        path = PHASE / relative
        original = path.read_bytes()
        try:
            change_json(path, edit)
            rejected = audit()
            if rejected.returncode == 0:
                raise SystemExit("Corruption was accepted: " + name)
        finally:
            path.write_bytes(original)
        restored = audit()
        if restored.returncode:
            raise SystemExit("Restored package refused: " + name + ": " + restored.stderr[-1000:])
        results.append({"mutation": name, "rejected": True, "restored_positive": True})
    print(json.dumps({"schema": "chio.recovery-p6-package-mutations.v1",
                      "rejected_mutations": len(results), "restored_positive_audits": len(results) + 1,
                      "results": results}, indent=2))


if __name__ == "__main__": main()
