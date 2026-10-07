#!/usr/bin/env python3
"""Audit exact sources, review, gates and immutable P4 evidence. Fail on drift."""
import importlib.util
import json
from pathlib import Path
from inventory import PHASE, sha

spec=importlib.util.spec_from_file_location("p5_seal",PHASE/"evidence/seal-package.py")
if spec is None or spec.loader is None: raise SystemExit("missing P5 package auditor")
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
recomputed=module.build_record()
record=json.loads((PHASE/"verification.json").read_text())
recomputed["created_at_utc"]=record["created_at_utc"]
if recomputed!=record: raise SystemExit("P5 verification differs from recomputation")
integrity=json.loads((PHASE/"package-integrity.json").read_text())
observed=sorted(str(p.relative_to(PHASE)) for p in PHASE.rglob("*") if p.is_file() and p.name!="package-integrity.json" and "__pycache__" not in p.parts)
if [row["path"] for row in integrity["artifacts"]]!=observed: raise SystemExit("P5 artifact inventory differs")
for row in integrity["artifacts"]:
    if sha(PHASE/row["path"])!=row["sha256"]: raise SystemExit("P5 artifact changed: "+row["path"])
print(f"PASS P5 evidence: {len(record['local_gates'])} local gates, ten obligations, P4 archive and seals intact; phase accomplished={record['phase_accomplished']}")
