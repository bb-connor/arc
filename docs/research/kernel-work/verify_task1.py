#!/usr/bin/env python3
"""Verify the G0 research package's provenance and structural claims, not its science."""

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-cache", type=Path)
    parser.add_argument("--paper-at-checkpoint", action="store_true",
                        help="verify the historical G0 paper checkpoint, without qualifying today's manuscript")
    args = parser.parse_args()
    package = Path(__file__).resolve().parent
    repo = package.parents[2]

    def git(*argv):
        return subprocess.check_output(["git", "-C", str(repo), *argv])

    baseline = json.loads((package / "recovery-baseline.json").read_text())
    register = json.loads((package / "claim-register.json").read_text())
    sources = json.loads((package / "task1-sources.json").read_text())
    revision = baseline["source"]["head"]
    require(register["baseline"]["recovery_commit"] == revision, "recovery pin drift")
    require(register["baseline"]["assume_shipped"] is True, "shipped assumption lost")
    for document in baseline["documents"]:
        raw = git("show", revision + ":" + document["path"])
        require(hashlib.sha256(raw).hexdigest() == document["sha256"],
                "recovery source hash mismatch: " + document["path"])
    requirements = json.loads(git("show", revision +
        ":docs/architecture/recoverable-agent-runtime/requirements.json"))
    ids = {item["id"] for item in requirements["requirements"]}
    require(len(ids) == 111 and ids == set(baseline["requirement_ids"]),
            "normative requirement inventory mismatch")
    groups = register["recovery_groups"]
    flattened = [item for values in groups.values() for item in values]
    require(len(flattened) == len(set(flattened)) == 111 and set(flattened) == ids,
            "crosswalk is not a disjoint complete inventory")
    crosswalk = (package / "recovery-crosswalk.md").read_text()
    for group, values in groups.items():
        rows = [line for line in crosswalk.splitlines() if line.startswith(f"| {group} |")]
        require(len(rows) == 1, "missing or duplicate crosswalk row: " + group)
        mentioned = re.findall(r"\b(?:SEC|RUST|REC|SIM|CON|ART|ISO|OPS|TEST)-\d\d\b", rows[0])
        require(mentioned == values, "crosswalk/register divergence: " + group)

    fields = {"id", "statement", "status", "assumptions", "recovery_requirements",
              "closest_prior_art", "counterdesign", "observable_difference",
              "falsifier", "evidence", "next_test"}
    require([claim["id"] for claim in register["claims"]] == ["R1", "R2", "R3"],
            "claim inventory mismatch")
    for claim in register["claims"]:
        require(fields <= claim.keys(), "missing claim fields: " + claim["id"])
        require(claim["status"] == "hypothesis", "G0 claim promoted without later evidence")
        expected = [item for group in claim["recovery_groups"] for item in groups[group]]
        require(claim["recovery_requirements"] == expected, "claim requirement drift")
        require(claim["observable_difference"]["established_difference"] is None,
                "G0 advertises an established difference")
        for category in ("model_results", "measured_implementation_results", "outside_reproduction"):
            require(claim["evidence"][category] == [], "unexpected later-stage evidence at G0")
        require(claim["evidence"]["uninspected_behavior"] == "not_examined",
                "unknown behavior mislabeled")
    for flag in ("breakthrough_established", "novelty_established",
                 "equivalence_proved", "manuscript_reentry_allowed"):
        require(register["gate"][flag] is False, "unearned G0 promotion: " + flag)
    require(all(value == "not_started" for value in register["gate"]["later_gates"].values()),
            "later gates were silently advanced")

    source_ids = set(sources["background_source_ids"])
    document_ids = set()
    for document in sources["documents"]:
        require(document["id"] not in document_ids, "duplicate source document")
        document_ids.add(document["id"])
        source_ids.add(document["source_id"])
        require(re.fullmatch(r"[0-9a-f]{64}", document["sha256"]), "invalid source hash")
        require(document["url"].startswith("https://") and document["locations"],
                "missing source location")
        require(document["experiment_reproduced"] is False, "source review mislabeled reproduction")
        if "revision" in document:
            require(re.fullmatch(r"[0-9a-f]{40}", document["revision"]) and
                    document["revision"] in document["url"], "mutable software source URL")
        if args.source_cache:
            raw = (args.source_cache / document["cache_path"]).read_bytes()
            require(hashlib.sha256(raw).hexdigest() == document["sha256"],
                    "primary source hash mismatch: " + document["id"])
    for claim in register["claims"]:
        require(set(claim["closest_prior_art"]) <= source_ids, "uncatalogued prior art")

    for path in package.glob("*.md"):
        content = path.read_text()
        require("\u2014" not in content, "em dash: " + path.name)
        for destination in re.findall(r"\]\(([^)]+)\)", content):
            if "://" in destination or destination.startswith("#"):
                continue
            target = destination.split("#", 1)[0]
            require((path.parent / target).exists(), "missing local link: " + destination)
    paper = "docs/papers/verifiable-work"
    expected_tree = register["baseline"]["frozen_paper_tree"]
    paper_revision = register["baseline"]["paper_checkpoint"] if args.paper_at_checkpoint else "HEAD"
    require(git("rev-parse", paper_revision + ":" + paper).decode().strip() == expected_tree,
            "committed paper changed")
    if not args.paper_at_checkpoint:
        require(not git("status", "--porcelain", "--untracked-files=all", "--", paper),
                "paper working tree changed")
    git("diff", "--check")
    git("diff", "--cached", "--check")
    print(json.dumps({"result": "pass", "recovery_documents_verified": len(baseline["documents"]),
        "requirements": len(ids), "crosswalk_groups": len(groups), "claims": len(register["claims"]),
        "primary_documents_catalogued": len(document_ids),
        "primary_document_hashes_verified": len(document_ids) if args.source_cache else 0,
        "paper_tree": expected_tree, "paper_scope": "historical G0 checkpoint" if args.paper_at_checkpoint else "current tree",
        "scientific_validity_proved": False}, indent=2))


if __name__ == "__main__":
    main()
