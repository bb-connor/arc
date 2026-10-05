#!/usr/bin/env python3
"""Closed refresh shards cannot become complete evidence on their own."""

import importlib.util
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
import tempfile
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ENTRY = load("shard_entrypoint", "security-execution-container-entrypoint.py")
HOST = load("shard_host", "run-security-execution-container.py")


class ShardInventoryTests(unittest.TestCase):
    def test_partition_preserves_all_campaigns_and_keeps_each_case_together(self):
        seen = set()
        cases = set()
        paths = set()
        for index in range(7):
            campaigns, shard_paths = ENTRY.refresh_shard(index)
            self.assertEqual(len(campaigns), 5)
            self.assertFalse(seen.intersection(campaigns))
            shard_cases = {
                case
                for campaign, _, case in ENTRY.ALL_REFRESH_INVENTORY
                if campaign in campaigns
            }
            self.assertFalse(cases.intersection(shard_cases))
            seen.update(campaigns)
            cases.update(shard_cases)
            paths.update(shard_paths)
            self.assertIn(f"refresh-evidence-shard-{index}", HOST.OUTPUT_SPECS)
        self.assertEqual(seen, set(ENTRY.ALL_CAMPAIGNS))
        self.assertEqual(paths, set(ENTRY.ALL_REFRESH_PATHS))
        self.assertEqual(len(cases), 28)

    def test_shard_identity_is_closed(self):
        for index in (-1, 7, True, "0", None):
            with self.subTest(index=index), self.assertRaises(ENTRY.EntrypointError):
                ENTRY.refresh_shard(index)

    def test_partial_refresh_publishes_only_a_bound_partial_inventory(self):
        campaigns, paths = ENTRY.refresh_shard(0)
        published = {}
        commands = []

        def trusted(command, timeout):
            self.assertEqual(timeout, 30)
            commands.append(command)
            self.assertNotIn("--require-complete", command)
            self.assertIn("--name-only", command)
            return b"\0".join(path.encode() for path in paths) + b"\0"

        with (
            mock.patch.object(ENTRY, "pending_campaigns", return_value=()),
            mock.patch.object(ENTRY, "run_sequence") as sequence,
            mock.patch.object(ENTRY, "run_trusted_bounded", side_effect=trusted),
            mock.patch.object(
                ENTRY, "repository_inventory", return_value=(b"patch", b"", b"")
            ),
            mock.patch.object(
                ENTRY, "candidate_environment", return_value={"SOURCE_SHA": "b" * 40}
            ),
            mock.patch.object(ENTRY, "execution_boundary_record", return_value=b"{}"),
            mock.patch.object(ENTRY, "require_exact_repository_inventory") as unchanged,
            mock.patch.object(
                ENTRY,
                "publish_regular",
                side_effect=lambda n, p: published.setdefault(n, p),
            ),
        ):
            ENTRY.refresh_evidence(30, campaigns, paths, full_inventory=False, shard=0)
        self.assertEqual(len(sequence.call_args.args[0]), 5)
        unchanged.assert_called_once_with((b"patch", b"", b""), 30)
        inventory = json.loads(published["all-evidence-inventory.json"])
        self.assertEqual(inventory["schema"], "chio.security-evidence-refresh-shard.v1")
        self.assertEqual(inventory["shard"], 0)
        self.assertEqual(inventory["shard_count"], 7)
        self.assertEqual(inventory["campaigns"], list(campaigns))
        self.assertEqual(inventory["paths"], list(paths))
        self.assertEqual(inventory["outcome_count"], 5)

    def test_arbitrary_partial_campaign_selection_never_executes(self):
        with mock.patch.object(ENTRY, "pending_campaigns") as pending:
            with self.assertRaises(ENTRY.EntrypointError):
                ENTRY.refresh_evidence(
                    30, ("grant_replay",), (), full_inventory=False, shard=0
                )
            pending.assert_not_called()


class AggregationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.aggregate = load("shard_aggregate", "aggregate-security-evidence-shards.py")

    def inventory(self, index):
        campaigns, paths = ENTRY.refresh_shard(index)
        return {
            "schema": "chio.security-evidence-refresh-shard.v1",
            "shard": index,
            "shard_count": 7,
            "source_sha": "b" * 40,
            "campaign_count": 5,
            "outcome_count": 5,
            "case_count": len(paths) - 6,
            "campaigns": list(campaigns),
            "paths": list(paths),
            "patch_sha256": hashlib.sha256(b"patch").hexdigest(),
            "execution_boundary": {
                "schema": "chio.security-execution-boundary.v1",
                "image_id": "sha256:" + "c" * 64,
                "platform": "linux/amd64",
                "seccomp_profile_sha256": "d" * 64,
                "trusted_file_sha256": {
                    name: "e" * 64 for name in HOST.TRUSTED_BOUNDARY_FILE_KEYS
                },
            },
        }

    def test_exact_partial_contract_and_mutations(self):
        for index in range(7):
            valid = self.inventory(index)
            self.aggregate.validate_inventory(valid, index, "b" * 40, b"patch")
            mutations = [
                ("source", lambda v: v.update(source_sha="a" * 40)),
                (
                    "full schema",
                    lambda v: v.update(schema="chio.security-evidence-refresh.v1"),
                ),
                ("other shard", lambda v: v.update(shard=(index + 1) % 7)),
                ("boolean shard", lambda v: v.update(shard=False)),
                ("missing campaign", lambda v: v["campaigns"].pop()),
                (
                    "duplicate campaign",
                    lambda v: v["campaigns"].append(v["campaigns"][0]),
                ),
                ("unexpected path", lambda v: v["paths"].append("Cargo.toml")),
                ("checksum", lambda v: v.update(patch_sha256="f" * 64)),
                ("unknown field", lambda v: v.update(complete=True)),
                (
                    "wrong platform",
                    lambda v: v["execution_boundary"].update(platform="linux/arm64"),
                ),
            ]
            for name, mutate in mutations:
                with self.subTest(index=index, mutation=name):
                    value = copy.deepcopy(valid)
                    mutate(value)
                    with self.assertRaises(self.aggregate.AggregationError):
                        self.aggregate.validate_inventory(
                            value, index, "b" * 40, b"patch"
                        )

    def test_case_repair_cannot_change_the_mutation_or_accept_pending(self):
        path = ROOT / ENTRY.ALL_REFRESH_INVENTORY[0][2]
        before = json.loads(path.read_text())
        repaired = copy.deepcopy(before)
        for campaign in repaired["artifact"]["campaigns"]:
            campaign["outcomes"].update(sha256="b" * 64, inputs_sha256="c" * 64)
        self.aggregate.validate_case_repair(before, repaired)
        for mutate in (
            lambda v: v.update(pending=True),
            lambda v: v["artifact"]["campaigns"][0].update(minimum_caught=0),
            lambda v: v["artifact"]["campaigns"][0]["outcomes"].update(
                path="elsewhere"
            ),
            lambda v: v["artifact"]["campaigns"][0]["outcomes"].update(sha256="wrong"),
            lambda v: v["notes"].append("arbitrary source repair"),
        ):
            changed = copy.deepcopy(repaired)
            mutate(changed)
            with self.assertRaises(self.aggregate.AggregationError):
                self.aggregate.validate_case_repair(before, changed)

    def test_directory_set_must_be_complete_and_regular(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with self.assertRaises(self.aggregate.AggregationError):
                self.aggregate.shard_directories(root)
            for index in range(7):
                (root / f"shard-{index}").mkdir()
            self.assertEqual(len(self.aggregate.shard_directories(root)), 7)
            (root / "shard-6").rmdir()
            (root / "shard-6").symlink_to(root / "shard-0", target_is_directory=True)
            with self.assertRaises(self.aggregate.AggregationError):
                self.aggregate.shard_directories(root)

    def prepare_git_shards(self, root):
        aggregate = self.aggregate
        candidate = root / "candidate"
        candidate.mkdir()
        for relative in ENTRY.ALL_REFRESH_PATHS:
            path = candidate / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / relative).read_bytes())
        aggregate.git(candidate, "init", "--quiet")
        aggregate.git(candidate, "add", ".")
        aggregate.git(
            candidate,
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--quiet",
            "--no-gpg-sign",
            "-m",
            "test: source inventory",
        )
        source = aggregate.git(candidate, "rev-parse", "HEAD").decode().strip()
        shards = root / "shards"
        shards.mkdir()
        trusted = aggregate.trusted_hashes()
        for index in range(7):
            campaigns, paths = ENTRY.refresh_shard(index)
            hashes = {}
            for campaign, outcome, _case in ENTRY.ALL_REFRESH_INVENTORY:
                if campaign in campaigns:
                    path = candidate / outcome
                    payload = path.read_bytes() + b"\n"
                    path.write_bytes(payload)
                    hashes[campaign] = hashlib.sha256(payload).hexdigest()
            for relative in paths:
                if relative.startswith("crates/core/chio-adversarial-suite/cases/"):
                    path = candidate / relative
                    value = json.loads(path.read_bytes())
                    for campaign in value["artifact"]["campaigns"]:
                        campaign["outcomes"]["sha256"] = hashes[campaign["id"]]
                    path.write_bytes(aggregate.CHECKER.canonical_json_bytes(value))
            aggregate.rebuild_manifest(candidate)
            aggregate.git(candidate, "add", ".")
            patch = aggregate.git(
                candidate, "diff", "--cached", "--binary", "--no-ext-diff"
            )
            inventory = self.inventory(index)
            inventory["source_sha"] = source
            inventory["patch_sha256"] = hashlib.sha256(patch).hexdigest()
            inventory["execution_boundary"]["trusted_file_sha256"].update(trusted)
            inventory["execution_boundary"]["seccomp_profile_sha256"] = trusted[
                "security-evidence-seccomp.json"
            ]
            directory = shards / f"shard-{index}"
            directory.mkdir()
            (directory / "all-evidence-inventory.json").write_bytes(
                aggregate.canonical(inventory)
            )
            (directory / "all-evidence.patch").write_bytes(patch)
            (directory / "all-evidence.patch.sha256").write_text(
                inventory["patch_sha256"] + "  all-evidence.patch\n"
            )
            (directory / "source-sha.txt").write_text(source + "\n")
            aggregate.git(candidate, "reset", "--hard", "HEAD")
        return candidate, source, shards

    def test_real_patch_composition_requires_isolated_complete_validation_before_publication(
        self,
    ):
        aggregate = self.aggregate
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            candidate, source, shards = self.prepare_git_shards(root)
            output = root / "output"
            with mock.patch.object(
                aggregate,
                "validate_composed",
                side_effect=aggregate.AggregationError("incomplete"),
            ) as validate:
                with self.assertRaisesRegex(aggregate.AggregationError, "incomplete"):
                    aggregate.aggregate(
                        candidate, source, shards, output, "sha256:" + "c" * 64
                    )
                validate.assert_called_once()
            self.assertFalse(output.exists())
            self.assertEqual(aggregate.git(candidate, "status", "--porcelain"), b"")
            with mock.patch.object(
                aggregate,
                "validate_composed",
                return_value={"diagnostic_test_double": True},
            ) as validate:
                aggregate.aggregate(
                    candidate, source, shards, output, "sha256:" + "c" * 64
                )
                validate.assert_called_once()
            published = json.loads(
                (output / "all-evidence-inventory.json").read_bytes()
            )
            self.assertEqual(published["paths"], list(ENTRY.ALL_REFRESH_PATHS))
            self.assertEqual(published["campaign_count"], 35)
            self.assertEqual(published["case_count"], 28)
            self.assertEqual(len(published["shards"]), 7)
            self.assertEqual(
                aggregate.git(candidate, "rev-parse", "HEAD").decode().strip(), source
            )
            self.assertEqual(aggregate.git(candidate, "status", "--porcelain"), b"")


if __name__ == "__main__":
    unittest.main()
