"""Assignment and authority validation fails before native child submission."""

import json

import pytest

from adaptive import cli, configuration
from adaptive.common import SCHEMA, persist
from adaptive.planning import inventory_plan, parse_plan, validate_plan
from snapshot import digest


def test_inventory_partition_changes_with_repository_contents_and_covers_every_path():
    small = ["api/main.py", "api/test_main.py", "web/index.ts"]
    larger = small + ["worker/run.py"]
    assert len(validate_plan(inventory_plan(small, 8), small, 8)) == 2
    assert len(validate_plan(inventory_plan(larger, 8), larger, 8)) == 3
    bounded = validate_plan(inventory_plan(larger, 2), larger, 2)
    assert len(bounded) == 2
    assert sorted(path for job in bounded for path in job["paths"]) == sorted(larger)


@pytest.mark.parametrize(
    "plan",
    [
        {"reviews": []},
        {"reviews": [{"paths": ["outside"], "focus": "read"}]},
        {"reviews": [{"paths": ["a"], "focus": "read"}]},
        {"reviews": [{"paths": ["a", "a", "b"], "focus": "read"}]},
        {"reviews": [{"paths": ["a", "b"], "focus": "read", "command": "/bin/sh"}]},
        {"reviews": [{"paths": ["a", "b"], "focus": "x" * 1001}]},
        {"reviews": [{"paths": ["a", "b"], "focus": " "}]},
        {"reviews": [{"paths": ["a", "b"], "focus": "read"}], "parent_id": "root"},
    ],
)
def test_invalid_plans_cannot_select_authority_or_omit_work(plan):
    with pytest.raises(ValueError):
        validate_plan(plan, ["a", "b"], 2)


def test_plan_limit_and_overlapping_reviews():
    plan = {
        "reviews": [
            {"paths": ["a", "b"], "focus": focus} for focus in ("behavior", "tests")
        ]
    }
    assert len(validate_plan(plan, ["a", "b"], 2)) == 2
    with pytest.raises(ValueError):
        validate_plan(plan, ["a", "b"], 1)


@pytest.mark.parametrize(
    "text", ['{"reviews":[],"reviews":[]}', '{"reviews":NaN}', "```json\n{}\n```"]
)
def test_ambiguous_or_non_json_model_output_rejects(text):
    with pytest.raises(ValueError):
        parse_plan(text)


def prepared_run(directory, timeout):
    directory.chmod(0o700)
    binary = directory / "chio"
    binary.write_bytes(b"pinned native binary fixture")
    snapshot = {"files": []}
    config = {
        "schema": SCHEMA,
        "chio": str(binary),
        "native_binary_sha256": cli.binary_hash(binary),
        "application_hash": configuration.application_hash(),
        "kernel_key": "pinned initialization key",
        "snapshot_hash": digest(snapshot),
        "max_reviews": 2,
        "max_parallel": 1,
        "max_calls": 30,
        "native_server": {
            "id": "repo",
            "command": ["/usr/bin/python3", "tools.py"],
            "launch_policy": str(directory / "launch-policy.json"),
            "launch_policy_signer": "pinned policy signer",
        },
    }
    if timeout is not None:
        config["native_server"]["request_timeout_seconds"] = timeout
    persist(directory / "snapshot.json", snapshot)
    persist(directory / "run.json", config)
    persist(directory / "worker-plan.json", configuration.plan(config, directory))
    (directory / "kernel.pub").write_text(config["kernel_key"] + "\n")
    host = json.loads(json.dumps(configuration.host(config, directory)))
    host["policy"] = str(directory / "policy.yaml")
    # Native Server deserialization materializes this default in host/host.json.
    host["servers"][0].setdefault("request_timeout_seconds", 60)
    (directory / "host").mkdir()
    persist(directory / "host/host.json", {"config": host})
    return config


@pytest.mark.parametrize("timeout", [None, 60, 180])
def test_initialized_host_timeout_roundtrip_keeps_full_authority(tmp_path, timeout):
    config = prepared_run(tmp_path, timeout)
    assert cli.validate_run(tmp_path) == config


@pytest.mark.parametrize("timeout", [None, 60, 180])
def test_host_timeout_default_does_not_mutate_pinned_run_metadata(tmp_path, timeout):
    config = prepared_run(tmp_path, timeout)
    original = json.loads((tmp_path / "run.json").read_text())
    host = configuration.host(config, tmp_path)
    assert host["servers"][0]["request_timeout_seconds"] == (
        60 if timeout is None else timeout
    )
    assert config == original
    host["servers"][0]["request_timeout_seconds"] = 900
    assert config == original


@pytest.mark.parametrize(
    ("path", "changed"),
    [
        (("servers", 0, "request_timeout_seconds"), 180),
        (("servers", 0, "command"), ["/usr/bin/other"]),
        (("servers", 0, "launch_policy"), "/other-policy.json"),
        (("servers", 0, "launch_policy_signer"), "other signer"),
        (("mailboxes", 0, "limits", "max_messages"), 2),
        (("children", 0, "budget_share_bps"), 9000),
        (("spawn_templates", 0, "max_budget_share_bps"), 9000),
        (("limits", "max_calls"), 1000),
        (("policy",), "/other-policy.yaml"),
    ],
)
def test_initialized_host_authority_changes_still_reject(tmp_path, path, changed):
    prepared_run(tmp_path, None)
    document = json.loads((tmp_path / "host/host.json").read_text())
    selected = document["config"]
    for key in path[:-1]:
        selected = selected[key]
    selected[path[-1]] = changed
    persist(tmp_path / "host/host.json", document)
    with pytest.raises(ValueError, match="initialized authority templates"):
        cli.validate_run(tmp_path)


def test_explicit_host_timeout_cannot_be_replaced_by_default(tmp_path):
    prepared_run(tmp_path, 180)
    document = json.loads((tmp_path / "host/host.json").read_text())
    document["config"]["servers"][0]["request_timeout_seconds"] = 60
    persist(tmp_path / "host/host.json", document)
    with pytest.raises(ValueError, match="initialized authority templates"):
        cli.validate_run(tmp_path)
