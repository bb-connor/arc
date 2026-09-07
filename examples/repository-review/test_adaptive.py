"""Assignment validation fails before any native child submission."""

import pytest

from adaptive.planning import inventory_plan, parse_plan, validate_plan


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
