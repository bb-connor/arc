"""Typed scope access preserves the existing conservative attenuation checks."""

import pytest

from chio_sdk import models


@pytest.mark.parametrize(
    ("change", "allowed"),
    [
        ({}, True),
        ({"max_invocations": 1}, True),
        ({"max_invocations": 4}, False),
        ({"max_invocations": None}, False),
        ({"dpop_required": False}, False),
        ({"constraints": []}, False),
        ({"server_id": "foreign"}, False),
        ({"operations": ["subscribe"]}, False),
    ],
)
def test_typed_scope_helper_and_legacy_method_preserve_tool_authority(change, allowed):
    grant = {
        "server_id": "files",
        "tool_name": "read",
        "operations": ["invoke"],
        "max_invocations": 3,
        "dpop_required": True,
        "constraints": [{"type": "path_prefix", "value": "/repository"}],
    }
    parent = models.ChioScope(grants=[models.ToolGrant(**grant)])
    child = models.ChioScope(grants=[models.ToolGrant(**(grant | change))])
    assert models.scope_is_subset_of(child, parent) is allowed
    assert child.is_subset_of(parent) is allowed


@pytest.mark.parametrize(
    ("child", "allowed"),
    [
        ({}, True),
        ({"resource_grants": [{"uri_pattern": "file:///tenant/a", "operations": ["read"]}]}, True),
        ({"resource_grants": [{"uri_pattern": "file:///other/a", "operations": ["read"]}]}, False),
        ({"prompt_grants": [{"prompt_name": "review", "operations": ["get"]}]}, True),
        ({"prompt_grants": [{"prompt_name": "deploy", "operations": ["get"]}]}, False),
    ],
)
def test_typed_scope_helper_preserves_resource_and_prompt_ceilings(child, allowed):
    parent = models.ChioScope.model_validate(
        {
            "resource_grants": [{"uri_pattern": "file:///tenant/*", "operations": ["read"]}],
            "prompt_grants": [{"prompt_name": "review", "operations": ["get"]}],
        }
    )
    scope = models.ChioScope.model_validate(child)
    assert models.scope_is_subset_of(scope, parent) is allowed
    assert scope.is_subset_of(parent) is allowed
