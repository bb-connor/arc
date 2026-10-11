"""Generated root models preserve the canonical path and environment constraints."""

import pytest
from pydantic import ValidationError

from chio_sdk._generated.security.cage_init_plan_v2_schema import AbsoluteCanonicalPath
from chio_sdk._generated.security.mcp_cage_launch_policy_v2_schema import (
    AbsoluteCanonicalPath as LaunchPath,
    EnvironmentVariable as LaunchEnvironmentVariable,
)
from chio_sdk._generated.security.tool_manifest_v2_schema import (
    EnvironmentVariable,
    ReadPath,
    WritePath,
)


@pytest.mark.parametrize("model", [AbsoluteCanonicalPath, LaunchPath, ReadPath, WritePath])
def test_generated_path_roots_keep_canonical_path_checks(model):
    assert model.model_validate("/workspace/repository").root == "/workspace/repository"
    for invalid in [
        "relative",
        "/",
        "/workspace//file",
        "/workspace/../file",
        "/workspace/./file",
        "/workspace/",
    ]:
        with pytest.raises(ValidationError):
            model.model_validate(invalid)


@pytest.mark.parametrize("model", [EnvironmentVariable, LaunchEnvironmentVariable])
def test_generated_environment_roots_keep_loader_and_credential_exclusion(model):
    assert model.model_validate("LANG").root == "LANG"
    for invalid in [
        "LD_PRELOAD",
        "ld_preload",
        "NODE_OPTIONS",
        "SSH_AUTH_SOCK",
        "RUSTC_WRAPPER",
        "API_KEY",
        "AWS_SECRET_ACCESS_KEY",
    ]:
        with pytest.raises(ValidationError):
            model.model_validate(invalid)
