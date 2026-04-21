"""Unit tests for :func:`chio_iac.run_terraform`.

The tests mock the subprocess layer so they never require a live
``terraform`` binary or a real Chio sidecar. The focus is the two-phase
capability split: ``plan`` requires ``infra:plan`` scope, ``apply``
requires ``infra:apply`` scope plus a plan-review pass that denies
out-of-scope resource types.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from chio_sdk.testing import MockChioClient, MockVerdict, allow_all, deny_all

from chio_iac import (
    ChioIACConfigError,
    ChioIACError,
    ChioIACPlanReviewError,
    PlanReviewGuard,
    ResourceTypeAllowlist,
    ResourceTypeDenylist,
    run_terraform,
)
from chio_iac import terraform as terraform_module

# ---------------------------------------------------------------------------
# Subprocess recorder
# ---------------------------------------------------------------------------


class _Recorder:
    """Replacement for :func:`chio_iac.terraform._run_subprocess`.

    Records every invocation so assertions can verify argv + cwd, and
    drives deterministic completed-process results for plan / show /
    apply phases without shelling out to real Terraform.
    """

    def __init__(self, *, show_json: dict | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.show_json = show_json or {}
        self.force_returncode: int | None = None

    def __call__(
        self,
        command: list[str],
        *,
        cwd: str | Path | None,
        capture_output: bool,
        env: dict[str, str] | None,
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append(
            {
                "command": list(command),
                "cwd": str(cwd) if cwd else None,
                "capture_output": capture_output,
                "env": env,
            }
        )
        stdout = ""
        # ``terraform show -json ...`` returns the injected JSON.
        if len(command) >= 3 and command[1:3] == ["show", "-json"]:
            stdout = json.dumps(self.show_json)
        returncode = self.force_returncode if self.force_returncode is not None else 0
        return subprocess.CompletedProcess(
            args=command,
            returncode=returncode,
            stdout=stdout,
            stderr="",
        )


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch) -> _Recorder:
    """Install a :class:`_Recorder` for every test."""
    rec = _Recorder()
    monkeypatch.setattr(terraform_module, "_run_subprocess", rec)
    return rec


@pytest.fixture
def fake_terraform_binary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """Provide a fake ``terraform`` binary path via ``$CHIO_IAC_TERRAFORM``.

    The path is created as a regular (non-executable) file so
    :func:`shutil.which` / :meth:`Path.exists` accept it. We never
    actually execute it because :class:`_Recorder` intercepts the
    subprocess call.
    """
    binary = tmp_path / "terraform-fake"
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    binary.chmod(0o755)
    monkeypatch.setenv("CHIO_IAC_TERRAFORM", str(binary))
    return str(binary)


# ---------------------------------------------------------------------------
# Helpers for building plans
# ---------------------------------------------------------------------------


def _tf_plan(*changes: tuple[str, list[str], str]) -> dict:
    return {
        "format_version": "1.2",
        "resource_changes": [
            {
                "address": address,
                "type": type_,
                "name": address.split(".")[-1],
                "change": {"actions": list(actions)},
            }
            for type_, actions, address in changes
        ],
    }


# ---------------------------------------------------------------------------
# (a) ``terraform plan`` enforces ``infra:plan`` scope
# ---------------------------------------------------------------------------


class TestPlanPhase:
    async def test_plan_evaluates_sidecar_and_dispatches_terraform(
        self,
        recorder: _Recorder,
        fake_terraform_binary: str,
        tmp_path: Path,
    ) -> None:
        chio = allow_all()
        recorder.show_json = _tf_plan(
            ("aws_db_instance", ["create"], "aws_db_instance.primary"),
        )

        result = await run_terraform(
            "plan",
            capability_id="cap-plan",
            working_dir=tmp_path,
            chio_client=chio,
        )

        # Sidecar evaluated with plan tool-name.
        calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(calls) == 1
        assert calls[0].tool_name == "terraform:plan"
        assert calls[0].capability_id == "cap-plan"
        assert calls[0].parameters["subcommand"] == "plan"

        # ``terraform plan -out=<plan>`` was dispatched.
        tf_calls = [c for c in recorder.calls if c["command"][1] == "plan"]
        assert len(tf_calls) == 1
        assert tf_calls[0]["command"][0] == fake_terraform_binary
        assert f"-out={tmp_path / 'tfplan'}" in tf_calls[0]["command"]

        # ``terraform show -json`` was dispatched to dump plan JSON.
        show_calls = [c for c in recorder.calls if c["command"][1:3] == ["show", "-json"]]
        assert len(show_calls) == 1

        # The JSON dump sidecar file was written.
        json_path = tmp_path / "tfplan.json"
        assert json_path.exists()
        assert result.subcommand == "plan"
        assert result.returncode == 0
        assert result.receipt is not None

    async def test_plan_denied_raises_iac_error(
        self,
        recorder: _Recorder,
        fake_terraform_binary: str,
        tmp_path: Path,
    ) -> None:
        chio = deny_all(reason="missing plan scope", guard="CapabilityGuard")

        with pytest.raises(ChioIACError) as exc_info:
            await run_terraform(
                "plan",
                capability_id="cap-no-plan",
                working_dir=tmp_path,
                chio_client=chio,
            )
        assert exc_info.value.subcommand == "plan"
        assert exc_info.value.guard == "CapabilityGuard"
        assert "missing plan scope" in exc_info.value.message
        # Terraform itself was never dispatched.
        assert not any(c["command"][1] == "plan" for c in recorder.calls)

    async def test_plan_denied_via_receipt_path(
        self,
        recorder: _Recorder,
        fake_terraform_binary: str,
        tmp_path: Path,
    ) -> None:
        chio = deny_all(
            reason="tight policy",
            guard="PolicyGuard",
            raise_on_deny=False,
        )

        with pytest.raises(ChioIACError) as exc_info:
            await run_terraform(
                "plan",
                capability_id="cap-rx",
                working_dir=tmp_path,
                chio_client=chio,
            )
        assert exc_info.value.receipt_id is not None
        assert exc_info.value.guard == "PolicyGuard"


# ---------------------------------------------------------------------------
# (b) ``terraform apply`` enforces ``infra:apply`` + plan-review
# ---------------------------------------------------------------------------


class TestApplyPhase:
    async def test_apply_allowed_with_in_scope_plan(
        self,
        recorder: _Recorder,
        fake_terraform_binary: str,
        tmp_path: Path,
    ) -> None:
        # Pre-write the plan JSON dump the apply path consumes.
        plan_json = _tf_plan(
            ("aws_db_instance", ["create"], "aws_db_instance.primary"),
        )
        (tmp_path / "tfplan").write_text("binary-ish", encoding="utf-8")
        (tmp_path / "tfplan.json").write_text(json.dumps(plan_json), encoding="utf-8")

        chio = allow_all()

        result = await run_terraform(
            "apply",
            capability_id="cap-apply",
            working_dir=tmp_path,
            allowlist=ResourceTypeAllowlist(patterns=["aws_db_*"]),
            chio_client=chio,
        )

        # Sidecar evaluated with apply tool-name AND the resource types.
        calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(calls) == 1
        assert calls[0].tool_name == "terraform:apply"
        assert calls[0].parameters["resource_types"] == ["aws_db_instance"]
        assert result.resource_types == ["aws_db_instance"]

        # ``terraform apply tfplan`` dispatched.
        tf_calls = [c for c in recorder.calls if c["command"][1] == "apply"]
        assert len(tf_calls) == 1
        assert str(tmp_path / "tfplan") in tf_calls[0]["command"]

    async def test_apply_denies_out_of_scope_resource_before_dispatch(
        self,
        recorder: _Recorder,
        fake_terraform_binary: str,
        tmp_path: Path,
    ) -> None:
        plan_json = _tf_plan(
            ("aws_db_instance", ["create"], "aws_db_instance.primary"),
            ("aws_iam_role", ["create"], "aws_iam_role.db_access"),
        )
        (tmp_path / "tfplan").write_text("binary-ish", encoding="utf-8")
        (tmp_path / "tfplan.json").write_text(json.dumps(plan_json), encoding="utf-8")

        chio = allow_all()

        with pytest.raises(ChioIACPlanReviewError) as exc_info:
            await run_terraform(
                "apply",
                capability_id="cap-apply",
                working_dir=tmp_path,
                allowlist=ResourceTypeAllowlist(patterns=["aws_db_*"]),
                chio_client=chio,
            )

        # Violation list names the out-of-scope resource.
        types = [v["resource_type"] for v in exc_info.value.violations]
        assert "aws_iam_role" in types
        assert "aws_db_instance" not in types
        # Sidecar was never consulted -- plan-review denies first.
        assert not chio.calls
        # Terraform apply was never dispatched.
        assert not any(c["command"][1] == "apply" for c in recorder.calls)

    async def test_apply_respects_denylist(
        self,
        recorder: _Recorder,
        fake_terraform_binary: str,
        tmp_path: Path,
    ) -> None:
        plan_json = _tf_plan(
            ("aws_iam_role", ["create"], "aws_iam_role.r"),
        )
        (tmp_path / "tfplan").write_text("binary-ish", encoding="utf-8")
        (tmp_path / "tfplan.json").write_text(json.dumps(plan_json), encoding="utf-8")

        chio = allow_all()

        with pytest.raises(ChioIACPlanReviewError) as exc_info:
            await run_terraform(
                "apply",
                capability_id="cap-apply",
                working_dir=tmp_path,
                allowlist=ResourceTypeAllowlist(patterns=["aws_*"]),
                denylist=ResourceTypeDenylist(patterns=["aws_iam_*"]),
                chio_client=chio,
            )
        assert any(
            "denylist" in v["reason"] for v in exc_info.value.violations
        )

    async def test_apply_requires_capability_id(
        self,
        recorder: _Recorder,
        fake_terraform_binary: str,
        tmp_path: Path,
    ) -> None:
        with pytest.raises(ChioIACConfigError):
            await run_terraform(
                "apply",
                capability_id="",
                working_dir=tmp_path,
                allowlist=ResourceTypeAllowlist(patterns=["*"]),
                chio_client=allow_all(),
            )

    async def test_apply_requires_plan_review_config(
        self,
        recorder: _Recorder,
        fake_terraform_binary: str,
        tmp_path: Path,
    ) -> None:
        with pytest.raises(ChioIACConfigError) as exc_info:
            await run_terraform(
                "apply",
                capability_id="cap-apply",
                working_dir=tmp_path,
                chio_client=allow_all(),
            )
        assert "plan_review_guard" in str(exc_info.value)

    async def test_apply_requires_plan_json_on_disk(
        self,
        recorder: _Recorder,
        fake_terraform_binary: str,
        tmp_path: Path,
    ) -> None:
        with pytest.raises(ChioIACConfigError) as exc_info:
            await run_terraform(
                "apply",
                capability_id="cap-apply",
                working_dir=tmp_path,
                allowlist=ResourceTypeAllowlist(patterns=["*"]),
                chio_client=allow_all(),
            )
        assert "plan" in str(exc_info.value).lower()

    async def test_apply_falls_back_to_show_json(
        self,
        recorder: _Recorder,
        fake_terraform_binary: str,
        tmp_path: Path,
    ) -> None:
        # No ``.json`` sidecar on disk; wrapper must fall back to
        # ``terraform show -json`` to learn the plan.
        (tmp_path / "tfplan").write_text("binary-ish", encoding="utf-8")
        recorder.show_json = _tf_plan(
            ("aws_db_instance", ["create"], "aws_db_instance.primary"),
        )

        chio = allow_all()
        result = await run_terraform(
            "apply",
            capability_id="cap-apply",
            working_dir=tmp_path,
            allowlist=ResourceTypeAllowlist(patterns=["aws_db_*"]),
            chio_client=chio,
        )
        # We saw a ``terraform show -json tfplan`` call before apply.
        show_calls = [c for c in recorder.calls if c["command"][1:3] == ["show", "-json"]]
        assert show_calls
        assert result.resource_types == ["aws_db_instance"]


# ---------------------------------------------------------------------------
# (c) ``terraform destroy`` maps to infra:apply + allow_destroy=True
# ---------------------------------------------------------------------------


class TestDestroyPhase:
    async def test_destroy_requires_apply_scope(
        self,
        recorder: _Recorder,
        fake_terraform_binary: str,
        tmp_path: Path,
    ) -> None:
        plan_json = _tf_plan(
            ("aws_db_instance", ["delete"], "aws_db_instance.primary"),
        )
        (tmp_path / "tfplan").write_text("binary-ish", encoding="utf-8")
        (tmp_path / "tfplan.json").write_text(json.dumps(plan_json), encoding="utf-8")

        chio = allow_all()
        result = await run_terraform(
            "destroy",
            capability_id="cap-destroy",
            working_dir=tmp_path,
            allowlist=ResourceTypeAllowlist(patterns=["aws_db_*"]),
            chio_client=chio,
        )
        calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(calls) == 1
        assert calls[0].tool_name == "terraform:destroy"
        # The kernel receives infra:apply scope.
        assert calls[0].parameters["scope_label"] == "infra:apply"
        assert result.subcommand == "destroy"


# ---------------------------------------------------------------------------
# (d) Scope mapping: plan vs apply can be governed by different caps
# ---------------------------------------------------------------------------


class TestScopeSplit:
    async def test_policy_permits_plan_denies_apply(
        self,
        recorder: _Recorder,
        fake_terraform_binary: str,
        tmp_path: Path,
    ) -> None:
        def policy(
            tool_name: str,
            _scope: dict[str, Any],
            _ctx: dict[str, Any],
        ) -> MockVerdict:
            if tool_name == "terraform:plan":
                return MockVerdict.allow_verdict()
            return MockVerdict.deny_verdict(
                "apply scope not granted", guard="CapabilityGuard"
            )

        chio = MockChioClient(policy=policy, raise_on_deny=False)

        # Plan works.
        recorder.show_json = _tf_plan(
            ("aws_db_instance", ["create"], "aws_db_instance.primary"),
        )
        plan_result = await run_terraform(
            "plan",
            capability_id="cap-plan-only",
            working_dir=tmp_path,
            chio_client=chio,
        )
        assert plan_result.returncode == 0
        assert plan_result.receipt is not None

        # Apply denied.
        with pytest.raises(ChioIACError) as exc_info:
            await run_terraform(
                "apply",
                capability_id="cap-plan-only",
                working_dir=tmp_path,
                allowlist=ResourceTypeAllowlist(patterns=["aws_*"]),
                chio_client=chio,
            )
        assert exc_info.value.subcommand == "apply"
        assert exc_info.value.guard == "CapabilityGuard"


# ---------------------------------------------------------------------------
# (e) Input validation
# ---------------------------------------------------------------------------


class TestInputValidation:
    async def test_unsupported_subcommand(
        self,
        fake_terraform_binary: str,
        tmp_path: Path,
    ) -> None:
        with pytest.raises(ChioIACConfigError) as exc_info:
            await run_terraform(
                "init",
                capability_id="cap",
                working_dir=tmp_path,
                chio_client=allow_all(),
            )
        assert "init" in str(exc_info.value)

    async def test_missing_terraform_binary(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.delenv("CHIO_IAC_TERRAFORM", raising=False)
        # Force PATH lookup to fail.
        monkeypatch.setattr(terraform_module.shutil, "which", lambda _: None)
        with pytest.raises(ChioIACConfigError) as exc_info:
            await run_terraform(
                "plan",
                capability_id="cap",
                working_dir=tmp_path,
                chio_client=allow_all(),
            )
        assert "terraform binary" in str(exc_info.value)

    async def test_pre_built_guard_is_used_verbatim(
        self,
        recorder: _Recorder,
        fake_terraform_binary: str,
        tmp_path: Path,
    ) -> None:
        plan_json = _tf_plan(
            ("aws_s3_bucket", ["create"], "aws_s3_bucket.logs"),
        )
        (tmp_path / "tfplan").write_text("binary-ish", encoding="utf-8")
        (tmp_path / "tfplan.json").write_text(json.dumps(plan_json), encoding="utf-8")

        guard = PlanReviewGuard(
            allowlist=ResourceTypeAllowlist(patterns=["aws_s3_*"]),
        )

        chio = allow_all()
        result = await run_terraform(
            "apply",
            capability_id="cap",
            working_dir=tmp_path,
            plan_review_guard=guard,
            chio_client=chio,
        )
        assert result.resource_types == ["aws_s3_bucket"]
