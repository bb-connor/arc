"""CLI entry point for ``arc-iac``.

Invoked as ``python -m arc_iac ...`` or via the ``arc-iac`` console
script installed by :mod:`hatchling`. The CLI is a thin shell around
:func:`arc_iac.terraform.run_terraform`; it exists so operators can
drop ARC governance in front of an existing Terraform workflow without
editing Python.

Usage
-----

::

    arc-iac terraform plan \
        --capability-id cap-infra-plan-42 \
        --working-dir ./terraform \
        -- \
        -var-file=envs/prod.tfvars

    arc-iac terraform apply \
        --capability-id cap-infra-apply-42 \
        --working-dir ./terraform \
        --allow aws_db_* \
        --allow aws_elasticache_* \
        --deny aws_iam_*

    arc-iac terraform destroy \
        --capability-id cap-infra-apply-42 \
        --working-dir ./terraform \
        --allow aws_db_* \
        --allow-destroy

Arguments after the ``--`` sentinel are passed through to ``terraform``
verbatim.

The CLI prints a short allow / deny line on stderr, forwards
Terraform's own stdout / stderr, and exits with ``terraform``'s
returncode on the allow path. Deny verdicts exit 2 so CI pipelines can
distinguish ARC denials from Terraform errors.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Sequence
from typing import Any

from arc_sdk.errors import ArcError

from arc_iac.errors import ArcIACConfigError, ArcIACError, ArcIACPlanReviewError
from arc_iac.plan_review import ResourceTypeAllowlist, ResourceTypeDenylist
from arc_iac.terraform import TerraformResult, run_terraform


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="arc-iac",
        description=(
            "ARC Infrastructure-as-Code governance: wraps terraform and "
            "pulumi with two-phase capability enforcement."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    terraform = subparsers.add_parser(
        "terraform",
        help="run a Terraform subcommand under ARC capability enforcement",
    )
    terraform.add_argument(
        "subcommand",
        choices=["plan", "apply", "destroy"],
        help="terraform subcommand to dispatch",
    )
    terraform.add_argument(
        "--capability-id",
        required=True,
        help="pre-minted ARC capability token id (required)",
    )
    terraform.add_argument(
        "--tool-server",
        default="terraform",
        help="ARC tool-server id for the sidecar evaluation (default: terraform)",
    )
    terraform.add_argument(
        "--working-dir",
        default=None,
        help="Terraform configuration directory (default: cwd)",
    )
    terraform.add_argument(
        "--plan-path",
        default=None,
        help="plan file path (default: <working-dir>/tfplan)",
    )
    terraform.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="PATTERN",
        help="resource-type allowlist entry (repeatable; glob-aware)",
    )
    terraform.add_argument(
        "--deny",
        action="append",
        default=[],
        metavar="PATTERN",
        help="resource-type denylist entry (repeatable; glob-aware)",
    )
    terraform.add_argument(
        "--allow-destroy",
        action="store_true",
        help="permit destroy / replace actions on apply (off by default)",
    )
    terraform.add_argument(
        "--sidecar-url",
        default=None,
        help="ARC sidecar base URL (default: http://127.0.0.1:9090)",
    )
    terraform.add_argument(
        "--terraform-binary",
        default=None,
        help="override the terraform binary path",
    )
    terraform.add_argument(
        "--json",
        action="store_true",
        help="emit the result as a single-line JSON object on stdout",
    )
    terraform.add_argument(
        "tf_args",
        nargs=argparse.REMAINDER,
        help="extra arguments passed verbatim to terraform (after --)",
    )

    return parser


def _strip_separator(args: list[str]) -> list[str]:
    """Drop the leading ``--`` that :mod:`argparse` preserves in REMAINDER."""
    if args and args[0] == "--":
        return args[1:]
    return args


def _format_result(result: TerraformResult) -> dict[str, Any]:
    """Build the JSON-emittable summary for the ``--json`` mode."""
    payload: dict[str, Any] = {
        "subcommand": result.subcommand,
        "returncode": result.returncode,
        "command": list(result.command),
    }
    if result.plan_path is not None:
        payload["plan_path"] = result.plan_path
    if result.resource_types:
        payload["resource_types"] = list(result.resource_types)
    if result.receipt is not None:
        payload["receipt_id"] = result.receipt.id
        payload["capability_id"] = result.receipt.capability_id
    return payload


async def _run_terraform_cmd(namespace: argparse.Namespace) -> int:
    """Dispatch the ``arc-iac terraform`` subcommand; return process exit code."""
    allowlist = ResourceTypeAllowlist(patterns=list(namespace.allow))
    denylist = ResourceTypeDenylist(patterns=list(namespace.deny))
    # ``apply`` / ``destroy`` need *something* to review against; if the
    # operator didn't provide any lists, synthesise an open allowlist so
    # the guard is constructed but the kernel retains final say.
    if (
        namespace.subcommand in {"apply", "destroy"}
        and not namespace.allow
        and not namespace.deny
    ):
        allowlist = ResourceTypeAllowlist(patterns=["*"])

    tf_args = _strip_separator(list(namespace.tf_args or []))
    try:
        result = await run_terraform(
            namespace.subcommand,
            tf_args,
            capability_id=namespace.capability_id,
            tool_server=namespace.tool_server,
            working_dir=namespace.working_dir,
            plan_path=namespace.plan_path,
            allowlist=allowlist,
            denylist=denylist,
            allow_destroy=(
                True if namespace.allow_destroy else None
            ),
            sidecar_url=namespace.sidecar_url,
            terraform_binary=namespace.terraform_binary,
            capture_output=False,
        )
    except ArcIACPlanReviewError as exc:
        _emit_deny(exc, as_json=namespace.json)
        return 2
    except ArcIACError as exc:
        _emit_deny(exc, as_json=namespace.json)
        return 2
    except ArcIACConfigError as exc:
        sys.stderr.write(f"arc-iac: configuration error: {exc}\n")
        return 3
    except ArcError as exc:
        sys.stderr.write(f"arc-iac: sidecar error: {exc}\n")
        return 4

    if namespace.json:
        sys.stdout.write(json.dumps(_format_result(result)) + "\n")
    else:
        sys.stderr.write(
            f"arc-iac: terraform {result.subcommand} allowed "
            f"(receipt={result.receipt.id if result.receipt else 'n/a'})\n"
        )
    return result.returncode


def _emit_deny(exc: ArcIACError, *, as_json: bool) -> None:
    """Render a deny verdict to stderr (text) or stdout (JSON)."""
    payload = exc.to_dict()
    if as_json:
        sys.stdout.write(json.dumps(payload) + "\n")
        return
    sys.stderr.write(f"arc-iac: DENIED: {exc.message}\n")
    if isinstance(exc, ArcIACPlanReviewError) and exc.violations:
        for violation in exc.violations:
            sys.stderr.write(
                "  - {type} @ {addr} ({action}): {reason}\n".format(
                    type=violation.get("resource_type", "unknown"),
                    addr=violation.get("address", ""),
                    action=violation.get("action", ""),
                    reason=violation.get("reason", ""),
                )
            )


def main(argv: Sequence[str] | None = None) -> int:
    """Console-script entry point.

    Returns the process exit code:

    * 0 -- ``terraform`` ran successfully under an allow verdict.
    * non-zero (from ``terraform``) -- Terraform itself failed.
    * 2 -- ARC denied the operation (sidecar deny or plan-review deny).
    * 3 -- configuration error before any sidecar call.
    * 4 -- sidecar transport / kernel error (retryable).
    """
    parser = _build_parser()
    namespace = parser.parse_args(argv)
    if namespace.command == "terraform":
        return asyncio.run(_run_terraform_cmd(namespace))
    parser.error(f"unknown command {namespace.command!r}")
    return 2  # unreachable; parser.error exits


if __name__ == "__main__":
    raise SystemExit(main())
