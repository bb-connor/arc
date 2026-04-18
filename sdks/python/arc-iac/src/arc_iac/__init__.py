"""ARC Infrastructure-as-Code governance.

Wraps Terraform and Pulumi with the ARC protocol's two-phase capability
model so every ``terraform plan`` / ``terraform apply`` -- and every
Pulumi program invocation -- flows through the ARC sidecar for
capability-scoped authorisation.

Two-phase enforcement
---------------------

The IaC wrapper splits a single infrastructure change into two
capability scopes:

* ``infra:plan`` (low privilege) -- read-only inspection of what a
  change would do. Maps to ``terraform plan`` and ``pulumi preview``.
* ``infra:apply`` (high privilege) -- actually mutates the cloud.
  Requires a plan-review pass that parses the plan JSON and denies
  resource types outside the granted scope, then evaluates the
  sidecar with the complete resource-type manifest.

Public surface
--------------

* :func:`run_terraform` -- async CLI wrapper for Terraform with
  subcommand-specific scope enforcement (``plan``, ``apply``,
  ``destroy``).
* :func:`arc_pulumi` -- decorator that gates a ``pulumi.Program``
  callable on an ARC capability, with the same plan / apply split.
* :class:`PlanReviewGuard` -- parses Terraform / Pulumi plan JSON and
  denies out-of-scope resource types. Supports
  :class:`ResourceTypeAllowlist` and :class:`ResourceTypeDenylist`
  (glob-aware).
* :func:`record_resource` -- Pulumi-side hook for programs that want
  to opt into the plan-review pass.
* :class:`ArcIACError`, :class:`ArcIACConfigError`,
  :class:`ArcIACPlanReviewError` -- error types.

Example
-------

.. code-block:: python

    import asyncio
    from arc_iac import (
        PlanReviewGuard,
        ResourceTypeAllowlist,
        run_terraform,
    )

    async def main() -> None:
        # Low-privilege: just render a plan.
        await run_terraform("plan", capability_id="cap-infra-plan-42")

        # High-privilege: apply, with plan-review.
        await run_terraform(
            "apply",
            capability_id="cap-infra-apply-42",
            plan_review_guard=PlanReviewGuard(
                allowlist=ResourceTypeAllowlist(
                    patterns=["aws_db_*", "aws_elasticache_*"],
                ),
            ),
        )

    asyncio.run(main())
"""

from arc_iac.errors import ArcIACConfigError, ArcIACError, ArcIACPlanReviewError
from arc_iac.plan_review import (
    PlanResource,
    PlanReviewGuard,
    PlanReviewVerdict,
    ResourceTypeAllowlist,
    ResourceTypeDenylist,
)
from arc_iac.pulumi import arc_pulumi, record_resource
from arc_iac.terraform import TerraformResult, run_terraform

__all__ = [
    "ArcIACConfigError",
    "ArcIACError",
    "ArcIACPlanReviewError",
    "PlanResource",
    "PlanReviewGuard",
    "PlanReviewVerdict",
    "ResourceTypeAllowlist",
    "ResourceTypeDenylist",
    "TerraformResult",
    "arc_pulumi",
    "record_resource",
    "run_terraform",
]
