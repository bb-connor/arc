"""Budget authorization and reconciliation workflow for mediated web3 spend."""
from __future__ import annotations

from dataclasses import dataclass

from .artifacts import ArtifactStore, Json
from .chio import ChioHttpError, TrustControlClient


@dataclass(frozen=True)
class BudgetWorkflowResult:
    authorization: Json
    reconciliation: Json
    summary: Json


class BudgetWorkflow:
    """Coordinates Chio budget holds around quote acceptance and settlement."""

    def __init__(self, *, store: ArtifactStore, trust: TrustControlClient | None) -> None:
        self.store = store
        self.trust = trust

    def authorize_quote(
        self,
        *,
        capability_id: str,
        grant_index: int,
        order_id: str,
        exposure_units: int,
        max_budget_units: int,
    ) -> Json:
        hold_id = f"budget-hold:{order_id}:{capability_id}:{grant_index}"
        if not self.trust:
            authorization = {
                "schema": "chio.example.ioa-web3.budget-authorization.v1",
                "source": "offline",
                "allowed": False,
                "holdId": hold_id,
                "reason": "trust-control unavailable",
            }
        else:
            raw = self.trust.authorize_exposure(
                capability_id=capability_id,
                grant_index=grant_index,
                exposure_units=exposure_units,
                hold_id=hold_id,
                event_id=f"{hold_id}:authorize",
                max_invocations=1,
                max_exposure_per_invocation=max_budget_units,
                max_total_exposure_units=max_budget_units,
            )
            authorization = {
                "schema": "chio.example.ioa-web3.budget-authorization.v1",
                "source": "chio-trust-control",
                "holdId": hold_id,
                "capabilityId": capability_id,
                "grantIndex": grant_index,
                "requestedExposureUnits": exposure_units,
                "maxBudgetUnits": max_budget_units,
                "allowed": raw.get("allowed") is True,
                "trustControlResponse": raw,
            }
        self.store.write_json("chio/budgets/quote-exposure-authorization.json", authorization)
        return authorization

    def reconcile_settlement(
        self,
        *,
        capability_id: str,
        grant_index: int,
        order_id: str,
        exposed_cost_units: int,
        realized_spend_units: int,
    ) -> Json:
        hold_id = f"budget-hold:{order_id}:{capability_id}:{grant_index}"
        if not self.trust:
            reconciliation = {
                "schema": "chio.example.ioa-web3.budget-reconciliation.v1",
                "source": "offline",
                "status": "unreconciled",
                "holdId": hold_id,
                "reason": "trust-control unavailable",
            }
        else:
            raw = self.trust.reconcile_spend(
                capability_id=capability_id,
                grant_index=grant_index,
                exposed_cost_units=exposed_cost_units,
                realized_spend_units=realized_spend_units,
                hold_id=hold_id,
                event_id=f"{hold_id}:reconcile",
            )
            reconciliation = {
                "schema": "chio.example.ioa-web3.budget-reconciliation.v1",
                "source": "chio-trust-control",
                "status": "reconciled",
                "holdId": hold_id,
                "capabilityId": capability_id,
                "grantIndex": grant_index,
                "exposedCostUnits": exposed_cost_units,
                "realizedSpendUnits": realized_spend_units,
                "trustControlResponse": raw,
            }
        self.store.write_json("chio/budgets/settlement-spend-reconciliation.json", reconciliation)
        return reconciliation

    def write_summary(self, authorization: Json, reconciliation: Json) -> Json:
        summary = {
            "schema": "chio.example.ioa-web3.budget-summary.v1",
            "authorizationStatus": "authorized" if authorization.get("allowed") else "denied",
            "reconciliationStatus": reconciliation.get("status"),
            "authorizedExposureUnits": authorization.get("requestedExposureUnits", 0),
            "realizedSpendUnits": reconciliation.get("realizedSpendUnits", 0),
            "source": "chio-trust-control" if self.trust else "offline",
        }
        self.store.write_json("chio/budgets/budget-summary.json", summary)
        return summary

    def overspend_negative_control(
        self,
        *,
        capability_id: str,
        grant_index: int,
        order_id: str,
        max_budget_units: int,
    ) -> Json:
        hold_id = f"budget-hold:{order_id}:overspend:{capability_id}:{grant_index}"
        try:
            if not self.trust:
                raise ChioHttpError("offline", 0, "trust-control unavailable")
            raw = self.trust.authorize_exposure(
                capability_id=capability_id,
                grant_index=grant_index,
                exposure_units=max_budget_units + 1,
                hold_id=hold_id,
                event_id=f"{hold_id}:authorize",
                max_invocations=1,
                max_exposure_per_invocation=max_budget_units,
                max_total_exposure_units=max_budget_units,
            )
            denied = raw.get("allowed") is False
            response: Json = raw
        except ChioHttpError as exc:
            denied = True
            response = {"status": exc.status, "body": exc.body}
        control = {
            "schema": "chio.example.ioa-web3.guardrail-denial.v1",
            "control": "overspend",
            "boundary": "chio-trust-control:/v1/budgets/authorize-exposure",
            "denied": denied,
            "receipt": {
                "schema": "chio.example.ioa-web3.denial-receipt.v1",
                "id": f"denial-overspend-{order_id}",
                "kind": "budget",
                "decision": "deny" if denied else "allow",
            },
            "response": response,
        }
        self.store.write_json("guardrails/overspend-denial.json", control)
        return control

