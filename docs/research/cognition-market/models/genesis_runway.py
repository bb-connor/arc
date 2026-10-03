#!/usr/bin/env python3
"""Minimal, deterministic Genesis treasury recurrence.

This is a structural model, not a forecast. Edit the explicit assumptions in
SCENARIOS, rerun it, and review the sensitivity before approving a pool or
carve cap. It uses only the Python standard library.
"""

from dataclasses import dataclass, replace
from math import isfinite


@dataclass(frozen=True)
class Assumptions:
    months: int = 36
    sustain_months: int = 3
    pool: float = 75_000
    admissions_per_month: int = 300
    harvest_share: float = 1.0
    commissioned_cost: float = 0
    floor_initial: float = 6
    floor_decay: float = 0.93
    new_audit_rate: float = 0.20
    corpus_audit_rate: float = 0.01
    audit_cost: float = 10
    initial_corpus: int = 0
    corpus_staleness: float = 0.05
    demanded_descriptors_per_month: int = 150
    organic_admissions_per_month: int = 0
    clearings_per_month: int = 0
    average_seller_price: float = 10
    clearing_fee_bps: int = 400
    operator_spread_share: float = 0.10
    carve_share: float = 0.25


def run(a: Assumptions) -> dict[str, float | int | str]:
    if a.months <= 0 or a.sustain_months <= 0:
        raise ValueError("month counts must be positive")
    if any(not isfinite(value) or value < 0 for value in vars(a).values()):
        raise ValueError("assumptions must be non-negative")
    if any(
        not 0 <= value <= 1
        for value in (
            a.harvest_share,
            a.floor_decay,
            a.new_audit_rate,
            a.corpus_audit_rate,
            a.corpus_staleness,
            a.operator_spread_share,
            a.carve_share,
        )
    ):
        raise ValueError("rates and shares must be in [0, 1]")
    if not 0 <= a.clearing_fee_bps <= 10_000:
        raise ValueError("clearing_fee_bps must be in [0, 10_000]")
    balance = a.pool
    corpus = float(a.initial_corpus)
    floors = production = audits = fee_offset = 0.0
    self_sustain_streak = 0

    for month in range(a.months):
        genesis_admissions = a.admissions_per_month
        total_new_admissions = genesis_admissions + a.organic_admissions_per_month
        floor_spend = genesis_admissions * a.floor_initial * (a.floor_decay**month)
        production_spend = (
            genesis_admissions * (1 - a.harvest_share) * a.commissioned_cost
        )
        audit_spend = (
            a.new_audit_rate * total_new_admissions + a.corpus_audit_rate * corpus
        ) * a.audit_cost
        available_fee = (
            a.clearings_per_month
            * a.average_seller_price
            * a.clearing_fee_bps
            / 10_000
            * (1 - a.operator_spread_share)
            * (1 - a.carve_share)
        )
        audit_top_up = max(audit_spend - available_fee, 0)
        committed = floor_spend + production_spend + audit_top_up
        if balance < committed:
            return {
                "verdict": "EXHAUST",
                "month": month + 1,
                "balance": balance,
                "floors": floors,
                "production": production,
                "audits": audits,
                "fee_offset": fee_offset,
            }
        balance -= committed
        floors += floor_spend
        production += production_spend
        audits += audit_spend
        fee_offset += min(audit_spend, available_fee)
        corpus = corpus * (1 - a.corpus_staleness) + total_new_admissions

        security_self_funding = available_fee >= audit_spend
        organic_takeover = (
            a.organic_admissions_per_month >= a.demanded_descriptors_per_month
        )
        self_sustain_streak = (
            self_sustain_streak + 1
            if security_self_funding and organic_takeover
            else 0
        )
        if self_sustain_streak >= a.sustain_months:
            return {
                "verdict": "SELF_SUSTAIN",
                "month": month + 1,
                "balance": balance,
                "floors": floors,
                "production": production,
                "audits": audits,
                "fee_offset": fee_offset,
            }

    return {
        "verdict": "ZOMBIE",
        "month": a.months,
        "balance": balance,
        "floors": floors,
        "production": production,
        "audits": audits,
        "fee_offset": fee_offset,
    }


# Illustrative smoke-test values only. Funding inputs require named owners and
# evidence references in the proposal that invokes this model.
BASE = Assumptions()
SCENARIOS = {
    "harvest_no_demand": BASE,
    "commissioned_no_demand": replace(
        BASE, harvest_share=0.25, commissioned_cost=25
    ),
    "harvest_with_takeover": replace(
        BASE, clearings_per_month=6_000, organic_admissions_per_month=150
    ),
}


def main() -> None:
    for name, assumptions in SCENARIOS.items():
        result = run(assumptions)
        print(name, result)

    assert run(BASE)["production"] == 0
    assert run(SCENARIOS["commissioned_no_demand"])["production"] > 0
    assert run(replace(BASE, pool=0))["verdict"] == "EXHAUST"
    assert run(SCENARIOS["harvest_with_takeover"])["month"] == BASE.sustain_months


if __name__ == "__main__":
    main()
