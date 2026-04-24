"use client";

import { useEffect, useState } from "react";

import { useBundle } from "@/components/BundleProvider";
import type { BudgetSummary, Summary } from "@/lib/types";

interface ChromeProps {
  summary: Summary;
}

interface RollupCounts {
  receiptsTotal: number;
  boundaryCount: number;
  adversarialDenials: number;
  guardrailDenials: number;
}

function rollup(summary: Summary): RollupCounts {
  const boundaries = summary.receipt_counts_by_boundary ?? {};
  const receiptsTotal = Object.values(boundaries).reduce<number>(
    (sum, n) => sum + (typeof n === "number" ? n : 0),
    0,
  );
  const adv = summary.adversarial_denial_status ?? {};
  const adversarialDenials = Object.values(adv).filter((v) => v === "denied").length;
  const gua = summary.guardrail_denial_status ?? {};
  // Guardrail denials are always-fired per scenario; every entry counts.
  const guardrailDenials = Object.keys(gua).length;
  return {
    receiptsTotal,
    boundaryCount: Object.keys(boundaries).length,
    adversarialDenials,
    guardrailDenials,
  };
}

export function Chrome({ summary }: ChromeProps): JSX.Element {
  const { fetchArtifact } = useBundle();
  const [txCount, setTxCount] = useState<number | null>(null);
  const [txStatus, setTxStatus] = useState<string>(
    typeof summary.base_sepolia_smoke_status === "string" ? summary.base_sepolia_smoke_status : "n/a",
  );
  const [budget, setBudget] = useState<BudgetSummary | null>(null);
  const [budgetError, setBudgetError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const body = (await fetchArtifact("web3/base-sepolia-smoke.json")) as {
          transactions?: unknown[];
          status?: string;
        } | null;
        if (cancelled) return;
        if (body && Array.isArray(body.transactions)) {
          setTxCount(body.transactions.length);
        } else {
          console.warn("base-sepolia-smoke.json: missing transactions array");
          setTxCount(null);
        }
        if (body && typeof body.status === "string") {
          setTxStatus(body.status);
        }
      } catch (err) {
        if (!cancelled) {
          console.warn("Chrome: failed to load base-sepolia-smoke.json", err);
          setTxCount(null);
        }
      }
    })();
    void (async () => {
      try {
        const body = (await fetchArtifact("chio/budgets/budget-summary.json")) as BudgetSummary;
        if (!cancelled) setBudget(body);
      } catch (err) {
        if (!cancelled) {
          setBudgetError(err instanceof Error ? err.message : String(err));
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [fetchArtifact]);

  const counts = rollup(summary);
  const denialTotal = counts.adversarialDenials + counts.guardrailDenials;

  return (
    <div className="chrome-rail">
      <div className="counter receipts">
        <div className="ck">receipts</div>
        <div className="cv">{counts.receiptsTotal}</div>
        <div className="cs">{counts.boundaryCount} boundaries</div>
      </div>

      <div className="counter ok">
        <div className="ck">denials - {denialTotal} fired</div>
        <div className="cv">{denialTotal}</div>
        <div className="cs">
          adversarial {counts.adversarialDenials} - guardrails {counts.guardrailDenials}
        </div>
      </div>

      <div className="counter chain">
        <div className="ck">base-sepolia tx</div>
        <div className="cv">{txCount !== null ? txCount : "n/a"}</div>
        <div className="cs">status - {txStatus}</div>
      </div>

      <BudgetCounter summary={budget} error={budgetError} />
    </div>
  );
}

interface BudgetCounterProps {
  summary: BudgetSummary | null;
  error: string | null;
}

function BudgetCounter({ summary, error }: BudgetCounterProps): JSX.Element {
  if (error) {
    return (
      <div className="counter">
        <div className="ck">budget</div>
        <div className="cv">n/a</div>
        <div className="cs">load error</div>
      </div>
    );
  }
  if (!summary) {
    return (
      <div className="counter">
        <div className="ck">budget</div>
        <div className="cv">...</div>
        <div className="cs">loading</div>
      </div>
    );
  }

  const authorized = typeof summary.authorizedExposureUnits === "number" ? summary.authorizedExposureUnits : null;
  const realized = typeof summary.realizedSpendUnits === "number" ? summary.realizedSpendUnits : null;
  const pct = authorized && authorized > 0 && realized !== null
    ? (realized / authorized) * 100
    : 0;
  const auth = summary.authorizationStatus ?? "unknown";
  const recon = summary.reconciliationStatus ?? "unknown";

  return (
    <div className="counter">
      <div className="ck">budget authorized</div>
      <div className="cv">
        {authorized !== null ? authorized.toLocaleString() : "n/a"}{" "}
        <span style={{ fontSize: 11, color: "var(--ink-3)" }}>units</span>
      </div>
      <div className="cs">
        spent {realized !== null ? realized.toLocaleString() : "n/a"} - {auth} / {recon}
      </div>
      <div className="bar">
        <div className="fill" style={{ width: `${Math.min(100, pct)}%` }} />
      </div>
    </div>
  );
}
