/* global React */

function Chrome({ summary }) {
  const delegated = BigInt(summary.budget.delegated_wei);
  const remaining = BigInt(summary.budget.remaining_wei);
  const used = delegated - remaining;
  const pct = Number((used * 1000n) / delegated) / 10;

  return (
    <div className="chrome-rail">
      <div className="counter receipts">
        <div className="ck">receipts</div>
        <div className="cv">{summary.receipts.total}</div>
        <div className="cs">
          trust {summary.receipts.trust} · api {summary.receipts.api_sidecar} · mcp {summary.receipts.mcp} · lineage {summary.receipts.lineage}
        </div>
      </div>

      <div className="counter ok">
        <div className="ck">denials · 6/6 fired</div>
        <div className="cv">{summary.denials.total}</div>
        <div className="cs">
          adversarial {summary.denials.adversarial} · guardrails {summary.denials.guardrails}
        </div>
      </div>

      <div className="counter chain">
        <div className="ck">base-sepolia tx</div>
        <div className="cv">{summary.base_sepolia.tx_count}</div>
        <div className="cs">status · {summary.base_sepolia.status}</div>
      </div>

      <div className="counter">
        <div className="ck">budget delegated</div>
        <div className="cv">{(Number(delegated) / 1e18).toFixed(2)} <span style={{fontSize:11,color:"var(--ink-3)"}}>ETH</span></div>
        <div className="cs">remaining {(Number(remaining) / 1e18).toFixed(2)} · used {pct.toFixed(1)}%</div>
        <div className="bar"><div className="fill" style={{width: `${pct}%`}}/></div>
      </div>
    </div>
  );
}

window.Chrome = Chrome;
