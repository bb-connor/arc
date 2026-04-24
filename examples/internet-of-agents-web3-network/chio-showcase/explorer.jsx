/* global React */
const { useState: useStateE, useMemo: useMemoE } = React;

function Explorer({ bundle, selectedPath, onSelectPath, filter, onFilter }) {
  const { manifest, fileContent } = bundle;
  const content = useMemoE(() => fileContent(selectedPath), [selectedPath]);
  const fileMeta = manifest.files.find((f) => f.path === selectedPath);

  return (
    <div className="explorer-grid">
      <div className="explorer-col">
        <div className="col-title">
          <span>tree · artifact-dir</span>
          <span className="n">{manifest.file_count}</span>
        </div>
        <Tree
          manifest={manifest}
          selectedPath={selectedPath}
          onSelect={onSelectPath}
          filter={filter}
          onFilter={onFilter}
        />
      </div>
      <div className="explorer-col">
        <div className="col-title">
          <span>json viewer</span>
          <span className="n">{selectedPath ? "read-only" : "—"}</span>
        </div>
        {selectedPath ? (
          <>
            <JsonHeader path={selectedPath} meta={fileMeta}/>
            <div className="json-body">
              <JsonTree value={content} depth={0} rootKey={null} defaultOpen={2}/>
            </div>
          </>
        ) : (
          <div className="json-body muted">Select an artifact.</div>
        )}
      </div>
      <div className="explorer-col">
        <div className="col-title">
          <span>lineage · cross-refs</span>
        </div>
        <LineagePane bundle={bundle} path={selectedPath} onJump={onSelectPath}/>
      </div>
    </div>
  );
}

/* ---- Tree ---- */
const SECTIONS = [
  { id: "review", label: "Verdict", paths: ["review-result.json", "summary.json", "bundle-manifest.json"] },
  { id: "chio", label: "Chio mediation" },
  { id: "market", label: "Market" },
  { id: "adversarial", label: "Adversarial" },
  { id: "guardrails", label: "Guardrails" },
  { id: "identity", label: "Identity" },
  { id: "federation", label: "Federation" },
  { id: "reputation", label: "Reputation" },
  { id: "subcontracting", label: "Subcontracting" },
  { id: "approvals", label: "Approvals" },
  { id: "payments", label: "Payments" },
  { id: "settlement", label: "Settlement" },
  { id: "rails", label: "Rails" },
  { id: "web3", label: "Web3 · Base Sepolia" },
  { id: "operations", label: "Operations" },
  { id: "disputes", label: "Disputes" },
];

function Tree({ manifest, selectedPath, onSelect, filter, onFilter }) {
  const [open, setOpen] = useStateE(() => new Set(["chio", "adversarial", "web3"]));
  const f = (filter || "").trim().toLowerCase();

  const bySection = useMemoE(() => {
    const map = {};
    for (const s of SECTIONS) map[s.id] = [];
    for (const file of manifest.files) {
      if (f && !file.path.toLowerCase().includes(f)) continue;
      if (file.path === "review-result.json" || file.path === "summary.json" || file.path === "bundle-manifest.json") {
        map.review.push(file);
      } else {
        const top = file.path.split("/")[0];
        if (map[top]) map[top].push(file);
      }
    }
    return map;
  }, [manifest, f]);

  const toggle = (id) => {
    const s = new Set(open);
    s.has(id) ? s.delete(id) : s.add(id);
    setOpen(s);
  };

  return (
    <>
      <div className="tree-filter">
        <input
          placeholder="/ filter …"
          value={filter}
          onChange={(e) => onFilter(e.target.value)}
        />
      </div>
      <div className="tree">
        {SECTIONS.map((s) => {
          const files = bySection[s.id] || [];
          if (!files.length && f) return null;
          const isOpen = open.has(s.id) || !!f;
          return (
            <div className="tree-group" key={s.id}>
              <div className="tree-row" onClick={() => toggle(s.id)} style={{background:"transparent", fontWeight:500}}>
                <span className="caret">{isOpen ? "▾" : "▸"}</span>
                <span className="label muted" style={{textTransform:"uppercase", letterSpacing:"0.15em", fontSize:10}}>{s.label}</span>
                <span className="count">{files.length}</span>
              </div>
              {isOpen && files.map((file) => (
                <div
                  key={file.path}
                  className={"tree-row" + (file.path === selectedPath ? " selected" : "")}
                  onClick={() => onSelect(file.path)}
                  title={file.path}
                >
                  <span className="caret"></span>
                  <span className={"hash-dot" + (!file.hash_match ? " fail" : "")} />
                  <span className="label">{file.path.split("/").slice(1).join("/") || file.path}</span>
                </div>
              ))}
            </div>
          );
        })}
      </div>
    </>
  );
}

/* ---- JSON header ---- */
function JsonHeader({ path, meta }) {
  if (!meta) return (
    <div className="json-header">
      <div className="path">{path}</div>
      <div className="hash-grid">
        <span className="hk">sha256</span><span className="hv muted">—</span>
      </div>
    </div>
  );
  return (
    <div className="json-header">
      <div className="path">{path}</div>
      <div className="hash-grid">
        <span className="hk">expected</span><span className="hv">{meta.sha256}</span>
        <span className="hk">computed</span><span className={"hv" + (meta.hash_match ? " match" : "")}>{meta.sha256}</span>
        <span className="hk">bytes</span><span className="hv">{meta.bytes.toLocaleString()}</span>
        {meta.signer && <>
          <span className="hk">signer</span><span className="hv signer">{meta.signer}</span>
          <span className="hk">sig</span><span className="hv" style={{color:"#34d399"}}>{meta.signature_verdict.toUpperCase()}</span>
        </>}
      </div>
    </div>
  );
}

/* ---- JSON pretty printer with collapse ---- */
function JsonTree({ value, depth, rootKey, defaultOpen }) {
  const [open, setOpen] = useStateE(depth <= (defaultOpen ?? 2));
  const indent = { paddingLeft: depth === 0 ? 0 : 14 };

  if (value === null) return <span className="jn">null</span>;
  if (typeof value === "string") return <span className="js">"{value}"</span>;
  if (typeof value === "number") return <span className="jn">{value}</span>;
  if (typeof value === "boolean") return <span className="jb">{String(value)}</span>;

  const isArr = Array.isArray(value);
  const entries = isArr ? value.map((v, i) => [i, v]) : Object.entries(value);
  const openCh = isArr ? "[" : "{";
  const closeCh = isArr ? "]" : "}";

  return (
    <div style={indent}>
      <span className="collapsible" onClick={() => setOpen(!open)}>
        <span style={{color:"#5b6470"}}>{open ? "▾" : "▸"} </span>
        {rootKey !== null && rootKey !== undefined && <><span className="jk">"{rootKey}"</span>: </>}
        <span style={{color:"#8d96a3"}}>{openCh}</span>
        {!open && <span className="collapsed"> {entries.length} {isArr ? "items" : "keys"} </span>}
        {!open && <span style={{color:"#8d96a3"}}>{closeCh}</span>}
      </span>
      {open && (
        <div>
          {entries.map(([k, v], i) => (
            <div key={k}>
              {isArr ? (
                <div style={{paddingLeft:14}}>
                  <JsonTree value={v} depth={depth+1} rootKey={null} defaultOpen={defaultOpen}/>
                  {i < entries.length - 1 && <span style={{color:"#5b6470"}}>,</span>}
                </div>
              ) : (
                typeof v === "object" && v !== null ? (
                  <JsonTree value={v} depth={depth+1} rootKey={k} defaultOpen={defaultOpen}/>
                ) : (
                  <div style={{paddingLeft:14}}>
                    <span className="jk">"{k}"</span>
                    <span style={{color:"#5b6470"}}>: </span>
                    <JsonTree value={v} depth={depth+1} rootKey={null} defaultOpen={defaultOpen}/>
                    {i < entries.length - 1 && <span style={{color:"#5b6470"}}>,</span>}
                  </div>
                )
              )}
            </div>
          ))}
          <div style={{paddingLeft: 14 * (depth>0?0:0)}}><span style={{color:"#8d96a3"}}>{closeCh}</span></div>
        </div>
      )}
    </div>
  );
}

/* ---- Lineage pane ---- */
function LineagePane({ bundle, path, onJump }) {
  if (!path) return <div className="lineage-body muted">—</div>;
  const content = bundle.fileContent(path);

  const isReceipt = path.startsWith("chio/receipts/");
  const isCap = path.startsWith("chio/capabilities/");
  const isDenial = path.startsWith("adversarial/") || path.startsWith("guardrails/");
  const isTx = path.startsWith("web3/base-sepolia");
  const isApproval = path.startsWith("approvals/");
  const isSubcontract = path.startsWith("subcontracting/");

  return (
    <div className="lineage-body">
      <div className="lineage-sec">
        <h6>Policy rule</h6>
        {content.policy_rule_fired ? (
          <div className="lineage-link policy">{content.policy_rule_fired}</div>
        ) : content.policy_rule ? (
          <div className="lineage-link">{content.policy_rule}</div>
        ) : <div className="muted" style={{fontSize:10}}>n/a</div>}
      </div>

      {isCap && content.delegation_chain && (
        <div className="lineage-sec">
          <h6>Delegation chain</h6>
          <div className="chain">
            {content.delegation_chain.map((x, i) => (
              <span key={i}>
                {x}{i < content.delegation_chain.length - 1 && <span className="arrow">→</span>}
              </span>
            ))}
          </div>
        </div>
      )}

      {isReceipt && (
        <div className="lineage-sec">
          <h6>Issuing capability</h6>
          <div className="lineage-link cap" onClick={() => onJump("chio/capabilities/procurement-rfq-lorem.json")}>
            chio/capabilities/procurement-rfq-lorem.json
          </div>
        </div>
      )}

      {isDenial && (
        <div className="lineage-sec">
          <h6>Denial receipt</h6>
          <div className="lineage-link receipt" onClick={() => onJump("chio/receipts/trust/atlas-proofworks-lorem.json")}>
            chio/receipts/trust/atlas-proofworks-lorem.json
          </div>
          <h6 style={{marginTop:12}}>Input that fired</h6>
          <pre style={{margin:0, fontSize:10, color:"#f43f5e", background:"var(--bg-2)", padding:"6px 8px", borderLeft:"2px solid #f43f5e", overflow:"auto"}}>
{JSON.stringify(content.input_snippet || {}, null, 2)}
          </pre>
        </div>
      )}

      {isTx && (
        <div className="lineage-sec">
          <h6>On-chain evidence</h6>
          <div className="lineage-link tx">
            {content.tx_hash?.slice(0, 24)}…
          </div>
          <div className="muted" style={{fontSize:10, marginTop:4}}>
            block {content.block_number} · {content.status}
          </div>
          <div className="lineage-link" style={{marginTop:6}}>
            ↗ {content.explorer}
          </div>
        </div>
      )}

      {isApproval && (
        <div className="lineage-sec">
          <h6>Budget envelope</h6>
          <div className="lineage-link cap" onClick={() => onJump("chio/capabilities/treasury-budget-lorem.json")}>
            chio/capabilities/treasury-budget-lorem.json
          </div>
        </div>
      )}

      {isSubcontract && (
        <div className="lineage-sec">
          <h6>Two-hop lineage</h6>
          <div className="lineage-link cap" onClick={() => onJump("chio/capabilities/provider-award-lorem.json")}>
            parent · provider-award
          </div>
          <div className="lineage-link cap" onClick={() => onJump("chio/capabilities/subcontract-cipherworks-lorem.json")}>
            child · subcontract-cipherworks
          </div>
        </div>
      )}

      <div className="lineage-sec">
        <h6>Produced receipts</h6>
        <div className="lineage-link receipt" onClick={() => onJump("chio/receipts/api-sidecar/market-broker-rfq-lorem.json")}>
          chio/receipts/api-sidecar/market-broker-rfq-lorem.json
        </div>
        <div className="lineage-link receipt" onClick={() => onJump("chio/receipts/lineage/subcontract-two-hop-lorem.json")}>
          chio/receipts/lineage/subcontract-two-hop-lorem.json
        </div>
      </div>

      <div className="lineage-sec">
        <h6>Cross-refs</h6>
        <div className="lineage-link" onClick={() => onJump("operations/trace-map.json")}>operations/trace-map.json</div>
        <div className="lineage-link" onClick={() => onJump("bundle-manifest.json")}>bundle-manifest.json</div>
      </div>
    </div>
  );
}

window.Explorer = Explorer;
