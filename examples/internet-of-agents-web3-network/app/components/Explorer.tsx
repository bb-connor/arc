"use client";

import { useEffect, useMemo, useState } from "react";

import { useBundle } from "@/components/BundleProvider";
import { SECTIONS } from "@/lib/paths";
import type { Manifest } from "@/lib/types";

interface ExplorerProps {
  selectedPath: string;
  onSelectPath: (p: string) => void;
  filter: string;
  onFilter: (s: string) => void;
}

export function Explorer({
  selectedPath,
  onSelectPath,
  filter,
  onFilter,
}: ExplorerProps): JSX.Element {
  const { bundle, fetchArtifact, computedHashFor } = useBundle();
  const manifest: Manifest | null = bundle?.manifest ?? null;
  const [content, setContent] = useState<unknown>(null);
  const [fetchError, setFetchError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setFetchError(null);
    if (!selectedPath) {
      setContent(null);
      return () => {
        cancelled = true;
      };
    }
    fetchArtifact(selectedPath)
      .then((body) => {
        if (!cancelled) setContent(body);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setFetchError(err instanceof Error ? err.message : String(err));
        setContent(null);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedPath, fetchArtifact]);

  if (!manifest) {
    return <div className="json-body muted">Loading manifest...</div>;
  }

  const expectedSha = manifest.sha256[selectedPath];
  const computedHash = computedHashFor(selectedPath);

  return (
    <div className="explorer-grid" data-testid="explorer">
      <div className="explorer-col">
        <div className="col-title">
          <span>tree - artifact-dir</span>
          <span className="n">{manifest.files.length}</span>
        </div>
        <Tree
          manifest={manifest}
          selectedPath={selectedPath}
          onSelect={onSelectPath}
          filter={filter}
          onFilter={onFilter}
          computedHashFor={computedHashFor}
        />
      </div>
      <div className="explorer-col">
        <div className="col-title">
          <span>json viewer</span>
          <span className="n">{selectedPath ? "read-only" : "none"}</span>
        </div>
        {selectedPath ? (
          <>
            <JsonHeader
              path={selectedPath}
              expectedSha256={expectedSha}
              computedSha256={computedHash}
            />
            <div className="json-body">
              {fetchError ? (
                <div className="muted">Failed to load: {fetchError}</div>
              ) : content === null ? (
                <div className="muted">Loading...</div>
              ) : (
                <JsonTree value={content} depth={0} rootKey={null} defaultOpen={2} />
              )}
            </div>
          </>
        ) : (
          <div className="json-body muted">Select an artifact.</div>
        )}
      </div>
      <div className="explorer-col">
        <div className="col-title">
          <span>lineage - cross-refs</span>
        </div>
        <LineagePane
          manifest={manifest}
          path={selectedPath}
          content={content}
          onJump={onSelectPath}
        />
      </div>
    </div>
  );
}

interface TreeProps {
  manifest: Manifest;
  selectedPath: string;
  onSelect: (p: string) => void;
  filter: string;
  onFilter: (s: string) => void;
  computedHashFor: (p: string) => string | undefined;
}

function Tree({
  manifest,
  selectedPath,
  onSelect,
  filter,
  onFilter,
  computedHashFor,
}: TreeProps): JSX.Element {
  const [open, setOpen] = useState<Set<string>>(() => new Set(["chio", "adversarial", "web3"]));
  const f = (filter || "").trim().toLowerCase();

  const bySection = useMemo<Record<string, string[]>>(() => {
    const map: Record<string, string[]> = {};
    for (const s of SECTIONS) map[s.id] = [];
    for (const filePath of manifest.files) {
      if (f && !filePath.toLowerCase().includes(f)) continue;
      if (
        filePath === "review-result.json" ||
        filePath === "summary.json" ||
        filePath === "bundle-manifest.json"
      ) {
        map["review"]?.push(filePath);
      } else {
        const top = filePath.split("/")[0] ?? "";
        const bucket = map[top];
        if (bucket) bucket.push(filePath);
      }
    }
    return map;
  }, [manifest, f]);

  const toggle = (id: string) => {
    const s = new Set(open);
    if (s.has(id)) s.delete(id);
    else s.add(id);
    setOpen(s);
  };

  return (
    <>
      <div className="tree-filter">
        <input
          placeholder="/ filter ..."
          value={filter}
          onChange={(e) => onFilter(e.target.value)}
          aria-label="Filter artifacts"
        />
      </div>
      <div className="tree">
        {SECTIONS.map((s) => {
          const files = bySection[s.id] ?? [];
          if (!files.length && f) return null;
          const isOpen = open.has(s.id) || Boolean(f);
          return (
            <div className="tree-group" key={s.id}>
              <div
                className="tree-row"
                onClick={() => toggle(s.id)}
                style={{ background: "transparent", fontWeight: 500 }}
              >
                <span className="caret">{isOpen ? "▾" : "▸"}</span>
                <span
                  className="label muted"
                  style={{ textTransform: "uppercase", letterSpacing: "0.15em", fontSize: 10 }}
                >
                  {s.label}
                </span>
                <span className="count">{files.length}</span>
              </div>
              {isOpen &&
                files.map((filePath) => {
                  const expected = manifest.sha256[filePath];
                  const computed = computedHashFor(filePath);
                  const mismatch =
                    expected && computed
                      ? !matchesHash(expected, computed)
                      : false;
                  return (
                    <div
                      key={filePath}
                      className={`tree-row${filePath === selectedPath ? " selected" : ""}`}
                      onClick={() => onSelect(filePath)}
                      title={filePath}
                    >
                      <span className="caret" />
                      <span className={`hash-dot${mismatch ? " fail" : ""}`} />
                      <span className="label">
                        {filePath.split("/").slice(1).join("/") || filePath}
                      </span>
                    </div>
                  );
                })}
            </div>
          );
        })}
      </div>
    </>
  );
}

function matchesHash(expected: string, computedHex: string): boolean {
  const normalized = expected.startsWith("sha256:") ? expected.slice("sha256:".length) : expected;
  const trimmed = normalized.replace(/[^0-9a-f]/gi, "").toLowerCase();
  return trimmed === computedHex.toLowerCase();
}

interface JsonHeaderProps {
  path: string;
  expectedSha256: string | undefined;
  computedSha256: string | undefined;
}

function JsonHeader({ path, expectedSha256, computedSha256 }: JsonHeaderProps): JSX.Element {
  if (!expectedSha256) {
    return (
      <div className="json-header">
        <div className="path">{path}</div>
        <div className="hash-grid">
          <span className="hk">sha256</span>
          <span className="hv muted">-</span>
          <span className="hk">note</span>
          <span className="hv muted">not in manifest.sha256</span>
        </div>
      </div>
    );
  }
  const clean = expectedSha256.replace(/[^0-9a-f]/gi, "").toLowerCase();
  const match = computedSha256 ? clean === computedSha256.toLowerCase() : undefined;
  const statusClass = match === undefined ? "" : match ? " match" : " mismatch";

  return (
    <div className="json-header">
      <div className="path">{path}</div>
      <div className="hash-grid">
        <span className="hk">expected</span>
        <span className="hv">{expectedSha256}</span>
        <span className="hk">computed</span>
        <span className={`hv${statusClass}`}>{computedSha256 ?? "(pending)"}</span>
      </div>
    </div>
  );
}

interface JsonTreeProps {
  value: unknown;
  depth: number;
  rootKey: string | number | null;
  defaultOpen: number;
}

function JsonTree({ value, depth, rootKey, defaultOpen }: JsonTreeProps): JSX.Element {
  const [open, setOpen] = useState<boolean>(depth <= defaultOpen);
  const indent = { paddingLeft: depth === 0 ? 0 : 14 } as const;

  if (value === null) return <span className="jn">null</span>;
  if (typeof value === "string") return <span className="js">&quot;{value}&quot;</span>;
  if (typeof value === "number") return <span className="jn">{value}</span>;
  if (typeof value === "boolean") return <span className="jb">{String(value)}</span>;

  const isArr = Array.isArray(value);
  const entries: Array<[string | number, unknown]> = isArr
    ? (value as unknown[]).map((v, i) => [i, v])
    : Object.entries(value as Record<string, unknown>);
  const openCh = isArr ? "[" : "{";
  const closeCh = isArr ? "]" : "}";

  return (
    <div style={indent}>
      <span className="collapsible" onClick={() => setOpen(!open)}>
        <span style={{ color: "#5b6470" }}>{open ? "▾" : "▸"} </span>
        {rootKey !== null && rootKey !== undefined ? (
          <>
            <span className="jk">&quot;{String(rootKey)}&quot;</span>:{" "}
          </>
        ) : null}
        <span style={{ color: "#8d96a3" }}>{openCh}</span>
        {!open ? (
          <>
            <span className="collapsed">
              {" "}
              {entries.length} {isArr ? "items" : "keys"}{" "}
            </span>
            <span style={{ color: "#8d96a3" }}>{closeCh}</span>
          </>
        ) : null}
      </span>
      {open ? (
        <div>
          {entries.map(([k, v], i) => (
            <div key={String(k)}>
              {isArr ? (
                <div style={{ paddingLeft: 14 }}>
                  <JsonTree value={v} depth={depth + 1} rootKey={null} defaultOpen={defaultOpen} />
                  {i < entries.length - 1 ? <span style={{ color: "#5b6470" }}>,</span> : null}
                </div>
              ) : typeof v === "object" && v !== null ? (
                <JsonTree value={v} depth={depth + 1} rootKey={k} defaultOpen={defaultOpen} />
              ) : (
                <div style={{ paddingLeft: 14 }}>
                  <span className="jk">&quot;{String(k)}&quot;</span>
                  <span style={{ color: "#5b6470" }}>: </span>
                  <JsonTree value={v} depth={depth + 1} rootKey={null} defaultOpen={defaultOpen} />
                  {i < entries.length - 1 ? <span style={{ color: "#5b6470" }}>,</span> : null}
                </div>
              )}
            </div>
          ))}
          <div>
            <span style={{ color: "#8d96a3" }}>{closeCh}</span>
          </div>
        </div>
      ) : null}
    </div>
  );
}

interface LineagePaneProps {
  manifest: Manifest;
  path: string;
  content: unknown;
  onJump: (p: string) => void;
}

function LineagePane({ manifest, path, content, onJump }: LineagePaneProps): JSX.Element {
  if (!path) return <div className="lineage-body muted">-</div>;
  const hasFile = (p: string): boolean => manifest.files.includes(p);
  const obj = (content && typeof content === "object") ? (content as Record<string, unknown>) : {};

  const isReceipt = path.startsWith("chio/receipts/");
  const isCap = path.startsWith("chio/capabilities/") || path.startsWith("capabilities/");
  const isDenial = path.startsWith("adversarial/") || path.startsWith("guardrails/");
  const isTx = path.startsWith("web3/base-sepolia");
  const isApproval = path.startsWith("approvals/");
  const isSubcontract = path.startsWith("subcontracting/");

  const delegationChain = Array.isArray(obj["delegation_chain"])
    ? (obj["delegation_chain"] as unknown[]).map((s) => String(s))
    : null;

  const inputSnippet = obj["input_snippet"];
  const policyRuleFired = typeof obj["policy_rule_fired"] === "string" ? (obj["policy_rule_fired"] as string) : null;
  const policyRule = typeof obj["policy_rule"] === "string" ? (obj["policy_rule"] as string) : null;
  const txHash = typeof obj["tx_hash"] === "string" ? (obj["tx_hash"] as string) : null;
  const blockNumber = typeof obj["block_number"] === "number" ? (obj["block_number"] as number) : null;
  const statusRaw = typeof obj["status"] === "string" ? (obj["status"] as string) : null;
  const explorer = typeof obj["explorer"] === "string" ? (obj["explorer"] as string) : null;

  // Pick real manifest paths for cross-ref jumps.
  const firstCap = manifest.files.find((p) => p.startsWith("chio/capabilities/")) ?? null;
  const firstReceipt = manifest.files.find((p) => p.startsWith("chio/receipts/")) ?? null;
  const firstSubcontractParent =
    manifest.files.find((p) => p === "capabilities/provider-agent.json") ??
    manifest.files.find((p) => p.startsWith("capabilities/") && p.includes("provider")) ?? null;
  const firstSubcontractChild =
    manifest.files.find((p) => p === "capabilities/subcontractor-agent.json") ??
    manifest.files.find((p) => p.startsWith("capabilities/") && p.includes("subcontract")) ?? null;
  const budgetEnvelope =
    manifest.files.find((p) => p === "chio/budgets/budget-summary.json") ??
    manifest.files.find((p) => p.startsWith("chio/budgets/")) ?? null;

  const JumpLink = ({
    target,
    label,
    cls,
  }: {
    target: string | null;
    label: string;
    cls: string;
  }): JSX.Element | null => {
    if (!target || !hasFile(target)) return null;
    return (
      <div className={cls} onClick={() => onJump(target)}>
        {label}
      </div>
    );
  };

  return (
    <div className="lineage-body">
      <div className="lineage-sec">
        <h6>Policy rule</h6>
        {policyRuleFired ? (
          <div className="lineage-link policy">{policyRuleFired}</div>
        ) : policyRule ? (
          <div className="lineage-link">{policyRule}</div>
        ) : (
          <div className="muted" style={{ fontSize: 10 }}>n/a</div>
        )}
      </div>

      {isCap && delegationChain ? (
        <div className="lineage-sec">
          <h6>Delegation chain</h6>
          <div className="chain">
            {delegationChain.map((x, i) => (
              <span key={i}>
                {x}
                {i < delegationChain.length - 1 ? <span className="arrow">-&gt;</span> : null}
              </span>
            ))}
          </div>
        </div>
      ) : null}

      {isReceipt ? (
        <div className="lineage-sec">
          <h6>Issuing capability</h6>
          <JumpLink target={firstCap} label={firstCap ?? "(none)"} cls="lineage-link cap" />
        </div>
      ) : null}

      {isDenial ? (
        <div className="lineage-sec">
          <h6>Denial receipt</h6>
          <JumpLink target={firstReceipt} label={firstReceipt ?? "(none)"} cls="lineage-link receipt" />
          <h6 style={{ marginTop: 12 }}>Input that fired</h6>
          <pre
            style={{
              margin: 0,
              fontSize: 10,
              color: "#f43f5e",
              background: "var(--bg-2)",
              padding: "6px 8px",
              borderLeft: "2px solid #f43f5e",
              overflow: "auto",
            }}
          >
            {JSON.stringify(inputSnippet ?? {}, null, 2)}
          </pre>
        </div>
      ) : null}

      {isTx ? (
        <div className="lineage-sec">
          <h6>On-chain evidence</h6>
          <div className="lineage-link tx">{txHash ? `${txHash.slice(0, 24)}...` : "-"}</div>
          <div className="muted" style={{ fontSize: 10, marginTop: 4 }}>
            block {blockNumber ?? "?"} - {statusRaw ?? "?"}
          </div>
          {explorer ? (
            <div className="lineage-link" style={{ marginTop: 6 }}>
              ^ {explorer}
            </div>
          ) : null}
        </div>
      ) : null}

      {isApproval ? (
        <div className="lineage-sec">
          <h6>Budget envelope</h6>
          <JumpLink target={budgetEnvelope} label={budgetEnvelope ?? "(none)"} cls="lineage-link cap" />
        </div>
      ) : null}

      {isSubcontract ? (
        <div className="lineage-sec">
          <h6>Two-hop lineage</h6>
          <JumpLink
            target={firstSubcontractParent}
            label={`parent - ${firstSubcontractParent ?? "(none)"}`}
            cls="lineage-link cap"
          />
          <JumpLink
            target={firstSubcontractChild}
            label={`child - ${firstSubcontractChild ?? "(none)"}`}
            cls="lineage-link cap"
          />
        </div>
      ) : null}

      <div className="lineage-sec">
        <h6>Cross-refs</h6>
        {hasFile("operations/trace-map.json") ? (
          <div className="lineage-link" onClick={() => onJump("operations/trace-map.json")}>
            operations/trace-map.json
          </div>
        ) : null}
        {hasFile("bundle-manifest.json") ? (
          <div className="lineage-link" onClick={() => onJump("bundle-manifest.json")}>
            bundle-manifest.json
          </div>
        ) : null}
      </div>
    </div>
  );
}
