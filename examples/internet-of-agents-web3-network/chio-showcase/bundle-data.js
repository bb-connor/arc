// Mock artifact bundle — clearly placeholder, lorem-style identifiers.
// Modeled after the PRD's artifact contract. Not real data.

window.BUNDLE = (() => {
  const lorem = (n = 8) => {
    const hex = "0123456789abcdef";
    let s = "";
    for (let i = 0; i < n; i++) s += hex[Math.floor(Math.random() * 16)];
    return s;
  };
  // stable hash-like strings (deterministic feel, obviously placeholder)
  const h = (seed) => {
    let x = 0;
    for (let i = 0; i < seed.length; i++) x = (x * 31 + seed.charCodeAt(i)) >>> 0;
    const parts = [];
    for (let i = 0; i < 8; i++) {
      x = (x * 1103515245 + 12345) >>> 0;
      parts.push(x.toString(16).padStart(8, "0"));
    }
    return parts.join("");
  };

  const orgs = {
    atlas: {
      id: "atlas",
      name: "Atlas Treasury",
      role: "Buyer",
      quadrant: "tl",
      trustControlUrl: "https://atlas.example.invalid/.chio/trust",
      color: "#7dd3fc",
      workloads: [
        { id: "atlas.treasury", name: "treasury", kind: "workload" },
        { id: "atlas.procurement", name: "procurement", kind: "workload" },
        { id: "atlas.approver", name: "approver-signer", kind: "workload" },
      ],
      sidecars: [
        { id: "atlas.mkt-broker", name: "market-broker", guards: "atlas.procurement" },
      ],
      mcp: [
        { id: "atlas.mcp.review", name: "provider-review", direction: "out" },
      ],
    },
    proofworks: {
      id: "proofworks",
      name: "ProofWorks",
      role: "Provider (Lorem)",
      quadrant: "tr",
      trustControlUrl: "https://proofworks.example.invalid/.chio/trust",
      color: "#5eead4",
      workloads: [
        { id: "proofworks.provider", name: "provider", kind: "workload" },
        { id: "proofworks.delegator", name: "delegator", kind: "workload" },
      ],
      sidecars: [
        { id: "proofworks.subcontract-desk", name: "subcontract-desk", guards: "proofworks.delegator" },
      ],
      mcp: [
        { id: "proofworks.mcp.review", name: "subcontractor-review", direction: "out" },
      ],
    },
    cipherworks: {
      id: "cipherworks",
      name: "CipherWorks",
      role: "Subcontractor (Lorem)",
      quadrant: "br",
      trustControlUrl: "https://cipherworks.example.invalid/.chio/trust",
      color: "#a78bfa",
      workloads: [
        { id: "cipherworks.subcontractor", name: "subcontractor", kind: "workload" },
        { id: "cipherworks.attestor", name: "attestor", kind: "workload" },
      ],
      sidecars: [],
      mcp: [],
    },
    meridian: {
      id: "meridian",
      name: "Meridian Rails",
      role: "Settlement + Auditor",
      quadrant: "bl",
      trustControlUrl: "https://meridian.example.invalid/.chio/trust",
      color: "#fbbf24",
      workloads: [
        { id: "meridian.settlement", name: "settlement", kind: "workload" },
        { id: "meridian.auditor", name: "auditor", kind: "workload" },
      ],
      sidecars: [
        { id: "meridian.settlement-desk", name: "settlement-desk", guards: "meridian.settlement" },
      ],
      mcp: [
        { id: "meridian.mcp.web3", name: "web3-evidence", direction: "in" },
      ],
    },
  };

  // topology edges
  const edges = [
    // intra-org
    { id: "e1", from: "atlas.treasury", to: "atlas.procurement", kind: "intra", label: "budget-delegation" },
    { id: "e2", from: "atlas.procurement", to: "atlas.mkt-broker", kind: "intra", label: "local" },
    { id: "e3", from: "proofworks.provider", to: "proofworks.delegator", kind: "intra", label: "local" },
    { id: "e4", from: "meridian.settlement", to: "meridian.settlement-desk", kind: "intra", label: "local" },
    // cross-org mediated
    { id: "e5", from: "atlas.mkt-broker", to: "proofworks.provider", kind: "mediated", label: "rfq/award", scope: "market.rfq.respond", ttl: "15m" },
    { id: "e6", from: "proofworks.subcontract-desk", to: "cipherworks.subcontractor", kind: "delegation", label: "two-hop-subcontract", scope: "subcontract.execute", ttl: "10m" },
    { id: "e7", from: "atlas.approver", to: "meridian.settlement-desk", kind: "mediated", label: "approval+x402", scope: "payment.settle", ttl: "5m" },
    { id: "e8", from: "meridian.auditor", to: "meridian.mcp.web3", kind: "intra", label: "evidence.read" },
    { id: "e9", from: "meridian.mcp.web3", to: "cipherworks.attestor", kind: "mediated", label: "attestation-read", scope: "attestation.read", ttl: "1h" },
    // denials (non-pre-rendered; flash)
    { id: "d1", from: "atlas.mkt-broker", to: "proofworks.provider", kind: "denial", label: "forged-passport", reason: "identity.passport.signature.invalid" },
    { id: "d2", from: "atlas.mkt-broker", to: "proofworks.provider", kind: "denial", label: "over-budget-bid", reason: "budget.envelope.exceeded" },
  ];

  // review-result
  const reviewResult = {
    verdict: "PASS",
    generated_at: "2026-04-23T14:07:42Z",
    checks: [
      { id: "bundle.manifest.integrity", status: "pass", hits: 247, misses: 0 },
      { id: "receipts.signature.chain", status: "pass", hits: 189 },
      { id: "capabilities.delegation.consistency", status: "pass", hits: 42 },
      { id: "policy.denials.complete", status: "pass", note: "6/6 adversarial denials fired" },
      { id: "guardrails.spiffe.identity", status: "pass", hits: 3 },
      { id: "web3.validation.ladder", status: "pass", tx_hashes: 4 },
      { id: "lineage.acyclic", status: "pass" },
      { id: "budget.reconciliation", status: "pass", delta_wei: 0 },
    ],
  };

  const summary = {
    run_id: "run-lorem-" + h("run").slice(0, 12),
    orchestrator: "orchestrate.py",
    started_at: "2026-04-23T14:02:18Z",
    completed_at: "2026-04-23T14:07:42Z",
    wall_time_ms: 324_511,
    orgs: 4,
    workloads: 9,
    sidecars: 3,
    mcp_endpoints: 3,
    receipts: { total: 189, trust: 42, api_sidecar: 87, mcp: 28, lineage: 32 },
    capabilities: { issued: 42, delegated: 18, revoked: 0 },
    denials: { total: 6, adversarial: 6, guardrails: 3 },
    base_sepolia: { tx_count: 4, status: "confirmed" },
    budget: { delegated_wei: "5000000000000000000", remaining_wei: "3127500000000000000" },
  };

  const manifestFiles = [
    "review-result.json",
    "summary.json",
    "bundle-manifest.json",
    "chio/topology.json",
    "chio/receipts/trust/atlas-proofworks-lorem.json",
    "chio/receipts/trust/proofworks-cipherworks-lorem.json",
    "chio/receipts/api-sidecar/market-broker-rfq-lorem.json",
    "chio/receipts/api-sidecar/settlement-desk-x402-lorem.json",
    "chio/receipts/mcp/auditor-web3-evidence-lorem.json",
    "chio/receipts/mcp/provider-review-lorem.json",
    "chio/receipts/lineage/subcontract-two-hop-lorem.json",
    "chio/capabilities/treasury-budget-lorem.json",
    "chio/capabilities/procurement-rfq-lorem.json",
    "chio/capabilities/provider-award-lorem.json",
    "chio/capabilities/subcontract-cipherworks-lorem.json",
    "chio/budgets/exposure.json",
    "chio/budgets/reconciliation.json",
    "market/rfq.json",
    "market/bids/bid-proofworks-lorem.json",
    "market/bids/bid-noname-lowrep-lorem.json",
    "market/bids/bid-adversary-forged-lorem.json",
    "market/rejections/low-rep-lorem.json",
    "market/rejections/forged-passport-lorem.json",
    "market/selection.json",
    "adversarial/forged-passport.json",
    "adversarial/expired-capability.json",
    "adversarial/scope-escalation.json",
    "adversarial/replay-attack.json",
    "adversarial/capability-confusion.json",
    "adversarial/mitm-downgrade.json",
    "guardrails/overspend.json",
    "guardrails/velocity-denial.json",
    "guardrails/invalid-spiffe.json",
    "identity/passports/atlas-treasury-lorem.json",
    "identity/passports/proofworks-provider-lorem.json",
    "identity/passports/cipherworks-subcontractor-lorem.json",
    "identity/presentations/proofworks-to-atlas-lorem.json",
    "identity/runtime-appraisals/proofworks-t0.json",
    "identity/runtime-appraisals/proofworks-t1.json",
    "identity/runtime-degradation/proofworks-wobble-lorem.json",
    "identity/runtime-degradation/proofworks-reattest-lorem.json",
    "federation/atlas-proofworks-bilateral.json",
    "federation/admission-proofworks.json",
    "federation/federated-capability-lorem.json",
    "reputation/local-report-proofworks.json",
    "reputation/passport-compare-proofworks.json",
    "reputation/admission-verdict-cipherworks.json",
    "subcontracting/capability.json",
    "subcontracting/obligations.json",
    "subcontracting/attestation.json",
    "approvals/signed-human-lorem.json",
    "payments/x402-proof-lorem.json",
    "settlement/cross-rail-lorem.json",
    "rails/selection.json",
    "web3/validation-ladder.json",
    "web3/base-sepolia-tx-lorem-0xa3f.json",
    "web3/base-sepolia-tx-lorem-0xb72.json",
    "operations/trace-map.json",
    "operations/siem-events.json",
    "operations/timeline.json",
    "disputes/weak-deliverable-lorem.json",
    "disputes/partial-payment-lorem.json",
    "disputes/remediation-lorem.json",
  ];

  const manifest = {
    bundle_sha: "sha256:" + h("bundle").slice(0, 40) + "…",
    generated_at: "2026-04-23T14:07:42Z",
    file_count: manifestFiles.length,
    files: manifestFiles.map((p) => ({
      path: p,
      sha256: "sha256:" + h(p).slice(0, 32) + "…",
      bytes: 400 + (h(p).charCodeAt(0) % 4000),
      signer: p.startsWith("chio/receipts/")
        ? "spiffe://chio.example.invalid/sidecar/lorem"
        : p.startsWith("identity/")
        ? "spiffe://chio.example.invalid/trust-authority/lorem"
        : null,
      signature_verdict: "valid",
      hash_match: true,
    })),
  };

  // File contents — schema-aware placeholders
  const fileContent = (path) => {
    const base = {
      $comment: "LOREM PLACEHOLDER — not real artifact data",
      path,
      sha256: manifest.files.find((f) => f.path === path)?.sha256,
    };
    if (path === "review-result.json") return { ...base, ...reviewResult };
    if (path === "summary.json") return { ...base, ...summary };
    if (path === "bundle-manifest.json") return { ...base, bundle_sha: manifest.bundle_sha, file_count: manifest.file_count, files_preview: manifest.files.slice(0, 6) };
    if (path === "chio/topology.json")
      return {
        ...base,
        orgs: Object.values(orgs).map((o) => ({ id: o.id, name: o.name, role: o.role, trust_control: o.trustControlUrl })),
        edges: edges.filter((e) => e.kind !== "denial").map((e) => ({ from: e.from, to: e.to, kind: e.kind, scope: e.scope || null, ttl: e.ttl || null })),
      };
    if (path.startsWith("chio/receipts/"))
      return {
        ...base,
        receipt_type: path.split("/")[2],
        issuer: "spiffe://chio.example.invalid/sidecar/lorem-" + h(path).slice(0, 6),
        subject: "spiffe://" + path.split("/").pop().replace(".json", ".example.invalid/lorem"),
        policy_rule: "lorem.mediation.v1",
        hash_chain_prev: "sha256:" + h(path + "prev").slice(0, 20) + "…",
        signature: "ed25519:" + h(path + "sig").slice(0, 40) + "…",
        signature_verdict: "valid",
        timestamp: "2026-04-23T14:0" + (2 + (h(path).charCodeAt(0) % 5)) + ":" + (10 + (h(path).charCodeAt(1) % 50)) + "Z",
        related_capability: path.includes("mcp") ? "cap-lorem-" + h(path).slice(0, 8) : null,
      };
    if (path.startsWith("chio/capabilities/"))
      return {
        ...base,
        capability_id: "cap-lorem-" + h(path).slice(0, 10),
        issuer: "spiffe://" + (path.includes("treasury") ? "atlas" : path.includes("provider") ? "proofworks" : "lorem") + ".example.invalid/trust",
        scope: path.includes("budget") ? ["budget.envelope.delegate"] : path.includes("rfq") ? ["market.rfq.respond"] : ["subcontract.execute"],
        ttl_seconds: 900,
        issued_at: "2026-04-23T14:02:45Z",
        expires_at: "2026-04-23T14:17:45Z",
        delegation_chain: [
          "spiffe://atlas.example.invalid/treasury",
          "spiffe://atlas.example.invalid/procurement",
          ...(path.includes("subcontract") ? ["spiffe://proofworks.example.invalid/delegator", "spiffe://cipherworks.example.invalid/subcontractor"] : []),
        ],
      };
    if (path.startsWith("adversarial/") || path.startsWith("guardrails/"))
      return {
        ...base,
        denial_id: "deny-lorem-" + h(path).slice(0, 10),
        attempt: path.split("/").pop().replace(".json", ""),
        mediator: "chio-sidecar-lorem",
        policy_rule_fired: path.includes("forged") ? "identity.passport.signature.invalid"
          : path.includes("overspend") ? "budget.envelope.exceeded"
          : path.includes("velocity") ? "guardrail.velocity.rate-limit"
          : path.includes("spiffe") ? "identity.spiffe.uri.malformed"
          : path.includes("expired") ? "capability.ttl.expired"
          : path.includes("scope") ? "capability.scope.escalation"
          : path.includes("replay") ? "receipt.nonce.replayed"
          : path.includes("confusion") ? "capability.audience.mismatch"
          : "mtls.cipher.downgrade",
        input_snippet: { "...": "redacted-lorem", forged_field: "<placeholder>" },
        verdict: "deny",
        receipt: "chio/receipts/trust/" + path.split("/").pop(),
      };
    if (path.startsWith("web3/"))
      return {
        ...base,
        network: "base-sepolia",
        tx_hash: "0x" + h(path).slice(0, 64),
        block_number: 7_000_000 + (h(path).charCodeAt(0) % 99999),
        status: "confirmed",
        explorer: "https://sepolia.basescan.example.invalid/tx/0x" + h(path).slice(0, 8) + "…",
        anchors: { bundle_sha: manifest.bundle_sha },
      };
    if (path.startsWith("approvals/"))
      return { ...base, approver: "did:web:atlas.example.invalid#signer-lorem", signed_at: "2026-04-23T14:05:10Z", budget_envelope_wei: "1500000000000000000", signature: "ed25519:" + h(path).slice(0, 40) + "…" };
    if (path.startsWith("payments/"))
      return { ...base, protocol: "x402", amount_wei: "1500000000000000000", payer: "atlas.treasury", payee: "proofworks.provider", proof: "0x" + h(path).slice(0, 96), settlement_ref: "settlement/cross-rail-lorem.json" };
    if (path.startsWith("settlement/") || path.startsWith("rails/"))
      return { ...base, rail: "base-sepolia + clearinghouse-lorem", selection_rationale: "lowest_latency_and_policy_compatible", alternatives: ["eth-mainnet", "ach-lorem"] };
    return { ...base, lorem: "placeholder payload for " + path, value: h(path).slice(0, 16) };
  };

  // Narrative beats — each points to artifacts.
  const beats = [
    { n: 1, title: "Budget delegated", caption: "treasury → procurement via signed capability envelope.", artifacts: ["chio/capabilities/treasury-budget-lorem.json", "chio/budgets/exposure.json"], edges: ["e1"] },
    { n: 2, title: "RFQ opens", caption: "market-broker publishes RFQ through chio api protect.", artifacts: ["market/rfq.json"], edges: ["e2", "e5"] },
    { n: 3, title: "Low-reputation bid rejected", caption: "Cheap bid denied on reputation.passport.compare.", artifacts: ["market/rejections/low-rep-lorem.json", "reputation/passport-compare-proofworks.json"], edges: [] },
    { n: 4, title: "Forged-passport bid denied", caption: "Malicious over-budget bid blocked at mediation boundary.", artifacts: ["adversarial/forged-passport.json", "guardrails/overspend.json"], edges: ["d1", "d2"], pause: true },
    { n: 5, title: "ProofWorks selected", caption: "Selection rationale recorded with bid references.", artifacts: ["market/selection.json"], edges: ["e5"] },
    { n: 6, title: "Two-hop narrowing to CipherWorks", caption: "ProofWorks subcontracts under scoped capability.", artifacts: ["subcontracting/capability.json", "chio/receipts/lineage/subcontract-two-hop-lorem.json"], edges: ["e6"] },
    { n: 7, title: "Runtime attestation wobble", caption: "Sidecar degrades amber, re-attests, returns green.", artifacts: ["identity/runtime-degradation/proofworks-wobble-lorem.json", "identity/runtime-degradation/proofworks-reattest-lorem.json"], edges: ["e5"] },
    { n: 8, title: "Signed human approval", caption: "Human-in-the-loop signs the budget envelope.", artifacts: ["approvals/signed-human-lorem.json"], edges: ["e7"] },
    { n: 9, title: "x402 payment proof", caption: "On-chain mediated proof anchors the payment.", artifacts: ["payments/x402-proof-lorem.json"], edges: ["e7"] },
    { n: 10, title: "Cross-rail settlement", caption: "Rails selected by policy compatibility.", artifacts: ["settlement/cross-rail-lorem.json", "rails/selection.json"], edges: ["e7"] },
    { n: 11, title: "Audit via read-only MCP", caption: "Auditor reads web3 evidence without write capability.", artifacts: ["chio/receipts/mcp/auditor-web3-evidence-lorem.json", "web3/validation-ladder.json"], edges: ["e8", "e9"] },
    { n: 12, title: "Bundle verified", caption: "Manifest hashes match; 6/6 denials fired; verdict PASS.", artifacts: ["review-result.json", "bundle-manifest.json"], edges: [] },
  ];

  return { orgs, edges, reviewResult, summary, manifest, beats, fileContent, manifestFiles };
})();
