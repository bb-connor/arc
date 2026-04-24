// Explorer tree section definitions.
//
// Each section groups manifest entries under a human-readable label. The
// `paths` list applies to the top-level "review" section, which pins specific
// files; every other section matches on a top-level path prefix (e.g. "chio/"
// entries land under "chio").

export interface Section {
  id: string;
  label: string;
  paths?: string[];
}

export const SECTIONS: readonly Section[] = [
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
  { id: "web3", label: "Web3 - Base Sepolia" },
  { id: "operations", label: "Operations" },
  { id: "disputes", label: "Disputes" },
];
