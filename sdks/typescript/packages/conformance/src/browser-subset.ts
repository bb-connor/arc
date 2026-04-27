/**
 * Browser/Edge conformance subset selector (BROWSER_SUBSET_V1).
 *
 * M08 ships @chio-protocol/{browser,workers,edge,deno}. Those runtimes
 * are verify-only and execute a NAMED, VERSIONED subset of the M01
 * conformance corpus, not the full corpus. This module defines that
 * subset.
 *
 * Source of truth: `.planning/trajectory/08-browser-edge-sdk.md`,
 * section "Conformance subset definition".
 *
 * The subset (v1) is intentionally narrow:
 *
 *   - canonical/v1.json:  ALL cases (canonical-JSON byte equivalence is
 *                         a verify primitive on every runtime).
 *   - receipt/v1.json:    cases tagged `verify_only: true`.
 *   - capability/v1.json: cases tagged `verify_only: true`.
 *
 * Explicitly excluded:
 *   - Receipt and capability SIGNING cases (signing waits on the M08
 *     Phase 3 trust-boundary review; verify-only ships first).
 *   - manifest, hashing, signing corpora (server-side concerns).
 *   - Any vector requiring fresh entropy or live time.
 *
 * The subset constant `BROWSER_SUBSET_V1` is referenced from M01's
 * conformance manifest. M01 owns the corpus; M08 owns this selector.
 * Bumping to v2 requires a coordinated change in both milestones.
 */

/**
 * Stable tag identifying this subset version. M01's conformance manifest
 * pins this string to gate cross-milestone compatibility.
 */
export const BROWSER_SUBSET_TAG = "chio.conformance.browser-subset/v1" as const;

/**
 * Selection rule for a category in the M01 conformance corpus.
 *
 * - `mode: "all"` selects every case in that category.
 * - `mode: "verify_only"` selects cases whose `verify_only` flag is `true`.
 */
export type CategorySelection =
  | { readonly mode: "all" }
  | { readonly mode: "verify_only" };

/**
 * The subset enumeration: which M01 corpus categories belong to the
 * browser/edge runtime gate, and how each is filtered.
 *
 * Iteration order matches the phase-doc declaration order
 * (canonical, receipt, capability); downstream consumers MUST NOT rely
 * on Object.keys ordering for correctness, but stable order is
 * convenient for snapshot tests.
 */
export const BROWSER_SUBSET_V1 = {
  tag: BROWSER_SUBSET_TAG,
  version: 1,
  categories: {
    canonical: { mode: "all" },
    receipt: { mode: "verify_only" },
    capability: { mode: "verify_only" },
  },
} as const satisfies {
  readonly tag: typeof BROWSER_SUBSET_TAG;
  readonly version: 1;
  readonly categories: {
    readonly canonical: CategorySelection;
    readonly receipt: CategorySelection;
    readonly capability: CategorySelection;
  };
};

/**
 * Category names included in BROWSER_SUBSET_V1. Used as a closed enum
 * in the selector input shape below.
 */
export type BrowserSubsetCategory = keyof typeof BROWSER_SUBSET_V1.categories;

/**
 * Minimal shape of a single conformance case as it appears in
 * `tests/bindings/vectors/<category>/v1.json`. The selector only reads
 * `id` and `verify_only`; cases carry additional fields per category
 * which the selector preserves verbatim via the generic.
 */
export interface ConformanceCase {
  readonly id: string;
  readonly verify_only?: boolean;
}

/**
 * Minimal shape of a single category file
 * (`tests/bindings/vectors/<category>/v1.json`). The selector only
 * reads `cases`; the rest of the file (signing seeds, version, etc.)
 * is preserved on the input for callers that pass the full parsed
 * file in.
 */
export interface ConformanceCategoryFile<C extends ConformanceCase = ConformanceCase> {
  readonly cases: ReadonlyArray<C>;
}

/**
 * Shape the selector accepts: a record keyed by category name with the
 * parsed JSON for that category. Callers build this by reading the
 * three category files from disk (or from a bundled fixture in tests).
 */
export type ConformanceManifest = {
  readonly [K in BrowserSubsetCategory]: ConformanceCategoryFile;
};

/**
 * Result of running the selector: a versioned, tagged record listing
 * which case IDs are in scope per category. Consumers iterate this to
 * drive the per-runtime test runner.
 */
export interface BrowserSubsetSelection {
  readonly tag: typeof BROWSER_SUBSET_TAG;
  readonly version: 1;
  readonly categories: {
    readonly [K in BrowserSubsetCategory]: ReadonlyArray<string>;
  };
}

/**
 * Apply BROWSER_SUBSET_V1 to a parsed M01 conformance manifest and
 * return the per-category list of case IDs that runtimes must pass.
 *
 * The function is pure: it does no I/O and does not mutate the input.
 * It is total: any category whose file lists zero matching cases
 * yields an empty array (callers may treat that as a manifest drift
 * signal).
 */
export function selector(manifest: ConformanceManifest): BrowserSubsetSelection {
  const categories: { [K in BrowserSubsetCategory]: ReadonlyArray<string> } = {
    canonical: pickIds(manifest.canonical, BROWSER_SUBSET_V1.categories.canonical),
    receipt: pickIds(manifest.receipt, BROWSER_SUBSET_V1.categories.receipt),
    capability: pickIds(manifest.capability, BROWSER_SUBSET_V1.categories.capability),
  };

  return {
    tag: BROWSER_SUBSET_TAG,
    version: 1,
    categories,
  };
}

function pickIds(
  file: ConformanceCategoryFile,
  rule: CategorySelection,
): ReadonlyArray<string> {
  if (rule.mode === "all") {
    return file.cases.map((c) => c.id);
  }
  return file.cases.filter((c) => c.verify_only === true).map((c) => c.id);
}
