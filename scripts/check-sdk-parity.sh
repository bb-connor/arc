#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v node >/dev/null 2>&1; then
  echo "sdk parity requires node on PATH" >&2
  exit 1
fi

node --input-type=module <<'EOF'
import { readFileSync } from "node:fs";

const matrix = JSON.parse(
  readFileSync("tests/bindings/matrix/sdk-feature-matrix.json", "utf8"),
);

if (matrix.schema_version !== 1) {
  throw new Error(`unsupported sdk feature matrix schema: ${matrix.schema_version}`);
}

const allowedStatuses = new Set(matrix.status_values);
const languageIds = Object.keys(matrix.languages);
if (languageIds.length === 0) {
  throw new Error("sdk feature matrix must define at least one language");
}
if (!Array.isArray(matrix.features) || matrix.features.length === 0) {
  throw new Error("sdk feature matrix must define at least one feature");
}

const counts = new Map(languageIds.map((languageId) => [languageId, new Map()]));

for (const feature of matrix.features) {
  if (typeof feature.id !== "string" || feature.id.length === 0) {
    throw new Error("sdk feature matrix feature ids must be non-empty strings");
  }
  if (!feature.languages || typeof feature.languages !== "object") {
    throw new Error(`feature ${feature.id} is missing language entries`);
  }

  for (const languageId of languageIds) {
    const entry = feature.languages[languageId];
    if (!entry || typeof entry !== "object") {
      throw new Error(`feature ${feature.id} is missing language ${languageId}`);
    }
    if (!allowedStatuses.has(entry.status)) {
      throw new Error(
        `feature ${feature.id} language ${languageId} has unsupported status ${entry.status}`,
      );
    }
    if (!Array.isArray(entry.evidence)) {
      throw new Error(`feature ${feature.id} language ${languageId} must define evidence`);
    }
    if (entry.status !== "planned" && entry.evidence.length === 0) {
      throw new Error(
        `feature ${feature.id} language ${languageId} must provide evidence for status ${entry.status}`,
      );
    }

    const perLanguageCounts = counts.get(languageId);
    perLanguageCounts.set(
      entry.status,
      (perLanguageCounts.get(entry.status) ?? 0) + 1,
    );
  }
}

console.log("sdk feature matrix validated");
for (const languageId of languageIds) {
  const language = matrix.languages[languageId];
  const perLanguageCounts = counts.get(languageId);
  const parts = matrix.status_values
    .filter((status) => perLanguageCounts.has(status))
    .map((status) => `${status}=${perLanguageCounts.get(status)}`);
  console.log(`${language.label}: ${parts.join(", ")}`);
}
EOF

./scripts/check-bindings-parity.sh
./scripts/check-arc-py.sh
./scripts/check-arc-go.sh

echo "Python live parity is package-backed for the current conformance surface:"
echo "  invariants, initialize/session, tools/resources/prompts, notifications, tasks, auth, nested callbacks"
echo "Go live parity is conformance-green for the current conformance surface:"
echo "  invariants, initialize/session, tools/resources/prompts, notifications, tasks, auth, nested callbacks"
echo "Current live evidence runs through these lanes:"
echo "  cargo test -p arc-conformance --test wave1_go_live -- --nocapture"
echo "  cargo test -p arc-conformance --test wave2_go_live -- --nocapture"
echo "  cargo test -p arc-conformance --test wave3_go_live -- --nocapture"
echo "  cargo test -p arc-conformance --test wave4_go_live -- --nocapture"
echo "  cargo test -p arc-conformance --test wave5_go_live -- --nocapture"
echo "  cargo test -p arc-conformance --test wave1_live -- --nocapture"
echo "  cargo test -p arc-conformance --test wave2_tasks_live -- --nocapture"
echo "  cargo test -p arc-conformance --test wave3_auth_live -- --nocapture"
echo "  cargo test -p arc-conformance --test wave4_notifications_live -- --nocapture"
echo "  cargo test -p arc-conformance --test wave5_nested_flows_live -- --nocapture"
