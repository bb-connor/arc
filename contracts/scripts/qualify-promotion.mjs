import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const contractsDir = path.resolve(__dirname, "..");
const repoRoot = path.resolve(contractsDir, "..");

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function writeJson(filePath, value) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function repoRelative(filePath) {
  return path.relative(repoRoot, filePath).replaceAll(path.sep, "/");
}

function runNode(args, expectSuccess = true) {
  const result = spawnSync("node", args, {
    cwd: repoRoot,
    encoding: "utf8"
  });
  if (expectSuccess) {
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } else {
    assert.notEqual(result.status, 0, "expected command to fail");
  }
  return result;
}

function buildApproval({ manifestPath, manifest, manifestHash, status = "approved", environment = "local-devnet" }) {
  return {
    approval_id: `chio.web3-deployment-approval.${environment}.v1`,
    candidate_release_id: manifest.review_context.candidate_release_id,
    deployment_policy_id: manifest.review_context.deployment_policy_id,
    reviewed_manifest_path: repoRelative(manifestPath),
    reviewed_manifest_sha256: manifestHash,
    environment,
    status,
    approvals: [
      {
        role: "release-reviewer",
        actor: "local-qualification",
        approved_at: "2026-04-02T17:30:00Z"
      },
      {
        role: "operator",
        actor: "local-devnet-admin",
        approved_at: "2026-04-02T17:30:30Z"
      }
    ],
    create2: {
      factory_mode: "runner-managed-local",
      factory_address: null,
      salt_namespace: manifest.salt_namespace
    },
    failure_policy: {
      rollback_mode: "evm_snapshot_revert",
      stop_on_error: true,
      require_manual_retry_after_failure: true
    }
  };
}

function duplicateContractManifest(manifest) {
  const copy = structuredClone(manifest);
  copy.contracts.push(structuredClone(manifest.contracts[0]));
  copy.manifest_id = `${manifest.manifest_id}.duplicate-salt-test`;
  return copy;
}

async function main() {
  const outputDirIndex = process.argv.indexOf("--output-dir");
  const outputRoot =
    outputDirIndex >= 0 && process.argv[outputDirIndex + 1]
      ? path.resolve(repoRoot, process.argv[outputDirIndex + 1])
      : path.join(repoRoot, "target", "web3-promotion-qualification");

  ensureDir(outputRoot);

  const manifestPath = path.join(contractsDir, "deployments", "local-devnet.reviewed.json");
  const manifest = readJson(manifestPath);
  const manifestHash = sha256File(manifestPath);

  const successRuns = [];
  for (const label of ["run-a", "run-b"]) {
    const runDir = path.join(outputRoot, label);
    ensureDir(runDir);
    const approvalPath = path.join(runDir, "approval.json");
    writeJson(approvalPath, buildApproval({ manifestPath, manifest, manifestHash }));
    runNode(
      [
        path.join("contracts", "scripts", "promote-deployment.mjs"),
        "--manifest",
        repoRelative(manifestPath),
        "--approval",
        repoRelative(approvalPath),
        "--output-dir",
        repoRelative(runDir),
        "--local-devnet",
        "--rollback-on-failure"
      ],
      true
    );
    successRuns.push(readJson(path.join(runDir, "promotion-report.json")));
  }

  assert.deepEqual(
    successRuns[0].planned_contract_addresses,
    successRuns[1].planned_contract_addresses,
    "replayed promotion should produce identical planned contract addresses"
  );
  assert.deepEqual(
    successRuns[0].deployed_contract_addresses,
    successRuns[1].deployed_contract_addresses,
    "replayed promotion should deploy the same contract addresses on fresh local devnets"
  );

  const badApprovalDir = path.join(outputRoot, "negative-approval");
  ensureDir(badApprovalDir);
  const badApprovalPath = path.join(badApprovalDir, "approval.json");
  const badApproval = buildApproval({ manifestPath, manifest, manifestHash: "deadbeef" });
  writeJson(badApprovalPath, badApproval);
  runNode(
    [
      path.join("contracts", "scripts", "promote-deployment.mjs"),
      "--manifest",
      repoRelative(manifestPath),
      "--approval",
      repoRelative(badApprovalPath),
      "--output-dir",
      repoRelative(badApprovalDir),
      "--local-devnet",
      "--rollback-on-failure"
    ],
    false
  );
  const badApprovalReport = readJson(path.join(badApprovalDir, "promotion-report.json"));
  assert.equal(badApprovalReport.status, "failed");

  const rollbackFailureDir = path.join(outputRoot, "negative-rollback");
  ensureDir(rollbackFailureDir);
  const badManifestPath = path.join(rollbackFailureDir, "duplicate-salt.reviewed.json");
  const duplicateManifest = duplicateContractManifest(manifest);
  writeJson(badManifestPath, duplicateManifest);
  const duplicateManifestHash = sha256File(badManifestPath);
  const duplicateApprovalPath = path.join(rollbackFailureDir, "approval.json");
  writeJson(
    duplicateApprovalPath,
    buildApproval({
      manifestPath: badManifestPath,
      manifest: duplicateManifest,
      manifestHash: duplicateManifestHash
    })
  );
  runNode(
    [
      path.join("contracts", "scripts", "promote-deployment.mjs"),
      "--manifest",
      repoRelative(badManifestPath),
      "--approval",
      repoRelative(duplicateApprovalPath),
      "--output-dir",
      repoRelative(rollbackFailureDir),
      "--local-devnet",
      "--rollback-on-failure"
    ],
    false
  );
  const rollbackPlan = readJson(path.join(rollbackFailureDir, "rollback-plan.json"));
  assert.equal(rollbackPlan.rollback_executed, true, "rollback should execute on failed local promotion");

  const summary = {
    report_id: "chio.web3-deployment-promotion-qualification.local-devnet.v1",
    generated_at: new Date().toISOString(),
    manifest: repoRelative(manifestPath),
    checks: [
      {
        id: "promotion.reproducible_rollout",
        outcome: "pass",
        note: "Two fresh local-devnet promotion runs produced identical CREATE2-planned and deployed contract addresses."
      },
      {
        id: "promotion.approval_gate",
        outcome: "pass",
        note: "Tampered approval manifest hashes fail closed before deployment."
      },
      {
        id: "promotion.rollback_on_failure",
        outcome: "pass",
        note: "Duplicate-salt deployment failure triggered explicit local snapshot rollback."
      }
    ],
    evidence: {
      success_runs: successRuns.map((_, index) => repoRelative(path.join(outputRoot, index === 0 ? "run-a" : "run-b", "promotion-report.json"))),
      negative_approval_report: repoRelative(path.join(badApprovalDir, "promotion-report.json")),
      negative_rollback_report: repoRelative(path.join(rollbackFailureDir, "promotion-report.json")),
      negative_rollback_plan: repoRelative(path.join(rollbackFailureDir, "rollback-plan.json"))
    }
  };

  writeJson(path.join(outputRoot, "promotion-qualification.json"), summary);
}

await main();
