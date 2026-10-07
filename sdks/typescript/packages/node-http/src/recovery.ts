/** Transport only. The Rust host owns identity, approval and native recovery. */
import { canonicalJsonString } from "./canonical.js";
import type { Recovery_Command, Recovery_CommandResult, Recovery_CommandResponse, Recovery_ReviewDocument, Recovery_SignedExplanationView, Recovery_DecisionReport, Recovery_DecisionReportView, Recovery_PolicyMaintenanceProposal, Recovery_PolicyMaintenanceView, Recovery_SignedRecoverySetupProbe, Recovery_SignedRecoverySetupReport } from "./_generated/index.js";
import { recoveryWireSchemas } from "./_generated/recovery-schemas.js";
import { createWireSchemaValidator } from "./wire-schema.js";
import { nativeError, RecoveryError } from "./recovery-errors.js";
import { parseLosslessJsonWithProjection, type LosslessJsonValue } from "./lossless-json.js";
import { assertFoundationRecoveryResponseResources, assertFoundationRecoveryWire, readFoundationRecoveryWire } from "./recovery-wire-profile.js";

export { RecoveryError, type RecoveryErrorCode } from "./recovery-errors.js";
export { LosslessJsonNumber, type LosslessJsonValue } from "./lossless-json.js";

export type RecoveryCommandResult = Omit<Recovery_CommandResult.RecoveryCommandResultV1, "original_response"> & {
  original_response?: Omit<NonNullable<Recovery_CommandResult.RecoveryCommandResultV1["original_response"]>, "result"> & {
    result: LosslessJsonValue;
    /** SDK-only exact JSON for forwarding the opaque result without numeric loss. */
    result_json: string;
  };
};

export interface RecoveryClientOptions {
  /** Override every route's deadline, from one through 120 seconds. */
  timeoutSeconds?: number;
}

const schemaBase = "https://chio.world/schemas/chio-wire/v1/recovery/";
let validateWire: ReturnType<typeof createWireSchemaValidator> | undefined;
function validates(schema: string, value: unknown): boolean {
  validateWire ??= createWireSchemaValidator(recoveryWireSchemas);
  const base = ["signed-explanation-view", "decision-report", "decision-report-view", "policy-maintenance-proposal", "policy-maintenance-view", "signed-recovery-setup-probe", "signed-recovery-setup-report"].includes(schema) ? "https://chio.computer/schemas/chio-wire/v1/recovery/" : schemaBase;
  return validateWire(base + schema + ".schema.json", value);
}

export class RecoveryClient {
  private readonly endpoint: URL;
  private readonly timeoutSeconds: number | undefined;
  constructor(endpoint: string, private readonly transport: typeof fetch = fetch,
              options: RecoveryClientOptions = {}) {
    if (options.timeoutSeconds !== undefined &&
        (!Number.isInteger(options.timeoutSeconds) || options.timeoutSeconds < 1 || options.timeoutSeconds > 120)) {
      throw new Error("recovery.invalid_budget");
    }
    this.timeoutSeconds = options.timeoutSeconds;
    try { this.endpoint = new URL(endpoint); }
    catch { throw new Error("recovery.invalid_endpoint"); }
    const local = ["localhost", "127.0.0.1", "[::1]"].includes(this.endpoint.hostname);
    if (!(this.endpoint.protocol === "https:" || (this.endpoint.protocol === "http:" && local)) ||
        this.endpoint.username || this.endpoint.password || this.endpoint.search || this.endpoint.hash) {
      throw new Error("recovery.invalid_endpoint");
    }
    if (!this.endpoint.pathname.endsWith("/")) this.endpoint.pathname += "/";
  }
  execute(capability: string, command: Recovery_Command.RecoveryCommandV1): Promise<RecoveryCommandResult> {
    if (!validates("command", command)) throw new Error("recovery.invalid_command");
    const wire = canonicalJsonString(command);
    try { assertFoundationRecoveryWire(wire); }
    catch { throw new RecoveryError("recovery.invalid_command"); }
    return this.post("commands", "command-result", { capability, command: wire });
  }
  review(capability: string, workflowId: string): Promise<Recovery_ReviewDocument.RecoveryReviewDocumentV1> {
    return this.post("review", "review-document", { capability, workflow_id: workflowId });
  }
  /** Signed advisory projection. Resume always rechecks current native authority. */
  explain(capability: string, workflowId: string): Promise<Recovery_SignedExplanationView.RecoverySignedExplanationViewV1> {
    return this.post("explain", "signed-explanation-view", { capability, workflow_id: workflowId });
  }
  settle(capability: string, workflowId: string): Promise<Recovery_CommandResponse.RecoveryCommandResponseV1> {
    return this.post("settle", "command-response", { capability, workflow_id: workflowId });
  }
  /** Classified evidence only. Current Rust authority is checked on every read. */
  submitReport(capability: string, commandId: string, report: Recovery_DecisionReport.DecisionReportV1): Promise<Recovery_DecisionReportView.DecisionReportViewV1> {
    if (!validates("decision-report", report)) throw new Error("recovery.invalid_command");
    return this.post("reports/submit", "decision-report-view", { capability, command_id: commandId, report: canonicalJsonString(report) });
  }
  readReport(capability: string, reportId: string): Promise<Recovery_DecisionReportView.DecisionReportViewV1> {
    return this.post("reports/read", "decision-report-view", { capability, report_id: reportId });
  }
  /** A proposal cannot apply a deployment change or grant an effect. */
  proposePolicy(capability: string, proposal: Recovery_PolicyMaintenanceProposal.PolicyMaintenanceProposalV1): Promise<Recovery_PolicyMaintenanceView.PolicyMaintenanceViewV1> {
    if (!validates("policy-maintenance-proposal", proposal)) throw new Error("recovery.invalid_command");
    return this.post("policy/propose", "policy-maintenance-view", { capability, proposal: canonicalJsonString(proposal) });
  }
  /** Native self-test evidence. The operator must restart the owning writer. */
  setupProbe(capability: string, workflowId: string): Promise<Recovery_SignedRecoverySetupProbe.SignedRecoverySetupProbeV1> {
    return this.post("setup/probe", "signed-recovery-setup-probe", { capability, workflow_id: workflowId });
  }
  /** Carry exact native bytes; this client cannot decide or persist readiness. */
  setupQualify(capability: string, canonicalProbe: string): Promise<Recovery_SignedRecoverySetupReport.SignedRecoverySetupReportV1> {
    if (new TextEncoder().encode(canonicalProbe).length > 32768) throw new Error("recovery.resource_exhausted");
    try {
      if (!validates("signed-recovery-setup-probe", readFoundationRecoveryWire(canonicalProbe))) throw new Error("invalid proof");
    } catch { throw new Error("recovery.invalid_command"); }
    return this.post("setup/qualify", "signed-recovery-setup-report", { capability, probe: canonicalProbe });
  }
  private async post<T>(path: string, schema: string, envelope: object): Promise<T> {
    const bytes = new TextEncoder().encode(canonicalJsonString(envelope));
    if (bytes.length > 65536) throw new Error("recovery.resource_exhausted");
    const url = new URL(`v1/recovery/${path}`, this.endpoint);
    const signal = AbortSignal.timeout((this.timeoutSeconds ?? (path.startsWith("setup/") ? 120 : 20)) * 1000);
    // There is exactly one request. A timeout must retain the same command ID.
    let response: Response;
    try {
      response = await withinDeadline(this.transport(url, { method: "POST", redirect: "error",
        headers: { "content-type": "application/json" }, body: bytes,
        signal }), signal);
    } catch { throw new RecoveryError("recovery.unavailable"); }
    if (!response.body) throw new RecoveryError("recovery.invalid_response");
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    let exhausted = false;
    try {
      while (true) {
        const { done, value } = await withinDeadline(reader.read(), signal);
        if (done) break;
        size += value.length;
        if (size > 262144) { exhausted = true; await withinDeadline(reader.cancel(), signal); throw new Error("response too large"); }
        chunks.push(value);
      }
    } catch {
      if (exhausted) throw new Error("recovery.resource_exhausted");
      throw new RecoveryError("recovery.unavailable");
    }
    finally {
      if (signal.aborted) void reader.cancel().catch(() => {});
      reader.releaseLock();
    }
    const output = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.length; }
    if (!response.ok) throw nativeError(response.status, output);
    try {
      const decoded = parseLosslessJsonWithProjection(new TextDecoder("utf-8", { fatal: true }).decode(output),
        schema === "command-result" ? ["original_response", "result"] : undefined);
      if (schema !== "decision-report-view" && schema !== "policy-maintenance-view") {
        assertFoundationRecoveryResponseResources(decoded.resourceProjection);
      }
      const value = decoded.value;
      let projected: unknown = value;
      // The result is already a lossless, duplicate-free JSON tree. Validate
      // its surrounding signed metadata independently of this opaque value.
      if (schema === "command-result" && isObject(value) && isObject(value.original_response)
          && Object.hasOwn(value.original_response, "result")) {
        projected = { ...value, original_response: { ...value.original_response, result: null } };
      }
      if (!validates(schema, projected)) throw new Error("invalid shape");
      if (schema === "command-result" && isObject(value) && isObject(value.original_response)) {
        if (decoded.capturedSource === undefined) throw new Error("missing original result source");
        value.original_response.result_json = decoded.capturedSource;
      }
      return value as T;
    } catch { throw new RecoveryError("recovery.invalid_response"); }
  }
}

function isObject(value: LosslessJsonValue | undefined): value is { [key: string]: LosslessJsonValue } {
  return value !== null && value !== undefined && typeof value === "object" &&
    !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

/** An injected transport cannot silently remove the caller's total wait bound. */
function withinDeadline<T>(pending: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const abort = () => reject(new RecoveryError("recovery.unavailable"));
    signal.addEventListener("abort", abort, { once: true });
    // Install both handlers before testing abort, including for a promise that
    // later rejects after the caller has already timed out.
    void pending.then(
      (value) => { signal.removeEventListener("abort", abort); resolve(value); },
      (error: unknown) => { signal.removeEventListener("abort", abort); reject(error); },
    );
    if (signal.aborted) {
      signal.removeEventListener("abort", abort);
      abort();
    }
  });
}
