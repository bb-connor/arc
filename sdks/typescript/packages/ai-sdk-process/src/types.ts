import type { Json, ProcessClient, ToolResult } from "@chio-protocol/process";
import type { Tool } from "ai";

/** The operator's selected definitions, as delivered in a worker bootstrap. */
export interface ProcessToolDefinition {
  name: string;
  server_id: string;
  tool_name: string;
  description: string;
  input_schema: { [key: string]: Json };
}

export interface ProcessIdentity {
  namespace: string;
  threadId: string;
  /** Persist with the model plan. Never derive from an OS attempt or credential. */
  turnId: string;
}

export interface ProcessReceiptEvent {
  readonly operationKey: string;
  readonly toolCallId: string;
  readonly tool: Readonly<ProcessToolDefinition>;
  /** Original receipt text is unverified and must be preserved unchanged. */
  readonly result: Readonly<ToolResult>;
}

export interface ProcessToolsOptions extends ProcessIdentity {
  client: Pick<ProcessClient, "invoke">;
  tools: readonly ProcessToolDefinition[];
  maxConcurrency?: number;
  maxPending?: number;
  abortSignal?: AbortSignal;
  /** Awaited before revealing a tool result. Throwing stops the complete run. */
  onReceipt?: (event: ProcessReceiptEvent) => void | Promise<void>;
}

export interface ProcessToolBindings {
  tools: Record<string, Tool<Json, Json>>;
  abortSignal: AbortSignal;
}

export type ProcessToolErrorCode =
  | "invalid_json" | "invalid_identity" | "invalid_definition" | "queue_full"
  | "closed" | "aborted" | "transport_error" | "missing_receipt"
  | "kernel_denied" | "incomplete" | "invalid_output" | "tool_error"
  | "receipt_sink_failed" | "conflict" | "cancelled" | "limit_reached"
  | "unauthenticated" | "invalid_request" | "runtime_error";

/** Safe model-visible text. Detailed receipt data goes only to onReceipt. */
export class ProcessToolError extends Error {
  constructor(readonly code: ProcessToolErrorCode) {
    super(`Chio process tool failed: ${code}`);
    this.name = "ProcessToolError";
  }
}
