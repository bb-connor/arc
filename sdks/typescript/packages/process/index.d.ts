export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export const PROTOCOL: "chio.process.v1";
export const MAX_REQUEST_BYTES: number;
export const MAX_RESPONSE_BYTES: number;
export class WorkerError extends Error { readonly code: string; constructor(code: string); }
export interface Checkpoint { revision: string; value: Json; }
export interface ProcessSnapshot {
  process_id: string; parent_id: string | null; root_id: string;
  state: "running" | "cancelled"; depth: number; tree_calls: number;
  limits: { max_processes: number; max_depth: number; max_calls: number };
  checkpoint: Checkpoint;
}
export interface ToolResult {
  request_id: string;
  verdict: "allow" | "deny" | "pending_approval";
  output: { kind: "value"; value: Json } | { kind: "stream"; chunks: Json[] } | null;
  reason: string | null;
  terminal_state: { state: "completed" } | { state: "cancelled" | "incomplete"; reason: string };
  /** Original canonical signed JSON. Preserve unchanged for a Chio verifier. */
  receipt_json: string;
  execution_nonce_json: string | null;
}
export class ProcessClient {
  constructor(socketPath: string, credential: string, options?: { timeoutMs?: number });
  inspect(): Promise<ProcessSnapshot>;
  invoke(operationKey: string, serverId: string, toolName: string, args: Json): Promise<ToolResult>;
  checkpoint(expectedRevision: string, value: Json): Promise<Checkpoint>;
  cancel(): Promise<{ cancelled_processes: number }>;
}
