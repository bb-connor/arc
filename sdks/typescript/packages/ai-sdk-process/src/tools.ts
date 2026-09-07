import { jsonSchema, type Tool } from "ai";
import { WorkerError, type Json, type ToolResult } from "@chio-protocol/process";
import {
  ProcessToolError, ProcessSuspendedError, type ProcessToolBindings, type ProcessToolDefinition,
  type ProcessToolsOptions,
} from "./types.js";
import { ChildWaits } from "./child-waits.js";
import { identity, json, processOperationKey } from "./values.js";

/** One bounded AI SDK run. Planning and durable model identities remain with the caller. */
export class ChioProcessTools {
  readonly #options: ProcessToolsOptions;
  readonly #controller = new AbortController();
  readonly #tools: ProcessToolBindings["tools"] = Object.create(null);
  readonly #pending = new Set<Promise<Json>>();
  readonly #queue: Array<{ resolve: () => void; reject: (error: ProcessToolError) => void }> = [];
  readonly #concurrency: number;
  readonly #maxPending: number;
  readonly #waits: ChildWaits | undefined;
  #active = 0;
  #state: "new" | "running" | "draining" | "closed" = "new";
  #failure: ProcessToolError | undefined;

  constructor(options: ProcessToolsOptions) {
    if (typeof options.client?.invoke !== "function" ||
        (options.onReceipt !== undefined && typeof options.onReceipt !== "function")) {
      throw new ProcessToolError("invalid_definition");
    }
    this.#options = { ...options, namespace: identity(options.namespace),
      threadId: identity(options.threadId), turnId: identity(options.turnId),
      client: { invoke: options.client.invoke.bind(options.client) } };
    if (options.cooperativeChildren !== undefined && typeof options.cooperativeChildren !== "boolean") throw new ProcessToolError("invalid_definition");
    if (options.cooperativeChildren && (typeof options.client.inspect !== "function" || typeof options.client.checkpoint !== "function")) throw new ProcessToolError("invalid_definition");
    this.#waits = options.cooperativeChildren ? new ChildWaits({ inspect: options.client.inspect!.bind(options.client), checkpoint: options.client.checkpoint!.bind(options.client) }) : undefined;
    this.#concurrency = options.maxConcurrency ?? 4;
    this.#maxPending = options.maxPending ?? 64;
    if (!Number.isInteger(this.#concurrency) || this.#concurrency < 1 || this.#concurrency > 32 ||
        !Number.isInteger(this.#maxPending) || this.#maxPending < this.#concurrency || this.#maxPending > 128 ||
        !Array.isArray(options.tools) || options.tools.length < 1 || options.tools.length > 128) {
      throw new ProcessToolError("invalid_definition");
    }
    for (const supplied of options.tools) {
      const definition = json(supplied) as unknown as ProcessToolDefinition;
      for (const field of [definition.name, definition.server_id, definition.tool_name]) identity(field);
      if (typeof definition.description !== "string" || !definition.input_schema ||
          Array.isArray(definition.input_schema) || typeof definition.input_schema !== "object" ||
          Object.hasOwn(this.#tools, definition.name)) throw new ProcessToolError("invalid_definition");
      const schema = jsonSchema<Json>(definition.input_schema);
      const bound: Tool<Json, Json> = {
        description: definition.description,
        inputSchema: schema,
        execute: (input, context) => this.#execute(definition, input, context?.toolCallId ?? "", context?.abortSignal),
      };
      this.#tools[definition.name] = Object.freeze(bound);
    }
    Object.freeze(this.#tools);
  }

  /** Consume streaming results inside this callback. All admitted client calls are drained on exit. */
  async run<T>(operation: (bindings: ProcessToolBindings) => Promise<T>): Promise<T> {
    if (this.#state !== "new") throw new ProcessToolError("closed");
    this.#state = "running";
    const external = this.#options.abortSignal;
    const abort = () => this.#fail(new ProcessToolError("aborted"));
    external?.addEventListener("abort", abort, { once: true });
    let value: T | undefined;
    let applicationError: unknown;
    try {
      if (external?.aborted) abort();
      if (this.#failure) throw this.#failure;
      value = await operation({ tools: this.#tools, abortSignal: this.#controller.signal });
    } catch (error) {
      applicationError = error;
      if (!this.#failure) this.#fail(new ProcessToolError("aborted"));
    } finally {
      this.#state = "draining";
      await Promise.allSettled([...this.#pending]);
      this.#state = "closed";
      external?.removeEventListener("abort", abort);
    }
    if (applicationError !== undefined && this.#failure?.code === "aborted") throw applicationError;
    if (this.#failure) throw this.#failure;
    return value as T;
  }

  #fail(error: ProcessToolError): ProcessToolError {
    if (!this.#failure || (this.#failure instanceof ProcessSuspendedError && !(error instanceof ProcessSuspendedError) && error.code !== "aborted")) this.#failure = error;
    this.#controller.abort(this.#failure);
    for (const waiting of this.#queue.splice(0)) waiting.reject(this.#failure);
    return this.#failure;
  }

  #execute(definition: ProcessToolDefinition, input: Json, callId: string, signal?: AbortSignal): Promise<Json> {
    if (this.#state !== "running") return Promise.reject(new ProcessToolError("closed"));
    if (this.#failure) return Promise.reject(this.#failure);
    if (this.#pending.size >= this.#maxPending) {
      return Promise.reject(this.#fail(new ProcessToolError("queue_full")));
    }
    const pending = this.#invoke(definition, input, callId, signal).catch(error => {
      throw this.#fail(normalizeError(error));
    });
    this.#pending.add(pending);
    void pending.then(() => this.#pending.delete(pending), () => this.#pending.delete(pending));
    return pending;
  }

  async #invoke(definition: ProcessToolDefinition, input: Json, callId: string, signal?: AbortSignal): Promise<Json> {
    const abort = () => this.#fail(new ProcessToolError("aborted"));
    let acquired = false;
    try {
      const args = json(input);
      const key = processOperationKey(this.#options, callId);
      if (signal?.aborted) throw new ProcessToolError("aborted");
      signal?.addEventListener("abort", abort, { once: true });
      if (this.#active >= this.#concurrency) {
        await new Promise<void>((resolve, reject) => this.#queue.push({ resolve, reject }));
      } else this.#active++;
      acquired = true;
      if (this.#failure) throw this.#failure;
      const wait = this.#waits && definition.server_id === "chio-process" && definition.tool_name === "wait_children"
        ? await this.#waits.claim(key, args) : undefined;
      const operationKey = wait?.operationKey ?? key;
      if (this.#failure) throw this.#failure;
      const result = json(await this.#options.client.invoke(operationKey, definition.server_id, definition.tool_name, args)) as unknown as ToolResult;
      if (typeof result?.receipt_json !== "string" || !result.receipt_json) throw new ProcessToolError("missing_receipt");
      try {
        await this.#options.onReceipt?.(Object.freeze({ operationKey, toolCallId: callId, tool: definition, result }));
      } catch { throw new ProcessToolError("receipt_sink_failed"); }
      if (result.verdict !== "allow") throw new ProcessToolError("kernel_denied");
      if (result.terminal_state?.state !== "completed") throw new ProcessToolError("incomplete");
      const output = result.output;
      let value: Json;
      if (output?.kind === "value" && Object.hasOwn(output, "value")) value = output.value;
      else if (output?.kind === "stream" && Array.isArray(output.chunks)) value = Object.freeze({ chunks: output.chunks });
      else throw new ProcessToolError("invalid_output");
      if (value !== null && typeof value === "object" && !Array.isArray(value) && value.isError === true) {
        throw new ProcessToolError("tool_error");
      }
      if (wait) await this.#waits!.observe(wait, args, value);
      if (this.#failure) throw this.#failure;
      return value;
    } catch (error) {
      throw this.#fail(normalizeError(error));
    } finally {
      signal?.removeEventListener("abort", abort);
      if (acquired) {
        const waiting = this.#queue.shift();
        if (waiting) waiting.resolve();
        else this.#active--;
      }
    }
  }
}

function normalizeError(error: unknown): ProcessToolError {
  if (error instanceof ProcessToolError) return error;
  if (error instanceof WorkerError) {
    switch (error.code) {
      case "conflict": case "cancelled": case "limit_reached":
      case "unauthenticated": case "invalid_request": case "runtime_error": case "checkpoint_conflict":
        return new ProcessToolError(error.code);
    }
  }
  return new ProcessToolError("transport_error");
}
