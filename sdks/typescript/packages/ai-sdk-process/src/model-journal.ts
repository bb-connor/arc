import { randomUUID } from "node:crypto";
import { WorkerError, type Json, type ProcessClient } from "@chio-protocol/process";
import type { LanguageModelMiddleware } from "ai";
import { identity, json } from "./values.js";
import { digest, encode, restored, ModelJournalError } from "./model-codec.js";
import type { ProcessIdentity } from "./types.js";

export const MODEL_JOURNAL_SLOT = "chio.ai-sdk.journal.v1";
type GenerateOptions = Parameters<NonNullable<LanguageModelMiddleware["wrapGenerate"]>>[0];
type StreamOptions = Parameters<NonNullable<LanguageModelMiddleware["wrapStream"]>>[0];
type Generated = Awaited<ReturnType<GenerateOptions["doGenerate"]>>;
type Streamed = Awaited<ReturnType<StreamOptions["doStream"]>>;
type Part = Streamed["stream"] extends ReadableStream<infer T> ? T : never;
type Entry = { request: string; kind: "generate" | "stream"; owner: string;
  state: "pending" | "completed"; response?: Json; responseHash?: string; callIds?: string[] };
type Turn = { identity: Json; entries: Entry[] };
type Slot = { schema: "chio.ai-sdk.journal.v1"; turns: Record<string, Turn> };
type Current = { value: Record<string, Json>; slot: Slot; revision: string };

export interface ModelJournalOptions extends ProcessIdentity {
  client: Pick<ProcessClient, "inspect" | "checkpoint">;
  /** Version the model configuration, provider endpoint and application behavior. */
  modelKey: string;
  maxModelCalls?: number;
  maxCheckpointBytes?: number;
}

/** Internal run-scoped writer. The checkpoint slot persists independently of this instance. */
export class ModelJournal {
  readonly #options: ModelJournalOptions;
  readonly #identity: Json;
  readonly #turnKey: string;
  readonly #controller = new AbortController();
  readonly #pending = new Set<Promise<unknown>>();
  readonly #maxBytes: number;
  readonly #maxCalls: number;
  readonly #onFailure: () => void;
  #failure: ModelJournalError | undefined;
  #closed = false;
  #busy = false;
  #cursor = 0;
  #process: string | undefined;

  constructor(options: ModelJournalOptions, onFailure: () => void) {
    this.#options = { ...options, client: {
      inspect: options.client.inspect.bind(options.client), checkpoint: options.client.checkpoint.bind(options.client),
    } };
    this.#identity = [identity(options.namespace), identity(options.threadId), identity(options.turnId), identity(options.modelKey)];
    this.#turnKey = digest(this.#identity.slice(0, 3));
    this.#maxCalls = options.maxModelCalls ?? 64;
    this.#maxBytes = options.maxCheckpointBytes ?? 1_048_576;
    this.#onFailure = onFailure;
    if (!Number.isInteger(this.#maxCalls) || this.#maxCalls < 1 || this.#maxCalls > 128 ||
        !Number.isInteger(this.#maxBytes) || this.#maxBytes < 4096 || this.#maxBytes > 1_048_576) {
      throw new ModelJournalError("model_journal_full");
    }
  }

  middleware(): LanguageModelMiddleware {
    return {
      // AI SDK 6 requires v3; AI SDK 7 accepts v3 middleware over its V4 wrapper.
      specificationVersion: "v3",
      transformParams: async ({ params }) => {
        try {
          const { abortSignal, ...values } = params;
          const snapshot = restored<typeof values>(encode(values));
          return { ...snapshot,
            abortSignal: AbortSignal.any([this.#controller.signal, ...(abortSignal ? [abortSignal] : [])]),
          };
        } catch (error) { throw this.#fail(error); }
      },
      wrapGenerate: options => this.#tracked(this.#generate(options)),
      wrapStream: options => this.#tracked(this.#stream(options)),
    };
  }

  #fail(error: unknown): ModelJournalError {
    this.#failure ??= error instanceof ModelJournalError ? error :
      new ModelJournalError(error instanceof WorkerError && error.code === "checkpoint_conflict"
        ? "model_checkpoint_conflict" : "model_checkpoint_unavailable");
    this.#controller.abort();
    this.#onFailure();
    return this.#failure;
  }

  #tracked<T>(promise: Promise<T>): Promise<T> {
    const pending = promise.catch(error => { throw this.#fail(error); });
    this.#pending.add(pending);
    void pending.then(() => this.#pending.delete(pending), () => this.#pending.delete(pending));
    return pending;
  }

  async finish(completed: boolean): Promise<void> {
    this.#closed = true;
    if (this.#pending.size) this.#fail(new ModelJournalError("model_aborted"));
    await Promise.allSettled([...this.#pending]);
    if (this.#failure) throw this.#failure;
    if (completed) {
      try {
        const { slot } = await this.#read();
        if ((slot.turns[this.#turnKey]?.entries.length ?? 0) !== this.#cursor) throw new ModelJournalError("model_replay_incomplete");
      } catch (error) { throw this.#fail(error); }
    }
  }

  async #read(): Promise<Current> {
    const snapshot = await this.#options.client.inspect();
    if (snapshot.state !== "running" || (this.#process !== undefined && snapshot.process_id !== this.#process)) {
      throw new ModelJournalError("model_checkpoint_conflict");
    }
    this.#process = snapshot.process_id;
    const value: Record<string, Json> = snapshot.checkpoint.value === null ? {} : JSON.parse(JSON.stringify(json(snapshot.checkpoint.value)));
    if (typeof value !== "object" || Array.isArray(value)) throw new ModelJournalError("model_checkpoint_invalid");
    const slot: Slot = Object.hasOwn(value, MODEL_JOURNAL_SLOT) ? value[MODEL_JOURNAL_SLOT] as unknown as Slot : { schema: MODEL_JOURNAL_SLOT, turns: {} };
    if (!slot || slot.schema !== MODEL_JOURNAL_SLOT || !slot.turns || typeof slot.turns !== "object" || Array.isArray(slot.turns)) {
      throw new ModelJournalError("model_checkpoint_invalid");
    }
    const turn = slot.turns[this.#turnKey];
    if (Object.hasOwn(slot.turns, this.#turnKey) && (!turn || !Array.isArray(turn.entries))) {
      throw new ModelJournalError("model_checkpoint_invalid");
    }
    if (turn && digest(turn.identity) !== digest(this.#identity)) throw new ModelJournalError("model_request_conflict");
    for (const entry of turn?.entries ?? []) {
      if (!entry || typeof entry.owner !== "string" || !entry.owner ||
          typeof entry.request !== "string" || !/^[a-f0-9]{64}$/.test(entry.request) ||
          !["generate", "stream"].includes(entry.kind) || !["pending", "completed"].includes(entry.state)) {
        throw new ModelJournalError("model_checkpoint_invalid");
      }
      if (entry.state === "completed" && (entry.response === undefined || !Array.isArray(entry.callIds) ||
          entry.callIds.some(id => typeof id !== "string") || entry.responseHash !== digest([entry.response, entry.callIds]))) {
        throw new ModelJournalError("model_checkpoint_invalid");
      }
      if (entry.state === "pending" && (entry.response !== undefined || entry.responseHash !== undefined || entry.callIds !== undefined)) {
        throw new ModelJournalError("model_checkpoint_invalid");
      }
    }
    value[MODEL_JOURNAL_SLOT] = slot as unknown as Json;
    return { value, slot, revision: snapshot.checkpoint.revision };
  }

  async #write(current: Current) {
    if (Buffer.byteLength(JSON.stringify(current.value)) > this.#maxBytes) throw new ModelJournalError("model_journal_full");
    await this.#options.client.checkpoint(current.revision, json(current.value));
  }

  #claim() {
    if (this.#failure) throw this.#failure;
    if (this.#closed) throw this.#fail(new ModelJournalError("model_closed"));
    if (this.#busy) throw this.#fail(new ModelJournalError("model_concurrent"));
    this.#busy = true;
  }

  async #begin(kind: Entry["kind"], options: GenerateOptions | StreamOptions) {
    if (options.params.abortSignal?.aborted) throw new ModelJournalError("model_aborted");
    // AbortSignal is transient. Everything else, including headers and provider options, is bound.
    const { abortSignal: _signal, ...params } = options.params;
    if (params.tools?.some(tool => tool.type !== "function")) throw new ModelJournalError("model_value_unsupported");
    const request = digest(encode([kind, options.model.specificationVersion, options.model.provider, options.model.modelId, params]));
    const current = await this.#read();
    const index = this.#cursor++;
    let turn = current.slot.turns[this.#turnKey];
    if (!turn) {
      if (Object.keys(current.slot.turns).length >= 128) throw new ModelJournalError("model_journal_full");
      turn = { identity: this.#identity, entries: [] };
      current.slot.turns[this.#turnKey] = turn;
    }
    const existing = turn.entries[index];
    if (existing) {
      if (existing.request !== request || existing.kind !== kind) throw new ModelJournalError("model_request_conflict");
      if (existing.state === "pending") throw new ModelJournalError("model_outcome_unknown");
      if (existing.state !== "completed" || existing.response === undefined ||
          existing.responseHash !== digest([existing.response, existing.callIds!])) throw new ModelJournalError("model_checkpoint_invalid");
      return { index, entry: existing, replay: true };
    }
    if (index !== turn.entries.length) throw new ModelJournalError("model_checkpoint_invalid");
    if (index >= this.#maxCalls) throw new ModelJournalError("model_journal_full");
    const entry: Entry = { request, kind, owner: randomUUID(), state: "pending" };
    turn.entries.push(entry);
    await this.#write(current);
    if (this.#failure || options.params.abortSignal?.aborted) throw this.#failure ?? new ModelJournalError("model_aborted");
    return { index, entry, replay: false };
  }

  async #complete(index: number, entry: Entry, value: unknown) {
    const response = encode(value);
    const snapshot = restored<{ content?: unknown[]; chunks?: unknown[]; finishReason?: { unified?: string } }>(response);
    const parts = entry.kind === "generate" ? snapshot.content : snapshot.chunks;
    if (!Array.isArray(parts) || (entry.kind === "generate" &&
        !["stop", "tool-calls", "length", "content-filter"].includes(snapshot.finishReason?.unified ?? "")) ||
        parts.some(part => part !== null && typeof part === "object" && "providerExecuted" in part && part.providerExecuted)) {
      throw new ModelJournalError("model_response_invalid");
    }
    const current = await this.#read();
    const saved = current.slot.turns[this.#turnKey]?.entries[index];
    if (!saved || saved.state !== "pending" || saved.owner !== entry.owner || saved.request !== entry.request || saved.kind !== entry.kind) {
      throw new ModelJournalError("model_checkpoint_conflict");
    }
    const calls = new Set(current.slot.turns[this.#turnKey]!.entries.slice(0, index).flatMap(item => item.callIds ?? []));
    const callIds: string[] = [];
    for (const value of parts) {
      if (!value || typeof value !== "object" || !("type" in value) || value.type !== "tool-call") continue;
      const part = value as { toolCallId?: unknown; toolName?: unknown; input?: unknown };
      try { identity(part.toolCallId); identity(part.toolName); }
      catch { throw new ModelJournalError("model_response_invalid"); }
      const id = part.toolCallId as string;
      if (typeof part.input !== "string" || calls.has(id)) throw new ModelJournalError("model_response_invalid");
      calls.add(id); callIds.push(id);
    }
    Object.assign(saved, { state: "completed", response, responseHash: digest([response, callIds]), callIds });
    await this.#write(current);
    if (this.#failure) throw this.#failure;
    return snapshot;
  }

  async #generate(options: GenerateOptions): Promise<Generated> {
    this.#claim();
    try {
      const { index, entry, replay } = await this.#begin("generate", options);
      if (replay) return restored<Generated>(entry.response!);
      let result: Generated;
      try { result = await options.doGenerate(); }
      catch { throw new ModelJournalError("model_outcome_unknown"); }
      return await this.#complete(index, entry, result) as Generated;
    } finally { this.#busy = false; }
  }

  async #stream(options: StreamOptions): Promise<Streamed> {
    this.#claim();
    let handedOff = false;
    try {
      const { index, entry, replay } = await this.#begin("stream", options);
      if (replay) {
        const saved = restored<{ metadata: Omit<Streamed, "stream">; chunks: Part[] }>(entry.response!);
        return { ...saved.metadata, stream: new ReadableStream<Part>({ start(controller) {
          for (const chunk of saved.chunks) controller.enqueue(chunk);
          controller.close();
        } }) };
      }
      let supplied: Streamed;
      try { supplied = await options.doStream(); }
      catch { throw new ModelJournalError("model_outcome_unknown"); }
      const fields = Object.getOwnPropertyDescriptors(supplied);
      if (![Object.prototype, null].includes(Object.getPrototypeOf(supplied)) ||
          Object.getOwnPropertySymbols(supplied).length || Object.values(fields).some(field => field.get || field.set || !field.enumerable)) {
        throw new ModelJournalError("model_value_unsupported");
      }
      const stream = fields.stream?.value as Streamed["stream"];
      const metadata = Object.fromEntries(Object.entries(fields).filter(([name]) => name !== "stream").map(([name, field]) => [name, field.value]));
      const stableMetadata = restored<Omit<Streamed, "stream">>(encode(metadata));
      const reader = ReadableStream.prototype.getReader.call(stream) as ReadableStreamDefaultReader<Part>;
      const chunks: Part[] = [], held: Part[] = [];
      let bytes = Buffer.byteLength(JSON.stringify(encode(metadata))), hold = false, finishes = 0;
      const abort = () => { void reader.cancel().catch(() => {}); };
      options.params.abortSignal?.addEventListener("abort", abort, { once: true });
      if (options.params.abortSignal?.aborted) abort();
      const output = new ReadableStream<Part>({
        start: controller => {
          const capture = this.#tracked((async () => {
            try {
              while (true) {
                const next = await reader.read();
                if (options.params.abortSignal?.aborted) throw new ModelJournalError("model_aborted");
                if (next.done) break;
                const wire = encode(next.value);
                bytes += Buffer.byteLength(JSON.stringify(wire));
                if (bytes > this.#maxBytes) throw new ModelJournalError("model_journal_full");
                const part = restored<Part>(wire);
                if (part.type === "error" || ("providerExecuted" in part && part.providerExecuted) || part.type === "tool-result") {
                  throw new ModelJournalError("model_response_invalid");
                }
                if (part.type === "finish") {
                  if (++finishes !== 1 || !["stop", "tool-calls", "length", "content-filter"].includes(part.finishReason.unified)) throw new ModelJournalError("model_response_invalid");
                }
                chunks.push(part);
                hold ||= part.type.startsWith("tool-") || part.type === "finish";
                if (hold) held.push(part); else controller.enqueue(restored<Part>(wire));
              }
              if (finishes !== 1) throw new ModelJournalError("model_outcome_unknown");
              await this.#complete(index, entry, { metadata: stableMetadata, chunks });
            } catch (error) {
              throw error instanceof ModelJournalError ? error : new ModelJournalError("model_outcome_unknown");
            } finally {
              options.params.abortSignal?.removeEventListener("abort", abort);
              await reader.cancel().catch(() => {});
              reader.releaseLock();
              this.#busy = false;
            }
            for (const part of held) controller.enqueue(part);
            controller.close();
          })());
          void capture.catch(error => { try { controller.error(error); } catch { /* consumer already cancelled */ } });
        },
        cancel: async () => { this.#fail(new ModelJournalError("model_aborted")); await reader.cancel().catch(() => {}); },
      });
      handedOff = true;
      return { ...stableMetadata, stream: output };
    } finally { if (!handedOff) this.#busy = false; }
  }
}
