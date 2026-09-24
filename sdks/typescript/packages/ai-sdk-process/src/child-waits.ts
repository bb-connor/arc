import type { Json, ProcessClient } from "@chio-protocol/process";
import { digest, encode } from "./model-codec.js";
import { json } from "./values.js";
import { ProcessSuspendedError, ProcessToolError } from "./types.js";

export const CHILD_WAITS_SLOT = "chio.ai-sdk.child-waits.v1";
type RecordEntry = { request: string; poll: number };
type Slot = { schema: typeof CHILD_WAITS_SLOT; waits: Record<string, RecordEntry> };
export type WaitClaim = { original: string; operationKey: string; request: string; poll: number };

/** Advance observations of one logical join only after retaining its pending receipt. */
export class ChildWaits {
  readonly #client: Pick<ProcessClient, "inspect" | "checkpoint">;
  #tail: Promise<unknown> = Promise.resolve();
  #process: string | undefined;

  constructor(client: Pick<ProcessClient, "inspect" | "checkpoint">) {
    this.#client = { inspect: client.inspect.bind(client), checkpoint: client.checkpoint.bind(client) };
  }

  async #locked<T>(operation: () => Promise<T>): Promise<T> {
    const next = this.#tail.then(operation);
    this.#tail = next.catch(() => {});
    return next;
  }

  async #read() {
    const snapshot = await this.#client.inspect();
    if (snapshot.state !== "running" || (this.#process !== undefined && snapshot.process_id !== this.#process)) throw new ProcessToolError("child_wait_conflict");
    this.#process = snapshot.process_id;
    const value = snapshot.checkpoint.value === null ? {} : JSON.parse(JSON.stringify(json(snapshot.checkpoint.value)));
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new ProcessToolError("child_wait_invalid");
    const slot: Slot = Object.hasOwn(value, CHILD_WAITS_SLOT) ? value[CHILD_WAITS_SLOT] : { schema: CHILD_WAITS_SLOT, waits: {} };
    if (!slot || slot.schema !== CHILD_WAITS_SLOT || !slot.waits || typeof slot.waits !== "object" || Array.isArray(slot.waits) || Object.keys(slot.waits).length > 1024) throw new ProcessToolError("child_wait_invalid");
    for (const [key, entry] of Object.entries(slot.waits)) {
      if (!/^ai-sdk:[a-f0-9]{64}$/.test(key) || !entry || typeof entry.request !== "string" || !/^[a-f0-9]{64}$/.test(entry.request) ||
          !Number.isInteger(entry.poll) || entry.poll < 0 || entry.poll > 128) throw new ProcessToolError("child_wait_invalid");
    }
    value[CHILD_WAITS_SLOT] = slot;
    return { value, slot, revision: snapshot.checkpoint.revision };
  }

  claim(original: string, args: Json): Promise<WaitClaim> {
    const request = digest(encode(args));
    return this.#locked(async () => {
      const current = await this.#read();
      let entry = current.slot.waits[original];
      if (!entry) {
        if (Object.keys(current.slot.waits).length >= 1024) throw new ProcessToolError("limit_reached");
        entry = { request, poll: 0 };
        current.slot.waits[original] = entry;
        await this.#client.checkpoint(current.revision, json(current.value));
      }
      if (entry.request !== request) throw new ProcessToolError("child_wait_conflict");
      const operationKey = entry.poll === 0 ? original : `ai-sdk:join:${digest([original, entry.poll])}`;
      return { original, operationKey, request, poll: entry.poll };
    });
  }

  async observe(claim: WaitClaim, args: Json, value: Json): Promise<void> {
    if (!value || typeof value !== "object" || Array.isArray(value) || typeof value.complete !== "boolean" ||
        !args || typeof args !== "object" || Array.isArray(args) || !Array.isArray(args.children) ||
        !Array.isArray(value.children) || digest(encode(value.children)) !== digest(encode(args.children))) throw new ProcessToolError("child_wait_invalid");
    if (value.complete) return;
    await this.#locked(async () => {
      const current = await this.#read(), entry = current.slot.waits[claim.original];
      if (!entry || entry.request !== claim.request || entry.poll !== claim.poll) throw new ProcessToolError("child_wait_conflict");
      if (entry.poll >= 128) throw new ProcessToolError("limit_reached");
      entry.poll++;
      await this.#client.checkpoint(current.revision, json(current.value));
    });
    throw new ProcessSuspendedError();
  }
}
