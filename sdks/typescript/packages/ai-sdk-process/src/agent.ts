import { wrapLanguageModel } from "ai";
import type { ProcessClient } from "@chio-protocol/process";
import { ChioProcessTools } from "./tools.js";
import { ModelJournal, type ModelJournalOptions } from "./model-journal.js";
import { ProcessSuspendedError } from "./types.js";
import { ModelJournalError } from "./model-codec.js";
import type { ProcessToolBindings, ProcessToolsOptions } from "./types.js";

export interface ProcessAgentOptions extends Omit<ProcessToolsOptions, "client">, Omit<ModelJournalOptions, "client"> {
  client: Pick<ProcessClient, "invoke"> & ModelJournalOptions["client"];
  model: Parameters<typeof wrapLanguageModel>[0]["model"];
}

export interface ProcessAgentBindings extends ProcessToolBindings {
  model: ReturnType<typeof wrapLanguageModel>;
}

/** A model-response journal and native tool execution share one saved application turn. */
export class ChioProcessAgent {
  readonly #options: ProcessAgentOptions;
  #used = false;

  constructor(options: ProcessAgentOptions) { this.#options = { ...options }; }

  async run<T>(operation: (bindings: ProcessAgentBindings) => Promise<T>): Promise<T> {
    if (this.#used) throw new Error("Chio process agent is closed");
    this.#used = true;
    const controller = new AbortController();
    const journal = new ModelJournal(this.#options, () => controller.abort());
    const model = wrapLanguageModel({ model: this.#options.model, middleware: journal.middleware() });
    const tools = new ChioProcessTools({ ...this.#options,
      abortSignal: AbortSignal.any([controller.signal, ...(this.#options.abortSignal ? [this.#options.abortSignal] : [])]),
    });
    let completed = false;
    let failure: unknown;
    try {
      const value = await tools.run(bindings => operation({ ...bindings, model }));
      completed = true;
      return value;
    } catch (error) {
      failure = error;
      throw error;
    } finally {
      try { await journal.finish(completed); }
      catch (error) {
        // An SDK may attempt another step after swallowing the cooperative tool error.
        // Its aborted model call must not replace the durable suspension signal.
        if (!(failure instanceof ProcessSuspendedError && error instanceof ModelJournalError && error.code === "model_aborted")) throw error;
      }
    }
  }
}
