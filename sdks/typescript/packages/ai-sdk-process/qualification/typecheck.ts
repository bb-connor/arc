import { generateText, streamText, type LanguageModel } from "ai";
import { ChioProcessTools, type ProcessToolDefinition } from "@chio-protocol/ai-sdk-process";
import { ProcessClient } from "@chio-protocol/process";

export async function existingApplication(model: LanguageModel, client: ProcessClient, definitions: ProcessToolDefinition[]) {
  const create = () => new ChioProcessTools({ client, tools: definitions,
    namespace: "application", threadId: "saved-thread", turnId: "saved-model-turn" });
  const generated = await create().run(bindings => generateText({ model, ...bindings, prompt: "Use the tools" }));
  const streamed = await create().run(async bindings => {
    const result = streamText({ model, ...bindings, prompt: "Use the tools" });
    for await (const _chunk of result.textStream) { /* application-owned stream consumer */ }
    return await result.text;
  });
  return { generated, streamed };
}
