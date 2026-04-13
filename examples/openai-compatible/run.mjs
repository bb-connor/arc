import OpenAI from "openai";
import { ArcClient, ReceiptQueryClient } from "@arc-protocol/sdk";

const DEFAULT_ARC_BASE_URL = "http://127.0.0.1:8931";
const DEFAULT_ARC_CONTROL_URL = "http://127.0.0.1:8940";
const DEFAULT_ARC_AUTH_TOKEN = "demo-token";
const dryRun = process.argv.includes("--dry-run");
const livePrompt =
  process.argv.filter((arg) => !arg.startsWith("--")).slice(2).join(" ") ||
  "Use the echo_text function to send back a short hello from GPT.";
const model = process.env.OPENAI_MODEL ?? "gpt-5-mini";

function arcConfig() {
  return {
    baseUrl: process.env.ARC_BASE_URL ?? DEFAULT_ARC_BASE_URL,
    controlUrl: process.env.ARC_CONTROL_URL ?? DEFAULT_ARC_CONTROL_URL,
    authToken: process.env.ARC_AUTH_TOKEN ?? DEFAULT_ARC_AUTH_TOKEN,
  };
}

async function sessionCapabilityId(baseUrl, authToken, sessionId) {
  const response = await fetch(`${baseUrl}/admin/sessions/${sessionId}/trust`, {
    headers: { Authorization: `Bearer ${authToken}` },
  });
  if (!response.ok) {
    throw new Error(`session trust query failed with HTTP ${response.status}`);
  }
  const payload = await response.json();
  const capabilityId = payload.capabilities?.[0]?.capabilityId;
  if (!capabilityId) {
    throw new Error("session trust endpoint did not return an active capability id");
  }
  return capabilityId;
}

async function latestReceipt(controlUrl, authToken, capabilityId) {
  const receipts = await new ReceiptQueryClient(controlUrl, authToken).query({
    capabilityId,
    limit: 10,
  });
  const receipt = receipts.receipts?.at(-1);
  if (!receipt) {
    throw new Error("receipt query did not return the governed tool receipt");
  }
  return receipt;
}

function openAiToolsFromArc(tools) {
  return tools.map((tool) => ({
    type: "function",
    function: {
      name: tool.name,
      description: tool.description ?? "",
      parameters: tool.inputSchema ?? { type: "object", properties: {} },
    },
  }));
}

function renderToolResult(result) {
  if (result.structuredContent) {
    return JSON.stringify(result.structuredContent);
  }
  if (Array.isArray(result.content)) {
    return result.content
      .filter((item) => item.type === "text")
      .map((item) => item.text)
      .join("\n");
  }
  return JSON.stringify(result);
}

async function main() {
  const { baseUrl, controlUrl, authToken } = arcConfig();
  const client = ArcClient.withStaticBearer(baseUrl, authToken);
  const session = await client.initialize({
    clientInfo: { name: "arc-openai-compatible-example", version: "0.1.0" },
  });

  try {
    const toolsResult = await session.listTools();
    const tools = toolsResult.tools ?? [];
    const capabilityId = await sessionCapabilityId(baseUrl, authToken, session.sessionId);

    if (dryRun) {
      const result = await session.callTool("echo_text", {
        message: "hello from the OpenAI-compatible dry-run",
      });
      const receipt = await latestReceipt(controlUrl, authToken, capabilityId);
      console.log(
        JSON.stringify(
          {
            mode: "dry-run",
            sessionId: session.sessionId,
            capabilityId,
            toolNames: tools.map((tool) => tool.name),
            echo:
              result.structuredContent?.echo ??
              result.content?.find((item) => item.type === "text")?.text ??
              null,
            receiptId: receipt.id,
            receiptDecision: receipt.decision,
          },
          null,
          2,
        ),
      );
      return;
    }

    if (!process.env.OPENAI_API_KEY) {
      throw new Error("OPENAI_API_KEY is required for a live OpenAI-compatible run");
    }

    const openai = new OpenAI({
      apiKey: process.env.OPENAI_API_KEY,
      baseURL: process.env.OPENAI_BASE_URL,
    });

    const messages = [
      {
        role: "system",
        content:
          "You are a helpful assistant. Use the provided function when it is relevant.",
      },
      { role: "user", content: livePrompt },
    ];
    const toolDefinitions = openAiToolsFromArc(tools);
    let lastToolResult = null;

    while (true) {
      const completion = await openai.chat.completions.create({
        model,
        messages,
        tools: toolDefinitions,
        tool_choice: "auto",
        store: false,
      });

      const message = completion.choices[0]?.message;
      if (!message) {
        throw new Error("chat completion did not return a message");
      }

      messages.push(message);
      const toolCalls = message.tool_calls ?? [];
      if (toolCalls.length === 0) {
        const receipt = await latestReceipt(controlUrl, authToken, capabilityId);
        console.log(
          JSON.stringify(
            {
              mode: "live",
              sessionId: session.sessionId,
              capabilityId,
              toolNames: tools.map((tool) => tool.name),
              assistantText: message.content ?? "",
              echo:
                lastToolResult?.structuredContent?.echo ??
                lastToolResult?.content?.find((item) => item.type === "text")?.text ??
                null,
              receiptId: receipt.id,
              receiptDecision: receipt.decision,
            },
            null,
            2,
          ),
        );
        return;
      }

      for (const toolCall of toolCalls) {
        if (toolCall.type !== "function") {
          continue;
        }
        const args =
          toolCall.function.arguments && toolCall.function.arguments.trim()
            ? JSON.parse(toolCall.function.arguments)
            : {};
        const result = await session.callTool(toolCall.function.name, args);
        lastToolResult = result;
        messages.push({
          role: "tool",
          tool_call_id: toolCall.id,
          content: renderToolResult(result),
        });
      }
    }
  } finally {
    await session.close();
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
