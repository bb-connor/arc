import Anthropic from "@anthropic-ai/sdk";
import { ArcClient, ReceiptQueryClient } from "@arc-protocol/sdk";

const DEFAULT_ARC_BASE_URL = "http://127.0.0.1:8931";
const DEFAULT_ARC_CONTROL_URL = "http://127.0.0.1:8940";
const DEFAULT_ARC_AUTH_TOKEN = "demo-token";
const livePrompt =
  process.argv.filter((arg) => !arg.startsWith("--")).slice(2).join(" ") ||
  "Use the echo_text tool to send back a short hello from Claude.";
const dryRun = process.argv.includes("--dry-run");
const model = process.env.ANTHROPIC_MODEL ?? "claude-sonnet-4-20250514";

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

function anthropicToolsFromMcp(tools) {
  return tools.map((tool) => ({
    name: tool.name,
    description: tool.description ?? "",
    input_schema: tool.inputSchema ?? { type: "object", properties: {} },
  }));
}

function renderToolResult(result) {
  if (result.structuredContent) {
    return JSON.stringify(result.structuredContent, null, 2);
  }
  if (Array.isArray(result.content)) {
    return result.content
      .filter((item) => item.type === "text")
      .map((item) => item.text)
      .join("\n");
  }
  return JSON.stringify(result, null, 2);
}

function normalizeAssistantContent(blocks) {
  return blocks.map((block) => {
    if (block.type === "text") {
      return { type: "text", text: block.text };
    }
    if (block.type === "tool_use") {
      return {
        type: "tool_use",
        id: block.id,
        name: block.name,
        input: block.input,
      };
    }
    return block;
  });
}

function textFromResponse(blocks) {
  return blocks
    .filter((block) => block.type === "text")
    .map((block) => block.text)
    .join("\n");
}

async function main() {
  const { baseUrl, controlUrl, authToken } = arcConfig();
  const client = ArcClient.withStaticBearer(baseUrl, authToken);
  const session = await client.initialize({
    clientInfo: { name: "anthropic-sdk-example", version: "0.2.0" },
  });
  try {
    const toolsResult = await session.listTools();
    const tools = toolsResult.tools ?? [];
    const capabilityId = await sessionCapabilityId(baseUrl, authToken, session.sessionId);

    if (dryRun) {
      const result = await session.callTool("echo_text", {
        message: "hello from the Anthropic SDK dry-run",
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

    if (!process.env.ANTHROPIC_API_KEY) {
      throw new Error("ANTHROPIC_API_KEY is required for a live Claude run");
    }

    const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
    const anthropicTools = anthropicToolsFromMcp(tools);
    const messages = [{ role: "user", content: livePrompt }];
    let lastToolResult = null;

    while (true) {
      const response = await anthropic.messages.create({
        model,
        max_tokens: 512,
        messages,
        tools: anthropicTools,
      });

      messages.push({
        role: "assistant",
        content: normalizeAssistantContent(response.content),
      });

      const toolUses = response.content.filter((block) => block.type === "tool_use");
      if (toolUses.length === 0) {
        const receipt = await latestReceipt(controlUrl, authToken, capabilityId);
        console.log(
          JSON.stringify(
            {
              mode: "live",
              sessionId: session.sessionId,
              capabilityId,
              toolNames: tools.map((tool) => tool.name),
              assistantText: textFromResponse(response.content),
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

      const toolResults = [];
      for (const toolUse of toolUses) {
        const result = await session.callTool(toolUse.name, toolUse.input ?? {});
        lastToolResult = result;
        toolResults.push({
          type: "tool_result",
          tool_use_id: toolUse.id,
          content: renderToolResult(result),
        });
      }

      messages.push({ role: "user", content: toolResults });
    }
  } finally {
    await session.close();
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
