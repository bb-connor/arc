// Exercise the published TypeScript client's result validation over real stdio.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { ListTasksResultSchema } from "@modelcontextprotocol/sdk/types.js";

const configPath = process.argv[2];
if (!configPath) throw new Error("Usage: npm run check -- /path/to/adopted/mcp.json");
const config = JSON.parse(await readFile(configPath, "utf8"));
const entry = config.mcpServers.journal;
const client = new Client({ name: "chio-typescript-acceptance", version: "1.0.0" });
const transport = new StdioClientTransport({
  command: entry.command, args: entry.args, env: entry.env,
});
try {
  await client.connect(transport);
  const pages = {
    tools: await client.listTools(),
    resources: await client.listResources(),
    resourceTemplates: await client.listResourceTemplates(),
    prompts: await client.listPrompts(),
    tasks: await client.request({ method: "tasks/list" }, ListTasksResultSchema),
  };
  assert.deepEqual(pages.tools.tools.map((tool) => tool.name), ["append_note"]);
  for (const [name, page] of Object.entries(pages)) {
    assert.equal(Object.hasOwn(page, "nextCursor"), false, `${name}: terminal cursor must be omitted`);
  }
  console.log(JSON.stringify({ validated_pages: Object.keys(pages), discovered_tools: ["append_note"] }));
} finally {
  await client.close();
}
