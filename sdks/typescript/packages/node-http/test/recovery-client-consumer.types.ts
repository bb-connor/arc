import {
  LosslessJsonNumber,
  RecoveryClient,
  type LosslessJsonValue,
  type RecoveryCommandResult,
} from "../src/index.js";

// Compile as a public SDK consumer. The opaque result never becomes an
// implicit floating-point authority claim or an untyped generated DTO field.
export async function consumeResult(client: RecoveryClient): Promise<string | undefined> {
  const response: RecoveryCommandResult = await client.execute("capability", {
    schema: "chio.recovery.command.v1", version: 1, command_id: "command",
    command: { kind: "inspect_workflow", workflow_id: "workflow" },
  });
  if (response.original_response === undefined) return undefined;
  const value: LosslessJsonValue = response.original_response.result;
  if (value !== null && typeof value === "object" && !Array.isArray(value)
      && !(value instanceof LosslessJsonNumber)) {
    const wide = value.wide;
    if (wide instanceof LosslessJsonNumber) {
      const token: string = wide.source;
      if (/^-?(?:0|[1-9][0-9]*)$/.test(token)) {
        const exact: bigint = wide.toBigInt();
        void exact;
      }
    }
  }
  return response.original_response.result_json;
}
