import type {
  Agent_ToolCallRequest,
  Kernel_CapabilityList,
  Security_DetectorHealthReceiptBodyV1,
} from "./_generated/index.js";

type Assert<T extends true> = T;
type IsPresent<T> = [Exclude<T, undefined>] extends [never] ? false : true;
type IsNever<T> = [T] extends [never] ? true : false;

type ToolCallRequest = Agent_ToolCallRequest.ChioAgentMessageToolCallRequest;
type CapabilityListEntry =
  Kernel_CapabilityList.ChioKernelMessageCapabilityList["capabilities"][number];
type DetectorHealthReceipt =
  Security_DetectorHealthReceiptBodyV1.ChioDetectorHealthReceiptBodyV1;
type UnresolvedDetectorHealth = Extract<
  DetectorHealthReceipt,
  { group_binding: { kind: "unresolved" } }
>;
type ContradictoryDetectorHealth = Extract<
  DetectorHealthReceipt,
  { watermark: { kind: "contradictory" } }
>;

export type GeneratedToolCallRequestApprovalTokenPresent = Assert<
  IsPresent<ToolCallRequest["approval_token"]>
>;
export type GeneratedToolCallRequestApprovalTokensPresent = Assert<
  IsPresent<ToolCallRequest["approval_tokens"]>
>;
export type GeneratedCapabilityListAggregateInvocationBudgetPresent = Assert<
  IsPresent<CapabilityListEntry["aggregate_invocation_budget"]>
>;
export type GeneratedUnresolvedDetectorWatermarkIsUnknown = Assert<
  IsNever<UnresolvedDetectorHealth> extends false
    ? UnresolvedDetectorHealth["watermark"] extends { kind: "unknown" }
      ? true
      : false
    : false
>;
export type GeneratedContradictoryDetectorGroupIsResolved = Assert<
  IsNever<ContradictoryDetectorHealth> extends false
    ? ContradictoryDetectorHealth["group_binding"] extends { kind: "resolved" }
      ? true
      : false
    : false
>;
export type GeneratedContradictoryDetectorHealthIsCorruptState = Assert<
  IsNever<ContradictoryDetectorHealth> extends false
    ? ContradictoryDetectorHealth["health_kind"] extends "corrupt_state"
      ? true
      : false
    : false
>;
