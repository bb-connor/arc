// Mirror of API response shapes from the PACT receipt query and lineage endpoints.

export type DecisionKind = 'allow' | 'deny' | 'cancelled' | 'incomplete'

export interface FinancialMetadata {
  grant_index: number
  cost_charged: number
  currency: string
  budget_remaining: number
  budget_total: number
  delegation_depth: number
  root_budget_holder: string
  settlement_status: string
}

export interface ReceiptAction {
  parameters: Record<string, unknown>
  parameter_hash: string
}

export type ReceiptDecision =
  | 'allow'
  | { deny: { reason: string; guard: string } }
  | { cancelled: Record<string, unknown> }
  | { incomplete: Record<string, unknown> }

export interface ReceiptMetadata {
  financial?: FinancialMetadata
}

export interface Receipt {
  id: string
  timestamp: number
  capability_id: string
  tool_server: string
  tool_name: string
  action: ReceiptAction
  decision: ReceiptDecision
  metadata?: ReceiptMetadata
}

export interface ReceiptQueryResponse {
  totalCount: number
  nextCursor: number | null
  receipts: Receipt[]
}

export interface CapabilitySnapshot {
  capability_id: string
  subject_key: string
  issuer_key: string
  issued_at: number
  expires_at: number
  grants_json: string
  delegation_depth: number
  parent_capability_id: string | null
}

export interface Filters {
  agentSubject?: string
  toolServer?: string
  toolName?: string
  outcome?: DecisionKind | ''
  since?: number
  until?: number
}

/**
 * Extract a DecisionKind label from a raw receipt decision value.
 */
export function decisionKind(decision: ReceiptDecision): DecisionKind {
  if (decision === 'allow') return 'allow'
  if (typeof decision === 'object' && 'deny' in decision) return 'deny'
  if (typeof decision === 'object' && 'cancelled' in decision) return 'cancelled'
  return 'incomplete'
}

/**
 * Format a minor-unit integer as a currency string for display purposes only.
 * Uses string arithmetic -- never converts to float for monetary calculations.
 */
export function formatMinorUnits(amount: number, currency: string): string {
  const major = Math.floor(amount / 100)
  const minor = amount % 100
  const minorStr = minor.toString().padStart(2, '0')
  const prefix = currency === 'USD' ? '$' : `${currency} `
  return `${prefix}${major}.${minorStr}`
}
