// Typed fetch wrappers for PACT receipt query and lineage endpoints.
// All endpoints require Bearer auth. Token is read from URL ?token= param on
// first load and stored in sessionStorage for subsequent calls.

import type { CapabilitySnapshot, Filters, Receipt, ReceiptQueryResponse } from './types'

const TOKEN_KEY = 'pact_token'

/**
 * Read Bearer token from sessionStorage or URL query param.
 * Stores in sessionStorage for subsequent calls.
 * Returns empty string if neither source provides a token.
 */
export function getToken(): string {
  const stored = sessionStorage.getItem(TOKEN_KEY)
  if (stored) return stored

  const param = new URLSearchParams(window.location.search).get('token')
  if (param) {
    sessionStorage.setItem(TOKEN_KEY, param)
    // Remove the token from the URL bar and history so it is not leaked via
    // the Referer header, browser history, or shoulder-surfing.
    window.history.replaceState({}, document.title, window.location.pathname)
    return param
  }
  return ''
}

/**
 * Wraps fetch with Authorization header injection.
 */
async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  const token = getToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(init?.headers as Record<string, string> | undefined),
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  const res = await fetch(path, { ...init, headers })
  if (!res.ok) {
    throw new Error(`API error ${res.status}: ${res.statusText}`)
  }
  return res
}

/**
 * Build query string from a Filters object, omitting undefined/empty values.
 */
function buildQuery(params: Record<string, string | number | undefined | null>): string {
  const entries = Object.entries(params).filter(
    ([, v]) => v !== undefined && v !== null && v !== ''
  )
  if (entries.length === 0) return ''
  return '?' + entries.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&')
}

/**
 * Fetch a page of receipts using the filter and cursor parameters.
 */
export async function fetchReceipts(
  filters: Filters,
  cursor?: number | null,
  limit = 50,
): Promise<ReceiptQueryResponse> {
  const query = buildQuery({
    agentSubject: filters.agentSubject,
    toolServer: filters.toolServer,
    toolName: filters.toolName,
    outcome: filters.outcome || undefined,
    since: filters.since,
    until: filters.until,
    cursor: cursor ?? undefined,
    limit,
  })
  const res = await apiFetch(`/v1/receipts/query${query}`)
  return res.json() as Promise<ReceiptQueryResponse>
}

/**
 * Fetch a single capability snapshot by ID.
 */
export async function fetchLineage(capabilityId: string): Promise<CapabilitySnapshot> {
  const res = await apiFetch(`/v1/lineage/${encodeURIComponent(capabilityId)}`)
  return res.json() as Promise<CapabilitySnapshot>
}

/**
 * Fetch the full delegation chain (root-first) for a capability.
 */
export async function fetchDelegationChain(capabilityId: string): Promise<CapabilitySnapshot[]> {
  const res = await apiFetch(`/v1/lineage/${encodeURIComponent(capabilityId)}/chain`)
  return res.json() as Promise<CapabilitySnapshot[]>
}

/**
 * Fetch receipts for a specific agent subject key.
 */
export async function fetchAgentReceipts(
  subjectKey: string,
  cursor?: number | null,
  limit = 50,
): Promise<ReceiptQueryResponse> {
  const query = buildQuery({ cursor: cursor ?? undefined, limit })
  const encoded = encodeURIComponent(subjectKey)
  const res = await apiFetch(`/v1/agents/${encoded}/receipts${query}`)
  return res.json() as Promise<ReceiptQueryResponse>
}

/**
 * Fetch all receipts for an agent and compute per-day cost data for the sparkline.
 * Returns an array of { time: string (date label), cost: number (minor units) }.
 */
export async function fetchAgentCostSeries(
  subjectKey: string,
): Promise<{ time: string; cost: number }[]> {
  // Fetch up to 200 receipts to build sparkline data
  const result = await fetchAgentReceipts(subjectKey, null, 200)
  const buckets = new Map<string, number>()

  for (const receipt of result.receipts) {
    const financial = receipt.metadata?.financial
    if (!financial) continue
    const date = new Date(receipt.timestamp * 1000)
    // Format as YYYY-MM-DD
    const key = date.toISOString().slice(0, 10)
    buckets.set(key, (buckets.get(key) ?? 0) + financial.cost_charged)
  }

  return Array.from(buckets.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([time, cost]) => ({ time, cost }))
}

// Re-export Receipt type for convenience
export type { Receipt, ReceiptQueryResponse, CapabilitySnapshot, Filters }
