import { type FormEvent, useCallback, useEffect, useRef, useState } from 'react'
import {
  createDashboardSession,
  deleteDashboardSession,
  hasDashboardSession,
  onDashboardUnauthorized,
} from './api'
import type { DashboardReportAvailability } from './api'
import type { Filters } from './types'
import { FilterSidebar } from './components/FilterSidebar'
import { ProofRoomView } from './components/ProofRoomView'
import { ReceiptTable } from './components/ReceiptTable'

const INITIAL_FILTERS: Filters = {
  agentSubject: '',
  toolServer: '',
  toolName: '',
  outcome: '',
  since: undefined,
  until: undefined,
}

type DashboardSessionState = 'checking' | 'authenticated' | 'unauthenticated'

const MAX_TIMER_DELAY_MS = 2_147_483_647
const SESSION_EXPIRED_MESSAGE = 'Dashboard session expired. Sign in again.'

const NO_RELAY_REPORTS: DashboardReportAvailability = {
  observability: false,
  alerts: false,
  trends: false,
  alertHandoff: false,
  alertDelivery: false,
  alertAssurance: false,
  alertAssuranceExport: false,
  alertAssuranceReplay: false,
  alertAssuranceRetention: false,
  alertAssuranceArchive: false,
  alertAssuranceCloseout: false,
  alertAssuranceArchivePackage: false,
  alertAssuranceArchiveExtraction: false,
  alertAssurancePhysicalArchive: false,
  alertAssuranceRetentionHandoff: false,
  alertAssuranceArchiveRestoreDrill: false,
  alertAssuranceExternalRetentionReview: false,
}

export default function App() {
  const [filters, setFilters] = useState<Filters>(INITIAL_FILTERS)
  const [sessionState, setSessionState] = useState<DashboardSessionState>('checking')
  const [credential, setCredential] = useState('')
  const [authError, setAuthError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [relayReports, setRelayReports] = useState<DashboardReportAvailability>(NO_RELAY_REPORTS)
  const [sessionExpiresAt, setSessionExpiresAt] = useState<number | null>(null)
  const authenticated = useRef(false)
  const sessionCheckSequence = useRef(0)
  const isProofRoom =
    window.location.pathname === '/proof-room'
    || new URLSearchParams(window.location.search).get('view') === 'proof-room'

  const clearAuthenticatedSession = useCallback((message: string | null) => {
    sessionCheckSequence.current += 1
    authenticated.current = false
    setSessionExpiresAt(null)
    setSessionState('unauthenticated')
    setCredential('')
    setFilters(INITIAL_FILTERS)
    setRelayReports(NO_RELAY_REPORTS)
    setAuthError(message)
  }, [])

  const activateDashboardSession = useCallback((session: Awaited<ReturnType<typeof hasDashboardSession>>) => {
    if (
      !session
      || session.authenticated !== true
      || !Number.isSafeInteger(session.expiresAt)
      || session.expiresAt <= 0
      || session.expiresAt > Math.floor(Number.MAX_SAFE_INTEGER / 1000)
      || session.expiresAt * 1000 <= Date.now()
    ) {
      return false
    }
    authenticated.current = true
    setSessionExpiresAt(session.expiresAt)
    setRelayReports(session.relayReports)
    setAuthError(null)
    setSessionState('authenticated')
    return true
  }, [])

  const checkDashboardSession = useCallback(async () => {
    const checkSequence = sessionCheckSequence.current + 1
    sessionCheckSequence.current = checkSequence
    setSessionState('checking')
    try {
      const session = await hasDashboardSession()
      if (checkSequence !== sessionCheckSequence.current) return
      if (!session) {
        clearAuthenticatedSession(null)
        return
      }
      if (!activateDashboardSession(session)) {
        clearAuthenticatedSession(SESSION_EXPIRED_MESSAGE)
      }
    } catch {
      if (checkSequence === sessionCheckSequence.current) {
        clearAuthenticatedSession('Dashboard session status is unavailable.')
      }
    }
  }, [activateDashboardSession, clearAuthenticatedSession])

  useEffect(() => onDashboardUnauthorized(() => {
    clearAuthenticatedSession(authenticated.current ? SESSION_EXPIRED_MESSAGE : null)
  }), [clearAuthenticatedSession])

  useEffect(() => {
    if (isProofRoom) return
    void checkDashboardSession()
  }, [checkDashboardSession, isProofRoom])

  useEffect(() => {
    if (sessionExpiresAt === null) return
    let timer: number | undefined
    const expireAtDeadline = () => {
      const remaining = sessionExpiresAt * 1000 - Date.now()
      if (remaining <= 0) {
        clearAuthenticatedSession(SESSION_EXPIRED_MESSAGE)
        return
      }
      timer = window.setTimeout(expireAtDeadline, Math.min(remaining, MAX_TIMER_DELAY_MS))
    }
    expireAtDeadline()
    return () => {
      if (timer !== undefined) window.clearTimeout(timer)
    }
  }, [clearAuthenticatedSession, sessionExpiresAt])

  useEffect(() => {
    if (isProofRoom) return
    const recheckAuthenticatedSession = () => {
      if (authenticated.current) void checkDashboardSession()
    }
    const recheckVisibleSession = () => {
      if (document.visibilityState === 'visible') recheckAuthenticatedSession()
    }
    window.addEventListener('pageshow', recheckAuthenticatedSession)
    document.addEventListener('visibilitychange', recheckVisibleSession)
    return () => {
      window.removeEventListener('pageshow', recheckAuthenticatedSession)
      document.removeEventListener('visibilitychange', recheckVisibleSession)
    }
  }, [checkDashboardSession, isProofRoom])

  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!credential || submitting) return
    const submittedCredential = credential
    setCredential('')
    setSubmitting(true)
    setAuthError(null)
    sessionCheckSequence.current += 1
    try {
      const session = await createDashboardSession(submittedCredential)
      if (!activateDashboardSession(session)) {
        clearAuthenticatedSession('Dashboard session response is expired or invalid.')
      }
    } catch {
      clearAuthenticatedSession(null)
      setAuthError('Dashboard credential was rejected.')
    } finally {
      setSubmitting(false)
    }
  }

  async function logout() {
    setAuthError(null)
    sessionCheckSequence.current += 1
    try {
      await deleteDashboardSession()
      clearAuthenticatedSession(null)
    } catch {
      if (authenticated.current) {
        setAuthError('Dashboard sign-out failed. The session remains active.')
      }
    }
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <h1>{isProofRoom ? 'Chio Proof Room' : 'Chio Receipt Dashboard'}</h1>
        {!isProofRoom && sessionState === 'authenticated' ? (
          <button type="button" onClick={() => void logout()}>Sign out</button>
        ) : null}
      </header>
      {!isProofRoom && sessionState === 'authenticated' && authError ? (
        <p role="alert">{authError}</p>
      ) : null}
      {isProofRoom ? (
        <ProofRoomView />
      ) : sessionState === 'checking' ? (
        <div className="main-content">
          <div className="state-loading">Checking dashboard access...</div>
        </div>
      ) : sessionState === 'unauthenticated' ? (
        <div className="main-content">
          <section className="auth-notice">
            <h2>Dashboard credential required</h2>
            <p>Exchange the dedicated read credential for a short-lived browser session.</p>
            <form onSubmit={(event) => void login(event)}>
              <label htmlFor="dashboard-credential">Dashboard read credential</label>
              <input
                id="dashboard-credential"
                name="dashboard-credential"
                type="password"
                autoComplete="off"
                value={credential}
                onChange={(event) => setCredential(event.target.value)}
                disabled={submitting}
                required
              />
              <button type="submit" disabled={submitting || credential.length === 0}>
                {submitting ? 'Signing in...' : 'Sign in'}
              </button>
            </form>
            {authError ? <p role="alert">{authError}</p> : null}
          </section>
        </div>
      ) : (
        <div className="app-body">
          <FilterSidebar filters={filters} onFiltersChange={setFilters} />
          <ReceiptTable
            filters={filters}
            relayReports={relayReports}
          />
        </div>
      )}
    </div>
  )
}
