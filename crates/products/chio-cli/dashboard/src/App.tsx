import { useEffect, useState } from 'react'
import { clearToken, getToken, setToken } from './api'
import type { Filters } from './types'
import { BearerLogin } from './components/BearerLogin'
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

export default function App() {
  const [filters, setFilters] = useState<Filters>(INITIAL_FILTERS)
  const [token, setActiveToken] = useState<string | null>(null)
  const [storageError, setStorageError] = useState('')
  const isProofRoom =
    window.location.pathname === '/proof-room'
    || new URLSearchParams(window.location.search).get('view') === 'proof-room'

  useEffect(() => {
    try {
      setActiveToken(getToken())
    } catch {
      setStorageError('Unable to read token storage in this tab.')
    }
  }, [])

  const missingToken = token !== null && token.length === 0

  function login(value: string) {
    setToken(value)
    setStorageError('')
    setActiveToken(value)
  }

  function logout() {
    try {
      clearToken()
    } catch {
      setStorageError('Unable to clear token storage. Close this tab to finish logging out.')
    } finally {
      setActiveToken('')
      setFilters(INITIAL_FILTERS)
    }
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <h1>{isProofRoom ? 'Chio Proof Room' : 'Chio Receipt Dashboard'}</h1>
        {!isProofRoom && token && (
          <button className="btn-clear auth-logout" type="button" onClick={logout}>Log out</button>
        )}
      </header>
      {token === null ? (
        <div className="main-content">
          <div className={storageError ? 'state-error' : 'state-loading'} role={storageError ? 'alert' : undefined}>
            {storageError || 'Checking dashboard access...'}
          </div>
        </div>
      ) : isProofRoom ? (
        <ProofRoomView />
      ) : missingToken ? (
        <div className="main-content">
          <BearerLogin onLogin={login} storageError={storageError} />
        </div>
      ) : (
        <div className="app-body">
          <FilterSidebar filters={filters} onFiltersChange={setFilters} />
          <ReceiptTable filters={filters} />
        </div>
      )}
    </div>
  )
}
