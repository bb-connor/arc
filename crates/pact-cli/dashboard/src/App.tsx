import { useEffect, useState } from 'react'
import { getToken } from './api'
import type { Filters } from './types'
import { FilterSidebar } from './components/FilterSidebar'
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

  // Read bearer token from URL param or sessionStorage on mount
  useEffect(() => {
    getToken()
  }, [])

  return (
    <div className="app-shell">
      <header className="app-header">
        <h1>PACT Receipt Dashboard</h1>
      </header>
      <div className="app-body">
        <FilterSidebar filters={filters} onFiltersChange={setFilters} />
        <ReceiptTable filters={filters} />
      </div>
    </div>
  )
}
