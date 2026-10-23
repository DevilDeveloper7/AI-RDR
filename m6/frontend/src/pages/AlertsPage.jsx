import { useEffect, useRef, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import AlertSummaryPanel from '../components/AlertSummaryPanel.jsx'
import AlertTable from '../components/AlertTable.jsx'
import FilterBar from '../components/FilterBar.jsx'
import PageHeader from '../components/PageHeader.jsx'
import Pagination from '../components/Pagination.jsx'
import { useToast } from '../components/Toast.jsx'
import { useApi } from '../hooks/useApi.js'
import { m6 } from '../services/api.js'
import { fmtTime } from '../utils/format.js'

const KEYS = ['q', 'severity', 'detection_type', 'response_state', 'host', 'range_minutes']
const EMPTY = Object.fromEntries(KEYS.map((k) => [k, '']))

export default function AlertsPage() {
  const navigate = useNavigate()
  const toast = useToast()
  // The URL is the single source of the filters, so the top-bar search, the Dashboard cards and this page all share them.
  const [searchParams, setSearchParams] = useSearchParams()
  const filters = Object.fromEntries(KEYS.map((k) => [k, searchParams.get(k) || '']))
  const setFilters = (next) => {
    const out = new URLSearchParams()
    KEYS.forEach((k) => { if (next[k]) out.set(k, next[k]) })
    setSearchParams(out, { replace: true })
  }
  const [qText, setQText] = useState(filters.q) // what is typed in this page's search box
  const typing = useRef(null)
  const [page, setPage] = useState(1)
  const [selectedId, setSelectedId] = useState(null)
  const params = { ...filters, page, page_size: 20 }
  const { data, error, loading, reload } = useApi(() => m6.alerts(params), [JSON.stringify(params)])
  const facets = useRef({ hosts: [], severities: [], detection_types: [], response_states: [] })
  if (data) facets.current = data.facets

  const filterKey = JSON.stringify(filters)
  useEffect(() => { setPage(1) }, [filterKey])
  // A search that arrives from outside (top bar, Reset) replaces what is typed and cancels a pending edit.
  useEffect(() => { clearTimeout(typing.current); setQText(filters.q) }, [filters.q])
  const onQuery = (value) => {
    setQText(value)
    clearTimeout(typing.current)
    typing.current = setTimeout(() => setFilters({ ...filters, q: value }), 300)
  }
  useEffect(() => {
    const onKey = (e) => e.key === 'Escape' && setSelectedId(null)
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [])

  const selected = data?.items.find((a) => a.id === selectedId) || null
  const open = (a) => navigate(`/alerts/${a.id}`, { state: { from: 'alerts' } })
  const acknowledge = async () => {
    try {
      const res = await m6.acknowledge(selected.id)
      toast(`${selected.id} acknowledged by ${res.acknowledged_by}`)
      reload()
    } catch (e) { toast(e.message) }
  }
  const from = data ? (page - 1) * data.page_size + 1 : 0

  return (
    <section className="screen">
      <PageHeader title="Alerts" sub="Review and investigate detected security events">
        <span className="mut">Monitoring active{data ? ` · last telemetry ${fmtTime(data.meta.reference_time)}` : ''}</span>
      </PageHeader>
      <div className="card">
        <FilterBar filters={{ ...filters, q: qText }} facets={facets.current} onChange={(next) => (next.q !== qText ? onQuery(next.q) : setFilters(next))} onReset={() => setFilters(EMPTY)} />
        <h3>All alerts<span>{data ? (data.total ? `Showing ${from}–${from + data.items.length - 1} of ${data.total}` : '0 results') : ''}</span></h3>
        {data ? (
          <AlertTable alerts={data.items} variant="full" selectedId={selectedId} onSelect={(a) => setSelectedId(a.id)} onInvestigate={open} />
        ) : <div className="pad mut">{error ? <>{error.message}{error.retryable && <> <button className="link" onClick={reload}>Retry</button></>}</> : loading && 'Loading…'}</div>}
        {data && <Pagination page={data.page} pages={data.pages} info={`${data.summary.open} open alerts`} onPage={setPage} />}
      </div>
      <AlertSummaryPanel alert={selected} onClose={() => setSelectedId(null)} onOpenDetail={() => open(selected)} onAcknowledge={acknowledge} />
    </section>
  )
}
