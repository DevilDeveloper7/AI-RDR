import { useEffect, useRef, useState } from 'react'
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom'
import Icon from './Icon.jsx'
import { m6 } from '../services/api.js'

// Does the typed text identify one threat-intelligence indicator (whole value, start, end, or the shortened "9f2c…e41a" form)?
function matchesIndicator(value, q) {
  const v = value.toLowerCase()
  const t = q.toLowerCase()
  if (t.includes('…') || t.includes('...')) {
    const [head, tail] = t.split(/…|\.\.\./)
    return v.startsWith(head) && v.endsWith(tail)
  }
  return t.length >= 4 && (v === t || v.startsWith(t) || v.endsWith(t))
}

// Header search. Enter opens the matching threat-intelligence indicator if the text identifies one;
// otherwise it searches alert records through the same `q` filter the Alerts page uses (/alerts?q=...).
export default function SearchBox() {
  const navigate = useNavigate()
  const { pathname } = useLocation()
  const [params] = useSearchParams()
  const onAlerts = pathname === '/alerts'
  const urlQuery = onAlerts ? params.get('q') || '' : ''
  const [text, setText] = useState(urlQuery)
  const input = useRef(null)

  // Show the active search on the Alerts page; empty it everywhere else.
  useEffect(() => { setText(urlQuery) }, [pathname, urlQuery])

  const go = (q) => {
    const next = new URLSearchParams(onAlerts ? params : undefined)
    if (q) next.set('q', q); else next.delete('q')
    const qs = next.toString()
    navigate(`/alerts${qs ? `?${qs}` : ''}`)
  }
  const submit = async () => {
    const q = text.trim()
    if (!q && !urlQuery) return
    if (q) {
      try {
        const hit = (await m6.intel()).items.find((t) => matchesIndicator(t.indicator, q))
        if (hit) { navigate('/threat-intelligence', { state: { indicator: hit.indicator } }); return }
      } catch { /* intelligence unavailable: fall back to the alert search */ }
    }
    go(q)
  }
  const clear = () => {
    setText('')
    if (onAlerts && urlQuery) go('')
    input.current?.focus()
  }
  const onKeyDown = (e) => {
    if (e.key === 'Enter') submit()
    if (e.key === 'Escape' && text) clear()
  }

  return (
    <div className="search" role="search">
      <Icon name="search" />
      <input ref={input} aria-label="Search all alerts" placeholder="Search alerts, hosts, indicators" value={text}
             onChange={(e) => setText(e.target.value)} onKeyDown={onKeyDown} />
      {text && <button className="search-clear" aria-label="Clear search" onClick={clear}><Icon name="x" /></button>}
    </div>
  )
}
