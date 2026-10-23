import { useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { ReputationBadge } from '../components/Badge.jsx'
import PageHeader from '../components/PageHeader.jsx'
import StateMessage from '../components/StateMessage.jsx'
import { useApi } from '../hooks/useApi.js'
import { m6 } from '../services/api.js'
import { fmtTime, shortHash } from '../utils/format.js'

export default function ThreatIntelPage() {
  const navigate = useNavigate()
  const [picked, setPicked] = useState(useLocation().state?.indicator || null)
  const list = useApi(() => m6.intel(), [])
  const items = list.data?.items || []
  const current = items.find((t) => t.indicator === picked) || items[0]
  const detail = useApi(() => (current ? m6.intelDetail(current.indicator) : Promise.resolve(null)), [current?.indicator])
  const head = <PageHeader title="Threat Intelligence" sub="Enrichment context attached to alerts. Not used for the detection decision." />
  if (!list.data) return <section className="screen">{head}<StateMessage loading={list.loading} error={list.error} onRetry={list.reload} /></section>
  const t = detail.data || current
  return (
    <section className="screen">
      {head}
      <div className="grid">
        <div className="card c8" style={{ alignSelf: 'start' }}>
          <h3>Indicators</h3>
          <div className="tw"><table>
            <thead><tr><th>Indicator</th><th>Type</th><th>Reputation</th><th>Source</th><th>Related alert</th><th>Checked</th></tr></thead>
            <tbody>
              {items.map((x) => (
                <tr key={x.indicator} className={`row${x.indicator === current?.indicator ? ' sel' : ''}`} tabIndex={0}
                    onClick={() => setPicked(x.indicator)} onKeyDown={(e) => e.key === 'Enter' && setPicked(x.indicator)}>
                  <td className="mono" title={x.indicator}>{shortHash(x.indicator)}</td><td>{x.type}</td><td><ReputationBadge reputation={x.reputation} /></td>
                  <td>{x.source}</td><td className="mono">{x.related_alert}</td><td className="mono">{fmtTime(x.last_checked)}</td>
                </tr>
              ))}
            </tbody>
          </table></div>
        </div>
        {t && (
          <div className="card c4" style={{ alignSelf: 'start' }}>
            <h3 className="rule">Indicator detail</h3>
            <div className="pad" style={{ paddingTop: 20 }}>
              <dl style={{ gridTemplateColumns: '100px 1fr' }}>
                <dt>Value</dt><dd className="mono" title={t.indicator} style={{ wordBreak: 'break-all' }}>{shortHash(t.indicator)}</dd>
                <dt>Type</dt><dd>{t.type}</dd>
                <dt>Reputation</dt><dd><ReputationBadge reputation={t.reputation} /></dd>
                <dt>Source</dt><dd>{t.source}</dd>
                <dt>Alert</dt><dd className="mono">{t.related_alert}</dd>
              </dl>
              <div className="note" style={{ margin: '20px 0' }}>{t.notes}</div>
              <button className="btn" onClick={() => navigate(`/alerts/${t.related_alert}`)}>Open alert {t.related_alert}</button>
            </div>
          </div>
        )}
      </div>
    </section>
  )
}
