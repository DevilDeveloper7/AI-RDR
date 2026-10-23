import { Link, useNavigate } from 'react-router-dom'
import AlertTable from '../components/AlertTable.jsx'
import { ReputationBadge } from '../components/Badge.jsx'
import HoneyTable from '../components/HoneyTable.jsx'
import PageHeader from '../components/PageHeader.jsx'
import StatCard from '../components/StatCard.jsx'
import { useApi } from '../hooks/useApi.js'
import { m6 } from '../services/api.js'
import { fmtTime, shortHash } from '../utils/format.js'

const failed = (api, retry) => (
  <div className="pad mut">{api.error ? <>{api.error.message}{api.error.retryable && retry && <> <button className="link" onClick={retry}>Retry</button></>}</> : 'Loading…'}</div>
)

export default function DashboardPage() {
  const navigate = useNavigate()
  const alerts = useApi(() => m6.alerts({ page_size: 5 }), [])
  const honey = useApi(() => m6.honeyFiles(), [])
  const intel = useApi(() => m6.intel({ limit: 4 }), [])
  const activity = useApi(() => m6.activity(5), [])
  const s = alerts.data?.summary
  const h = honey.data?.summary
  const last = alerts.data?.meta.reference_time

  return (
    <section className="screen">
      <PageHeader title="Dashboard" sub={last ? `Monitoring active · last telemetry received ${fmtTime(last)}` : 'Monitoring active'} />
      <div className="grid">
        <div className="c3"><StatCard label="Active Alerts" value={s ? s.active : '—'} to="/alerts?response_state=Frozen" /></div>
        <div className="c3"><StatCard label="Critical Alerts" value={s ? s.critical : '—'} crit to="/alerts?severity=Critical&response_state=Frozen" /></div>
        <div className="c3"><StatCard label="Honey Files" value={h ? `${h.total_files} · ${h.triggered} triggered` : '—'} to="/honey-files" /></div>
        <div className="c3"><StatCard label="Systems Monitored" value={h ? `${h.monitored_hosts} of ${h.total_hosts} hosts` : '—'} to="/honey-files" /></div>

        <div className="card c12">
          <h3>Live Alert Feed<span>Select an alert to investigate</span></h3>
          {alerts.data
            ? <AlertTable alerts={alerts.data.items} variant="feed" onSelect={(a) => navigate(`/alerts/${a.id}`, { state: { from: 'dashboard' } })} />
            : failed(alerts, alerts.reload)}
        </div>

        <div className="card c6">
          <h3>Monitored honey files<span>{h ? `inotify: active on ${h.monitored_hosts} of ${h.total_hosts} hosts` : <Link to="/honey-files">View all</Link>}</span></h3>
          {honey.data ? <HoneyTable items={honey.data.items} compact /> : failed(honey, honey.reload)}
        </div>

        <div className="card c6">
          <h3>Threat Intelligence Context<span>Enrichment only</span></h3>
          {intel.data ? (
            <div className="tw tight"><table>
              <thead><tr><th>Indicator</th><th>Type</th><th>Reputation</th><th>Checked</th></tr></thead>
              <tbody>
                {intel.data.items.map((t) => (
                  <tr key={t.indicator} className="row" tabIndex={0}
                      onClick={() => navigate('/threat-intelligence', { state: { indicator: t.indicator } })}
                      onKeyDown={(e) => e.key === 'Enter' && navigate('/threat-intelligence', { state: { indicator: t.indicator } })}>
                    <td className="mono" title={t.indicator}>{shortHash(t.indicator)}</td><td>{t.type}</td>
                    <td><ReputationBadge reputation={t.reputation} /></td><td className="mono">{fmtTime(t.last_checked)}</td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          ) : failed(intel, intel.reload)}
        </div>

        <div className="card c12">
          <h3 className="rule">Recent Response Activity</h3>
          <div className="pad" style={{ paddingTop: 24 }}>
            {activity.data ? (
              <ul className="tl big">
                {activity.data.items.map((r, i) => (
                  <li key={i} className={i < 1 ? 'hot' : undefined}>
                    <time>{fmtTime(r.timestamp)}</time>
                    <span><b>{r.event}</b> <span className="mut">· {r.detail} · {r.alert_id}</span></span>
                  </li>
                ))}
              </ul>
            ) : <span className="mut">{activity.error ? activity.error.message : 'Loading…'}</span>}
          </div>
        </div>
      </div>
    </section>
  )
}
