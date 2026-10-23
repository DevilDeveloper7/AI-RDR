import { useState } from 'react'
import HoneyTable from '../components/HoneyTable.jsx'
import PageHeader from '../components/PageHeader.jsx'
import StateMessage from '../components/StateMessage.jsx'
import StatCard from '../components/StatCard.jsx'
import { useApi } from '../hooks/useApi.js'
import { m6 } from '../services/api.js'
import { fmtTime } from '../utils/format.js'

export default function HoneyFilesPage() {
  const [selected, setSelected] = useState(null)
  const { data, error, loading, reload } = useApi(() => m6.honeyFiles(), [])
  const head = <PageHeader title="Honey Files" sub="Deception path · interaction is treated as a high-confidence alert" />
  if (!data) return <section className="screen">{head}<StateMessage loading={loading} error={error} onRetry={reload} /></section>
  const { summary: s, items, activity } = data
  const sel = selected != null ? items[selected] : null
  return (
    <section className="screen">
      {head}
      <div className="grid">
        <div className="c3"><StatCard label="Watcher" value={s.watcher_status} /></div>
        <div className="c3"><StatCard label="Honey files" value={s.total_files} /></div>
        <div className="c3"><StatCard label="Triggered" value={s.triggered} crit /></div>
        <div className="c3"><StatCard label="Last interaction" value={s.last_interaction ? fmtTime(s.last_interaction.time) : '—'} /></div>
        <div className="card c8">
          <h3>Monitored honey files<span>inotify: active on {s.monitored_hosts} of {s.total_hosts} hosts</span></h3>
          <HoneyTable items={items} selected={selected} onSelect={setSelected} />
        </div>
        <div className="card c4" style={{ alignSelf: 'start' }}>
          <h3 className="rule">Recent activity</h3>
          <div className="pad" style={{ paddingTop: 20 }}>
            <ul className="tl">
              {activity.map((r, i) => (<li key={i} className={r.hot ? 'hot' : undefined}><time>{fmtTime(r.timestamp)}</time><span className={r.hot ? undefined : 'mut'}>{r.text}</span></li>))}
            </ul>
            {sel && <div className="note" style={{ marginTop: 18 }}>Selected: <b>{sel.file}</b> on {sel.host}, {sel.location}</div>}
          </div>
        </div>
      </div>
    </section>
  )
}
