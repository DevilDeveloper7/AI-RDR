import { ResponseBadge, SeverityBadge, StatusBadge } from './Badge.jsx'
import { fmtDateTime, fmtTime } from '../utils/format.js'

const onKey = (fn) => (e) => { if (e.key === 'Enter') fn() }

// variant "feed": Dashboard live feed. variant "full": Alerts page table.
export default function AlertTable({ alerts, variant = 'feed', selectedId, onSelect, onInvestigate }) {
  if (variant === 'feed') {
    return (
      <div className="tw"><table>
        <thead><tr><th>Severity</th><th>Detection</th><th>Time</th><th>Host</th><th>Process / activity</th><th>State</th></tr></thead>
        <tbody>
          {alerts.map((a) => (
            <tr key={a.id} className="row" tabIndex={0} onClick={() => onSelect(a)} onKeyDown={onKey(() => onSelect(a))}>
              <td><SeverityBadge severity={a.severity} /></td>
              <td>{a.detection_type}<span className="sub">{a.id}</span></td>
              <td className="mono">{fmtTime(a.timestamp)}</td>
              <td>{a.host}</td>
              <td className="mono">{a.process}</td>
              <td><ResponseBadge alert={a} />{a.status === 'Open' && <> <StatusBadge status="Open" /></>}</td>
            </tr>
          ))}
        </tbody>
      </table></div>
    )
  }
  return (
    <div className="tw"><table>
      <thead><tr><th>Severity</th><th>Alert ID</th><th>Detection type</th><th>Host</th><th>Process / activity</th><th>Timestamp</th><th>Response state</th><th colSpan={2}>Status / action</th></tr></thead>
      <tbody>
        {alerts.length === 0 && (
          <tr><td colSpan={9} className="mut" style={{ textAlign: 'center', padding: 32 }}>No alerts match the current filters.</td></tr>
        )}
        {alerts.map((a) => (
          <tr key={a.id} className={`row${a.id === selectedId ? ' sel' : ''}`} tabIndex={0} onClick={() => onSelect(a)} onKeyDown={onKey(() => onSelect(a))}>
            <td><SeverityBadge severity={a.severity} /></td>
            <td className="mono nowrap">{a.id}</td>
            <td>{a.detection_type}</td>
            <td className="nowrap">{a.host}</td>
            <td className="mono">{a.process}</td>
            <td className="mono">{fmtDateTime(a.timestamp)}</td>
            <td><ResponseBadge alert={a} /></td>
            <td className="cell-status"><StatusBadge status={a.status} /></td>
            <td className="cell-action"><button className="btn sm" onClick={(e) => { e.stopPropagation(); onInvestigate(a) }}>Investigate</button></td>
          </tr>
        ))}
      </tbody>
    </table></div>
  )
}
