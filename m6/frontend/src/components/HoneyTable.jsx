import { useNavigate } from 'react-router-dom'
import { HoneyBadge } from './Badge.jsx'
import { fmtTime } from '../utils/format.js'

// Honey-file table shared by the Dashboard (compact) and the Honey Files page (selectable rows).
// The API has no decoy identifier, so "D1…Dn" is the position in the list; the host stays visible under it.
export default function HoneyTable({ items, compact, selected, onSelect }) {
  const navigate = useNavigate()
  return (
    <div className={`tw${compact ? ' tight' : ''}`}><table>
      <thead><tr><th>Decoy ID</th><th>Honey file</th><th>Location</th><th>Status</th><th>Last event</th><th>Action</th></tr></thead>
      <tbody>
        {items.map((h, i) => (
          <tr key={h.host} className={onSelect ? `row${selected === i ? ' sel' : ''}` : undefined}
              onClick={onSelect ? () => onSelect(i) : undefined}>
            <td>D{i + 1}<span className="sub" style={{ fontFamily: 'inherit', fontSize: 11 }}>{h.host}</span></td>
            <td className="mono">{h.file}</td><td className="mono">{h.location}</td>
            <td><HoneyBadge status={h.status} /></td>
            <td className="mono">{h.last_event ? fmtTime(h.last_event) : 'No activity'}</td>
            <td>{h.alert_id
              ? <button className="btn stack sm" onClick={(e) => { e.stopPropagation(); navigate(`/alerts/${h.alert_id}`) }}>Alert created</button>
              : <span className="mut">—</span>}</td>
          </tr>
        ))}
      </tbody>
    </table></div>
  )
}
