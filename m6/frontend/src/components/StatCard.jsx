import { Link } from 'react-router-dom'

// Pass `to` to make the whole card a link (a real anchor: keyboard focusable, Enter activates it).
export default function StatCard({ label, value, crit, to }) {
  const className = `card stat${crit ? ' crit' : ''}${to ? ' stat-link' : ''}`
  const body = (<><small>{label}</small><b>{value}</b></>)
  return to ? <Link to={to} className={className}>{body}</Link> : <div className={className}>{body}</div>
}
