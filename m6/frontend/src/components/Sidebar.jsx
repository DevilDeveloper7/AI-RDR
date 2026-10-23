import { Link } from 'react-router-dom'
import Icon from './Icon.jsx'
import { NAV } from '../routes.js'
import { initialOf, usePrefs } from '../utils/prefs.js'

// Floating icon navigation. Labels are the accessible names and tooltips.
export default function Sidebar({ activeKey, allConnected }) {
  const prefs = usePrefs()
  return (
    <nav className="floatnav" aria-label="Primary">
      {NAV.map((n) => {
        const label = n.key === 'integrations' && allConnected ? 'Integrations · all core services online' : n.label
        return (
          <Link key={n.key} to={n.to} className={activeKey === n.key ? 'on' : undefined} aria-label={n.label} title={label}
                aria-current={activeKey === n.key ? 'page' : undefined}>
            <Icon name={n.icon} />
          </Link>
        )
      })}
      <Link to="/profile" className={`me${activeKey === 'profile' ? ' on' : ''}`} aria-label="Profile and settings" title="Profile and settings"
            aria-current={activeKey === 'profile' ? 'page' : undefined}>
        <span className="av">{initialOf(prefs.fullName)}</span>
      </Link>
    </nav>
  )
}
