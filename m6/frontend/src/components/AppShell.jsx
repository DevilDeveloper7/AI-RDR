import { useEffect } from 'react'
import { Link, Outlet, matchPath, useLocation } from 'react-router-dom'
import Sidebar from './Sidebar.jsx'
import { useApi } from '../hooks/useApi.js'
import { m6 } from '../services/api.js'
import { ROUTES } from '../routes.js'
import logoSymbol from '../assets/brand/ai-rdr-symbol.svg'

export default function AppShell() {
  const { pathname } = useLocation()
  const route = ROUTES.find((r) => matchPath({ path: r.path, end: true }, pathname)) || ROUTES[0]
  // Integration status API: the Integrations icon only mentions "all core services online" when every module reports Connected.
  const integrations = useApi(() => m6.integrations(), [])
  const allConnected = !!integrations.data && integrations.data.components.every((c) => c.status === 'Connected')
  useEffect(() => { document.documentElement.scrollTop = 0 }, [pathname])

  return (
    <>
      <Link to="/" className="logo" aria-label="AI-RDR dashboard"><img src={logoSymbol} alt="AI-RDR" /></Link>
      <Sidebar activeKey={route.nav} allConnected={allConnected} />
      <main>
        <Outlet />
      </main>
    </>
  )
}
