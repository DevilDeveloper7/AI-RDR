import { Navigate, Route, Routes } from 'react-router-dom'
import AppShell from './components/AppShell.jsx'
import { ToastProvider } from './components/Toast.jsx'
import ActionPage from './pages/ActionPage.jsx'
import AlertDetailPage from './pages/AlertDetailPage.jsx'
import AlertsPage from './pages/AlertsPage.jsx'
import DashboardPage from './pages/DashboardPage.jsx'
import HoneyFilesPage from './pages/HoneyFilesPage.jsx'
import IntegrationsPage from './pages/IntegrationsPage.jsx'
import ProfilePage from './pages/ProfilePage.jsx'
import ShapPage from './pages/ShapPage.jsx'
import ThreatIntelPage from './pages/ThreatIntelPage.jsx'

export default function App() {
  return (
    <ToastProvider>
      <Routes>
        <Route element={<AppShell />}>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/alerts/:alertId" element={<AlertDetailPage />} />
          <Route path="/alerts/:alertId/shap" element={<ShapPage />} />
          <Route path="/alerts/:alertId/action" element={<ActionPage />} />
          <Route path="/honey-files" element={<HoneyFilesPage />} />
          <Route path="/threat-intelligence" element={<ThreatIntelPage />} />
          <Route path="/integrations" element={<IntegrationsPage />} />
          <Route path="/profile" element={<ProfilePage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </ToastProvider>
  )
}
