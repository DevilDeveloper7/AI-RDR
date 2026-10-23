// Navigation items (icon-only floating nav; the label becomes the accessible name) and page routes.
export const NAV = [
  { key: 'dashboard', label: 'Dashboard', to: '/', icon: 'home' },
  { key: 'alerts', label: 'Alerts', to: '/alerts', icon: 'bell' },
  { key: 'honey-files', label: 'Honey Files', to: '/honey-files', icon: 'file' },
  { key: 'threat-intelligence', label: 'Threat Intelligence', to: '/threat-intelligence', icon: 'shieldcheck' },
  { key: 'integrations', label: 'Integrations', to: '/integrations', icon: 'grid' },
]

export const ROUTES = [
  { path: '/', nav: 'dashboard', title: 'Dashboard' },
  { path: '/alerts', nav: 'alerts', title: 'Alerts' },
  { path: '/alerts/:alertId', nav: 'alerts', title: 'Alerts' },
  { path: '/alerts/:alertId/shap', nav: 'alerts', title: 'Alerts' },
  { path: '/alerts/:alertId/action', nav: 'alerts', title: 'Alerts' },
  { path: '/honey-files', nav: 'honey-files', title: 'Honey Files' },
  { path: '/threat-intelligence', nav: 'threat-intelligence', title: 'Threat Intelligence' },
  { path: '/integrations', nav: 'integrations', title: 'Integrations' },
  { path: '/profile', nav: 'profile', title: 'Analyst Profile and Settings' },
]
