import Icon from './Icon.jsx'

// Solid semantic badges from the approved design. The icon is chosen from the label.
const ICONS = { Critical: 'alert', High: 'alert', Medium: 'alert', TRIGGERED: 'alert', Malicious: 'alert', Warning: 'alert',
  Frozen: 'pause', Isolated: 'ban', Thawed: 'check', Running: 'check', Acknowledged: 'check', Connected: 'check', Clean: 'check',
  Suspicious: 'warn2', Unknown: 'help', Protected: 'shieldcheck', Open: 'clock', Stubbed: 'minus', Failed: 'xc' }

export function Badge({ tone, label }) {
  const key = Object.keys(ICONS).find((k) => label.startsWith(k))
  return <span className={`tag ${tone}`}>{key && <Icon name={ICONS[key]} />}{label}</span>
}

export const SeverityBadge = ({ severity }) => <Badge tone={{ Critical: 'crit', High: 'high', Medium: 'med' }[severity]} label={severity} />
export const responseLabel = (a) => (a.response_state === 'Frozen' && a.verification_state === 'Verifying' ? 'Frozen · verifying' : a.response_state)
export const ResponseBadge = ({ alert }) => <Badge tone={{ Frozen: 'high', Isolated: 'crit', Thawed: 'ok' }[alert.response_state]} label={responseLabel(alert)} />
export const StatusBadge = ({ status }) => <Badge tone={status === 'Open' ? 'gr' : 'ok'} label={status} />
export const ReputationBadge = ({ reputation }) => <Badge tone={{ Malicious: 'crit', Suspicious: 'high', Clean: 'ok', Unknown: 'gr' }[reputation]} label={reputation} />
export const HoneyBadge = ({ status }) => (status === 'Triggered' ? <Badge tone="crit" label="TRIGGERED" /> : <Badge tone="ok" label="Protected" />)
export const IntegrationBadge = ({ status }) => <Badge tone={{ Connected: 'ok', Stubbed: 'info', Warning: 'high', Failed: 'crit' }[status]} label={status} />
