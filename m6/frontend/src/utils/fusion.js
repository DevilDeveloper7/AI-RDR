// Signals that support an alert, built only from data the API already returns:
// the alert itself (detection type, ML confidence, indicators), the honey-file list and the threat-intelligence list.
const KIND = { 'IP address': 'IP address', 'SHA-256': 'file hash', Domain: 'domain' }

export function fusionSignals(alert, honeyItems = [], intelItems = []) {
  const out = []
  if (alert.detection_type === 'Honey-File Trigger') out.push('Honey-file interaction')
  else {
    const trig = honeyItems.find((h) => h.host === alert.host && h.status === 'Triggered')
    if (trig) out.push(`Honey-file interaction on this host (${trig.file})`)
  }
  if (alert.detection_type === 'ML Behavioural Detection') out.push('Suspicious process behaviour')
  if (alert.confidence != null) out.push(`ML probability ${alert.confidence.toFixed(2)}`)
  for (const value of alert.indicators || []) {
    const hit = intelItems.find((t) => t.indicator === value)
    if (hit && ['Malicious', 'Suspicious'].includes(hit.reputation)) {
      out.push(`Matching ${hit.reputation.toLowerCase()} ${KIND[hit.type] || hit.type.toLowerCase()}`)
    }
  }
  return out
}
