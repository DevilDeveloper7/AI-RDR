import { ResponseBadge, SeverityBadge, StatusBadge } from './Badge.jsx'
import Icon from './Icon.jsx'
import Steps from './Steps.jsx'
import { fmtDateTime } from '../utils/format.js'

// Slide-over shown when a row is selected on the Alerts page.
export default function AlertSummaryPanel({ alert, onClose, onOpenDetail, onAcknowledge }) {
  return (
    <aside id="panel" className={alert ? 'on' : undefined} aria-label="Alert summary" aria-hidden={!alert}>
      {alert && (
        <>
          <div className="top">
            <b>Alert {alert.id}</b><SeverityBadge severity={alert.severity} />
            <button className="btn sm" aria-label="Close" onClick={onClose}><Icon name="x" /></button>
          </div>
          <div className="sec">
            <dl style={{ gridTemplateColumns: '110px 1fr' }}>
              <dt>Detection</dt><dd>{alert.detection_type}</dd>
              <dt>Host</dt><dd>{alert.host}</dd>
              <dt>Process</dt><dd className="mono">{alert.process}</dd>
              <dt>Timestamp</dt><dd className="mono">{fmtDateTime(alert.timestamp)}</dd>
              <dt>Response</dt><dd><ResponseBadge alert={alert} /></dd>
              <dt>Status</dt><dd><StatusBadge status={alert.status} /></dd>
            </dl>
          </div>
          <div className="sec"><h4>Response workflow</h4><Steps alert={alert} /></div>
          <div className="sec acts">
            <button className="btn p" onClick={onOpenDetail}>Open Alert Detail</button>
            <button className="btn" disabled={alert.status !== 'Open'} onClick={onAcknowledge}>{alert.status === 'Open' ? 'Acknowledge' : 'Acknowledged'}</button>
          </div>
        </>
      )}
    </aside>
  )
}
