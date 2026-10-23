import { useLocation, useNavigate, useParams } from 'react-router-dom'
import { ResponseBadge, SeverityBadge, StatusBadge } from '../components/Badge.jsx'
import Icon from '../components/Icon.jsx'
import PageHeader from '../components/PageHeader.jsx'
import StateMessage from '../components/StateMessage.jsx'
import Steps from '../components/Steps.jsx'
import Timeline from '../components/Timeline.jsx'
import { useToast } from '../components/Toast.jsx'
import { useApi } from '../hooks/useApi.js'
import { m6 } from '../services/api.js'
import { fmtTime } from '../utils/format.js'
import { fusionSignals } from '../utils/fusion.js'

const NEXT_STEP = {
  Frozen: 'The process is frozen while verification runs. Acknowledge to confirm you have seen this alert, or override the response if it is a false positive.',
  Isolated: 'The host has been isolated from the network. Acknowledge to confirm you have seen this alert.',
  Thawed: 'The process was released as a false positive. Acknowledge to confirm you have seen this alert.',
}

export default function AlertDetailPage() {
  const { alertId } = useParams()
  const navigate = useNavigate()
  const toast = useToast()
  const fromAlerts = useLocation().state?.from === 'alerts'
  const { data: a, error, loading, reload } = useApi(() => m6.alert(alertId), [alertId])
  // Supporting signals come from endpoints the app already uses; if either is unavailable the list simply has fewer entries.
  const honey = useApi(() => m6.honeyFiles(), [])
  const intel = useApi(() => m6.intel(), [])
  const back = { label: fromAlerts ? 'Alerts' : 'Dashboard', onClick: () => navigate(fromAlerts ? '/alerts' : '/') }
  if (!a) return <section className="screen"><PageHeader title={`Alert ${alertId}`} back={back} /><StateMessage loading={loading} error={error} onRetry={reload} /></section>

  const ml = a.detection_type === 'ML Behavioural Detection'
  const signals = fusionSignals(a, honey.data?.items, intel.data?.items)
  const acknowledge = async () => {
    try {
      const res = await m6.acknowledge(a.id)
      toast(`${a.id} acknowledged by ${res.acknowledged_by}`)
      reload()
    } catch (e) { toast(e.message) }
  }
  return (
    <section className="screen">
      <PageHeader title={`Alert ${a.id}`} sub={`${a.detection_type} · ${a.host}`} back={back} />
      <div className="grid">
        <div className="card c8" style={{ alignSelf: 'start' }}>
          <div className="sec"><dl>
            <dt>Severity</dt><dd><SeverityBadge severity={a.severity} /></dd>
            <dt>Detection method</dt><dd>{a.detection_type}</dd>
            <dt>Timestamp</dt><dd className="mono">{a.timestamp.slice(0, 10)} {fmtTime(a.timestamp)}</dd>
            <dt>Affected host</dt><dd>{a.host}</dd>
            <dt>Process</dt><dd className="mono">{a.process}</dd>
            <dt>Status</dt><dd><StatusBadge status={a.status} /></dd>
          </dl></div>
          <div className="sec"><h4>Detection explanation</h4><p>{a.summary}</p></div>
          <div className="sec"><h4>Evidence</h4><dl className="evid">
            {a.evidence.map((e) => (<div key={e.label} style={{ display: 'contents' }}><dt>{e.label}</dt><dd>{e.value}</dd></div>))}
          </dl></div>
          <div className="sec"><h4>Timeline</h4><Timeline items={a.timeline} /></div>
        </div>
        <div className="c4 col">
          <div className="card">
            <h3>Risk Fusion Detection</h3>
            <div className="pad" style={{ paddingTop: 0, paddingBottom: a.confidence != null ? 18 : 22 }}>
              {signals.length > 0
                ? <ul className="signals">{signals.map((s) => <li key={s}>{s}</li>)}</ul>
                : <span className="mut">No supporting signals are available for this alert.</span>}
              {signals.length >= 3 && <p className="fusion-note">Multiple independent signals support this detection.</p>}
            </div>
            {a.confidence != null && (
              <div className="risk" role="group" aria-label="ML confidence">
                <div className="row"><span className="tag crit">ML confidence</span><span className="big">{Math.round(a.confidence * 100)}%</span></div>
                <div className="track"><i style={{ width: `${Math.round(a.confidence * 100)}%` }} /></div>
              </div>
            )}
          </div>
          <div className="card"><h3 className="rule">Response status</h3><div className="pad" style={{ paddingTop: 18 }}>
            <ResponseBadge alert={a} />
            <p className="mut" style={{ margin: '12px 0', lineHeight: 1.5 }}>Workflow: Freeze → Verify → Kill/Isolate, or Thaw if false positive.</p>
            <Steps alert={a} />
          </div></div>
          <div className="card"><h3 className="rule">Actions</h3>
            <p className="actcopy" style={{ paddingTop: 18 }}>{NEXT_STEP[a.response_state] || NEXT_STEP.Frozen}</p>
            <hr className="hr" />
            <div className="acts acts-row">
              <button className="btn p" disabled={a.status !== 'Open'} onClick={acknowledge}><Icon name="check" />{a.status === 'Open' ? 'Acknowledge' : 'Acknowledged'}</button>
              <button className="btn" onClick={() => (ml ? navigate(`/alerts/${a.id}/shap`) : toast('SHAP applies to ML detections only'))}><Icon name="chart" />View SHAP explanation</button>
              <button className="btn d" onClick={() => navigate(`/alerts/${a.id}/action`)}>Override response…</button>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
