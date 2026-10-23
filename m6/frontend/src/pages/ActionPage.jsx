import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { ResponseBadge, SeverityBadge } from '../components/Badge.jsx'
import Modal from '../components/Modal.jsx'
import PageHeader from '../components/PageHeader.jsx'
import StateMessage from '../components/StateMessage.jsx'
import Steps from '../components/Steps.jsx'
import { useToast } from '../components/Toast.jsx'
import { useApi } from '../hooks/useApi.js'
import { m6 } from '../services/api.js'

export default function ActionPage() {
  const { alertId } = useParams()
  const navigate = useNavigate()
  const toast = useToast()
  const { data: a, error, loading, reload } = useApi(() => m6.alert(alertId), [alertId])
  const [reason, setReason] = useState('')
  const [confirmed, setConfirmed] = useState(false)
  const [modal, setModal] = useState(null) // 'override' | 'isolate' | null
  const back = { label: `Alert ${alertId}`, onClick: () => navigate(`/alerts/${alertId}`) }
  if (!a) return <section className="screen"><PageHeader title="Response Actions" sub="Acknowledge or override the automatic response" back={back} /><StateMessage loading={loading} error={error} onRetry={reload} /></section>

  const final = a.response_state !== 'Frozen'
  const run = async (fn, okMessage) => {
    try { await fn(); toast(okMessage); setModal(null); reload() } catch (e) { setModal(null); toast(e.message) }
  }
  const acknowledge = () => run(() => m6.acknowledge(a.id), `${a.id} acknowledged`)
  return (
    <section className="screen">
      <PageHeader title="Response Actions" sub="Acknowledge or override the automatic response" back={back} />
      <div className="grid">
        <div className="card c5" style={{ alignSelf: 'start' }}><h3 className="rule">Alert summary</h3><div className="pad" style={{ paddingTop: 20 }}>
          <dl style={{ gridTemplateColumns: '140px 1fr' }}>
            <dt>Alert</dt><dd className="mono">{a.id}</dd>
            <dt>Severity</dt><dd><SeverityBadge severity={a.severity} /></dd>
            <dt>Host</dt><dd>{a.host}</dd>
            <dt>Process</dt><dd className="mono">{a.process}</dd>
            <dt>Automatic action</dt><dd><b>{a.response_state === 'Frozen' ? 'Process frozen' : a.response_state}</b></dd>
            <dt>Current state</dt><dd>{a.response_state === 'Frozen' ? 'Verification in progress' : a.verification_state}</dd>
          </dl>
          <div style={{ marginTop: 18 }}><Steps alert={a} /></div>
        </div></div>
        <div className="c7 col">
          <div className="plain"><b>Acknowledge</b>
            <span className="mut">Confirms you have seen this alert. The automatic response continues unchanged.</span>
            <div><button className="btn p" disabled={a.status !== 'Open'} onClick={acknowledge}>{a.status === 'Open' ? 'Acknowledge alert' : 'Acknowledged'}</button></div>
          </div>
          <div className="opt dz"><b>Override automatic response</b>
            <dl style={{ gridTemplateColumns: '140px 1fr' }}>
              <dt>Current action</dt><dd>{a.response_state}</dd>
              <dt>Proposed action</dt><dd>Thaw (release process, treat as false positive)</dd>
            </dl>
            <label htmlFor="why" className="mut" style={{ marginTop: 4 }}>Reason (required)</label>
            <textarea id="why" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. Scheduled backup job, verified with host owner" />
            <label className="mut"><input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} /> I confirm I am authorised to override this response.</label>
            <div className="acts">
              <button className="btn d" disabled={!confirmed || reason.trim().length < 3 || final} onClick={() => setModal('override')}>Override…</button>
              <span className="sep" />
              <button className="btn" disabled={final} onClick={() => setModal('isolate')}>Confirm Kill / Isolate</button>
            </div>
            {final && <span className="mut">Response is final for this alert.</span>}
          </div>
        </div>
      </div>
      <Modal open={modal === 'override'} title="Override automatic response?" onClose={() => setModal(null)}>
        <p className="mut">Continuing may allow the detected process ({a.process}) on {a.host} to resume. The current action, <b>{a.response_state}</b>, will be replaced with <b>Thaw</b>. This is recorded against your account.</p>
        <div className="acts"><button className="btn" onClick={() => setModal(null)}>Cancel</button>
          <button className="btn p" onClick={() => run(() => m6.override(a.id, reason.trim()), `Override applied: ${a.host} process thawed`)}>Confirm Override</button></div>
      </Modal>
      <Modal open={modal === 'isolate'} title="Confirm Kill and Isolate?" onClose={() => setModal(null)}>
        <p className="mut">Verification will be treated as confirmed. The process is killed and {a.host} is isolated from the network.</p>
        <div className="acts"><button className="btn" onClick={() => setModal(null)}>Cancel</button>
          <button className="btn p" onClick={() => run(() => m6.action(a.id, 'isolate'), `${a.host} isolated`)}>Confirm Kill / Isolate</button></div>
      </Modal>
    </section>
  )
}
