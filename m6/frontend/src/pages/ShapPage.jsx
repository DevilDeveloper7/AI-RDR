import { useNavigate, useParams } from 'react-router-dom'
import { SeverityBadge } from '../components/Badge.jsx'
import PageHeader from '../components/PageHeader.jsx'
import StateMessage from '../components/StateMessage.jsx'
import { useApi } from '../hooks/useApi.js'
import { m6 } from '../services/api.js'
import { fmtTime } from '../utils/format.js'

export default function ShapPage() {
  const { alertId } = useParams()
  const navigate = useNavigate()
  const { data: s, error, loading, reload } = useApi(() => m6.shap(alertId), [alertId])
  const back = { label: `Alert ${alertId}`, onClick: () => navigate(`/alerts/${alertId}`) }
  if (!s) {
    const missing = error && ['SHAP_NOT_AVAILABLE', 'SHAP_NOT_APPLICABLE'].includes(error.code)
    return (
      <section className="screen">
        <PageHeader title="Detection Explanation" sub={`SHAP explanation for ${alertId}`} back={back} />
        <StateMessage loading={loading} error={error} onRetry={missing ? undefined : reload} />
      </section>
    )
  }
  const max = Math.max(0.5, ...s.features.map((f) => Math.abs(f.value)))
  return (
    <section className="screen">
      <PageHeader title="Detection Explanation" sub={`SHAP explanation for ${s.alert_id} · ${s.host}`} back={back} />
      <div className="grid">
        <div className="card c8" style={{ alignSelf: 'start' }}>
          <h3 className="rule">Feature contributions<span>SHAP value · impact on model output</span></h3>
          <div className="pad" style={{ paddingTop: 12 }}>
            {s.features.map((f) => (
              <div className="bar" key={f.feature}>
                <span className="mono">{f.feature}</span>
                <div className="t">
                  <span className="axis" />
                  <i style={{ [f.value > 0 ? 'left' : 'right']: '50%', width: `${(Math.abs(f.value) / max) * 50}%`, background: f.value > 0 ? 'var(--primary-red)' : '#6B7280' }} />
                </div>
                <b className="mono">{f.value > 0 ? '+' : '−'}{Math.abs(f.value).toFixed(2)}</b>
              </div>
            ))}
            <p className="mut" style={{ margin: '14px 0 0', fontSize: 12 }}>
              <span className="lg"><i style={{ background: 'var(--primary-red)' }} />Increases likelihood</span>
              <span className="lg"><i style={{ background: '#6B7280' }} />Reduces likelihood</span>
            </p>
          </div>
          <div className="sec"><h4>Explanation</h4><p>{s.summary}</p></div>
        </div>
        <div className="c4 col">
          <div className="card"><h3 className="rule">Model output</h3>
            <div className="pad" style={{ paddingTop: 18 }}><span className="mut">Ransomware likelihood</span><b style={{ display: 'block', fontSize: 34, lineHeight: 1.2, color: 'var(--primary-red)' }}>{Math.round(s.ransomware_likelihood * 100)}%</b></div>
          </div>
          <div className="card"><h3 className="rule">Details</h3><div className="pad" style={{ paddingTop: 20 }}>
            <dl style={{ gridTemplateColumns: '100px 1fr' }}>
              <dt>Model</dt><dd>{s.model}</dd>
              <dt>Alert ID</dt><dd className="mono">{s.alert_id}</dd>
              <dt>Severity</dt><dd><SeverityBadge severity={s.severity} /></dd>
              <dt>Explained at</dt><dd className="mono">{fmtTime(s.explained_at)}</dd>
              <dt>Top feature</dt><dd className="mono">{[...s.features].sort((a, b) => b.value - a.value)[0].feature}</dd>
            </dl>
          </div></div>
        </div>
      </div>
    </section>
  )
}
