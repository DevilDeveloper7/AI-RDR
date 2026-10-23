import { IntegrationBadge } from '../components/Badge.jsx'
import PageHeader from '../components/PageHeader.jsx'
import StateMessage from '../components/StateMessage.jsx'
import { useToast } from '../components/Toast.jsx'
import { useApi } from '../hooks/useApi.js'
import { m6 } from '../services/api.js'
import { fmtTime } from '../utils/format.js'

export default function IntegrationsPage() {
  const toast = useToast()
  const { data, error, loading, reload } = useApi(() => m6.integrations(), [])
  const check = async (module, message) => {
    try { await m6.checkIntegration(module); toast(message); reload() } catch (e) { toast(e.message) }
  }
  const runAll = <button className="btn pill" onClick={() => check(null, 'All contract checks complete')}>Run all checks</button>
  const head = <PageHeader title="Integration Status" sub="Interface contracts between modules">{data && runAll}</PageHeader>
  if (!data) return <section className="screen">{head}<StateMessage loading={loading} error={error} onRetry={reload} /></section>
  return (
    <section className="screen">
      {head}
      <div className="grid">
        <div className="card c12"><h3 className="rule">Components</h3>
          <div className="tw"><table>
            <thead><tr><th>Component</th><th>Interface</th><th>Endpoint</th><th>Status</th><th>Last check</th><th /></tr></thead>
            <tbody>
              {data.components.map((r) => (
                <tr key={r.module}>
                  <td className="nowrap"><b>{r.module}</b> <span className="mut">{r.name}</span></td>
                  <td>{r.interface}{r.mode === 'mock' && <span className="sub" style={{ fontFamily: 'inherit', fontSize: 12 }}>Mock · provisional</span>}</td>
                  <td className="mono">{r.endpoint}</td>
                  <td><IntegrationBadge status={r.status} /></td><td className="mono">{fmtTime(r.last_check)}</td>
                  <td>{r.module !== 'M6' && <button className="btn" onClick={() => check(r.module.toLowerCase(), `${r.module} check complete`)}>Check</button>}</td>
                </tr>
              ))}
            </tbody>
          </table></div>
        </div>
        <div className="card c12"><h3 className="rule">Integration test<span>Last run {fmtTime([...data.recent_tests].map((t) => t.timestamp).sort().pop())}</span></h3>
          <div className="tw"><table><tbody>
            {data.recent_tests.map((t) => (<tr key={t.path}><td><b>{t.path}</b></td><td>{t.contract}</td><td>{t.result}</td><td className="mono mut">{fmtTime(t.timestamp)}</td></tr>))}
          </tbody></table></div>
        </div>
      </div>
    </section>
  )
}
