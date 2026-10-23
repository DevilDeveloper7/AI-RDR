// Freeze -> Verify -> Kill/Isolate workflow, or Thaw for a false positive.
export default function Steps({ alert }) {
  const labels = ['Freeze', 'Verify', 'Kill / Isolate']
  const cur = alert.response_state === 'Isolated' ? 3 : alert.response_state === 'Thawed' ? -1 : 1
  return (
    <div className="steps">
      {labels.map((s, i) => {
        const cls = cur === -1 ? (i < 2 ? 'done' : '') : i < cur ? 'done' : i === cur ? 'cur' : ''
        return <span key={s} className={cls}>{s}</span>
      })}
      {alert.response_state === 'Thawed' && <span className="cur">Thaw</span>}
    </div>
  )
}
