import { fmtTime } from '../utils/format.js'

export default function Timeline({ items }) {
  return (
    <ul className="tl">
      {items.map((t, i) => (
        <li key={i} className={t.pending ? 'pend' : t.hot ? 'hot' : undefined}>
          <time className="mono">{fmtTime(t.timestamp)}</time>
          <span className={t.pending ? 'mut' : undefined}>{t.event}</span>
        </li>
      ))}
    </ul>
  )
}
