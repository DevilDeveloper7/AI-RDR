import Icon from './Icon.jsx'

export const RANGES = [[60, 'Last hour'], [360, 'Last 6 hours'], [1440, 'Last 24 hours'], [10080, 'Last 7 days']]

function Select({ label, all, value, onChange, options }) {
  return (
    <select aria-label={label} value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="">{all}</option>
      {value && !options.some((o) => (Array.isArray(o) ? String(o[0]) : o) === value) && <option>{value}</option>}
      {options.map((o) => (Array.isArray(o) ? <option key={o[0]} value={o[0]}>{o[1]}</option> : <option key={o}>{o}</option>))}
    </select>
  )
}

export default function FilterBar({ filters, facets, onChange, onReset }) {
  const set = (k) => (v) => onChange({ ...filters, [k]: v })
  return (
    <div className="filters" role="search">
      <label className="search">
        <Icon name="search" />
        <input aria-label="Search alerts" placeholder="Search by alert ID, host or process" value={filters.q} onChange={(e) => set('q')(e.target.value)} />
      </label>
      <Select label="Severity" all="All severities" value={filters.severity} onChange={set('severity')} options={facets.severities} />
      <Select label="Detection type" all="All detection types" value={filters.detection_type} onChange={set('detection_type')} options={facets.detection_types} />
      <Select label="Response state" all="All response states" value={filters.response_state} onChange={set('response_state')} options={facets.response_states} />
      <Select label="Host" all="All hosts" value={filters.host} onChange={set('host')} options={facets.hosts} />
      <Select label="Time range" all="All time" value={filters.range_minutes} onChange={set('range_minutes')} options={RANGES} />
      <button className="link" onClick={onReset}>Reset</button>
    </div>
  )
}
