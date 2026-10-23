export default function Pagination({ page, pages, info, onPage }) {
  return (
    <div className="pg">
      <span>{info}</span>
      <div className="acts">
        <button className="btn" disabled={page === 1} onClick={() => onPage(page - 1)}>Previous</button>
        {Array.from({ length: pages }, (_, i) => i + 1).map((n) => (
          <button key={n} className={`btn${n === page ? ' p' : ''}`} aria-current={n === page ? 'page' : undefined} onClick={() => onPage(n)}>{n}</button>
        ))}
        <button className="btn" disabled={page === pages} onClick={() => onPage(page + 1)}>Next</button>
      </div>
    </div>
  )
}
