// Loading / error / empty states, in the existing card language (no separate error screens).
export default function StateMessage({ loading, error, empty, onRetry }) {
  return (
    <div className="card">
      <div className="pad mut">
        {loading ? 'Loading…' : error ? (
          <>{error.message}{error.retryable && onRetry && <> <button className="link" onClick={onRetry}>Retry</button></>}</>
        ) : empty}
      </div>
    </div>
  )
}
