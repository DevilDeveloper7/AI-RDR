// The only place the frontend talks to the network. Pages never call fetch() directly.
const BASE = (import.meta.env.VITE_API_BASE_URL || '/api/v1').replace(/\/$/, '')

export class ApiError extends Error {
  constructor(message, { status = null, code = 'ERROR' } = {}) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }

  // Retrying only makes sense for network, timeout, malformed or server-side failures.
  get retryable() {
    return ['NETWORK_ERROR', 'TIMEOUT', 'MALFORMED_RESPONSE'].includes(this.code) || (this.status !== null && this.status >= 500)
  }
}

async function request(path, { method = 'GET', body, timeoutMs = 8000 } = {}) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const res = await fetch(BASE + path, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    })
    let data = null
    try { data = await res.json() } catch { /* handled below */ }
    if (!res.ok) {
      throw new ApiError(data?.error?.message || `Request failed (${res.status})`, {
        status: res.status,
        code: data?.error?.code || 'HTTP_ERROR',
      })
    }
    if (data === null) throw new ApiError('Malformed response from server', { status: res.status, code: 'MALFORMED_RESPONSE' })
    return data
  } catch (err) {
    if (err instanceof ApiError) throw err
    if (err.name === 'AbortError') throw new ApiError('Request timed out', { code: 'TIMEOUT' })
    throw new ApiError('API unreachable', { code: 'NETWORK_ERROR' })
  } finally {
    clearTimeout(timer)
  }
}

const qs = (o) => {
  const p = new URLSearchParams()
  Object.entries(o || {}).forEach(([k, v]) => { if (v !== '' && v != null) p.set(k, v) })
  const s = p.toString()
  return s ? `?${s}` : ''
}
const e = encodeURIComponent

export const api = {
  get: (path) => request(path),
  post: (path, body) => request(path, { method: 'POST', body }),
  getHealth: () => request('/health'), // used by tests/dev checks; not shown in the UI
}

// M6 endpoints used by the UI. Every page goes through these functions.
export const m6 = {
  alerts: (params) => api.get('/alerts' + qs(params)),
  alert: (id) => api.get(`/alerts/${e(id)}`),
  shap: (id) => api.get(`/alerts/${e(id)}/shap`),
  acknowledge: (id) => api.post(`/alerts/${e(id)}/acknowledge`, {}),
  override: (id, reason) => api.post(`/alerts/${e(id)}/override`, { reason }),
  action: (id, action, reason) => api.post(`/alerts/${e(id)}/action`, { action, reason }),
  activity: (limit) => api.get('/response-activity' + qs({ limit })),
  honeyFiles: () => api.get('/honey-files'),
  intel: (params) => api.get('/threat-intelligence' + qs(params)),
  intelDetail: (indicator) => api.get(`/threat-intelligence/${e(indicator)}`),
  integrations: () => api.get('/integrations/status'),
  checkIntegration: (module) => api.post('/integrations/check', { module }),
}
