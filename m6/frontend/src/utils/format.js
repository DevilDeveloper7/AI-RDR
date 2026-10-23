const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
// Timestamps are ISO strings in UTC ("2026-09-29T09:41:15Z"); they are sliced, not converted, so every analyst sees the same time.
export const fmtTime = (iso) => (iso ? iso.slice(11, 19) : '—')
export const fmtDate = (iso) => `${Number(iso.slice(8, 10))} ${MONTHS[Number(iso.slice(5, 7)) - 1]}`
export const fmtDateTime = (iso) => `${fmtDate(iso)} ${fmtTime(iso)}`
// Long hex digests (any length from 32 characters up) are shortened to "9f2c…e41a"; everything else is shown as is.
export const shortHash = (v) => (/^[0-9a-f]{32,}$/i.test(v) ? `${v.slice(0, 4)}…${v.slice(-4)}` : v)
