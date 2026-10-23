import { useSyncExternalStore } from 'react'
import { ANALYST, PROFILE } from '../config.js'

// Analyst preferences. They live only in this browser (localStorage); there is no profile API.
const KEY = 'ai-rdr-m6.prefs'
export const DEFAULT_PREFS = {
  fullName: PROFILE.fullName, role: PROFILE.role, email: PROFILE.email,
  dark: false, compact: true, notifyCritical: true, notifyHoney: true, digest: false,
}

function read() {
  try { return { ...DEFAULT_PREFS, ...JSON.parse(localStorage.getItem(KEY) || '{}') } } catch { return { ...DEFAULT_PREFS } }
}
let current = read()
const listeners = new Set()

// Applies the appearance preferences to <html>. Called once at start-up and after every change.
export function applyPrefs(p = current) {
  const root = document.documentElement
  root.dataset.theme = p.dark ? 'dark' : 'light'
  root.dataset.density = p.compact ? 'compact' : 'comfortable'
}

export const getPrefs = () => current
export function setPrefs(patch) {
  current = { ...current, ...patch }
  try { localStorage.setItem(KEY, JSON.stringify(current)) } catch { /* storage unavailable: keep the in-memory value */ }
  applyPrefs(current)
  listeners.forEach((l) => l())
}
const subscribe = (l) => { listeners.add(l); return () => listeners.delete(l) }
export const usePrefs = () => useSyncExternalStore(subscribe, getPrefs)

// "Muhammad Alam Bharmar" -> "Muhammad Alam" (the heading shows the first two names).
export const displayName = (full) => (full || ANALYST.name).trim().split(/\s+/).slice(0, 2).join(' ')
export const initialOf = (full) => (full || ANALYST.name).trim().charAt(0).toUpperCase()
