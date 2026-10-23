// Read-only UI checks against the live Flask API (mock data). Start the backend first: python backend/run.py
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App.jsx'
import { DEFAULT_PREFS, setPrefs } from './utils/prefs.js'

afterEach(() => { cleanup(); vi.restoreAllMocks() })
const open = (path) => render(<MemoryRouter initialEntries={[path]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}><App /></MemoryRouter>)
const see = (text) => waitFor(() => expect(screen.getAllByText(text).length).toBeGreaterThan(0), { timeout: 4000 })

describe('M6 screens render from the Flask API', () => {
  it('Dashboard: stats, live feed, honey files, threat intel, activity', async () => {
    open('/')
    await see('Live Alert Feed'); await see('A-2041'); await see('Monitored honey files'); await see('D3'); await see('TRIGGERED')
    await waitFor(() => expect(screen.getByText('Critical Alerts').nextSibling.textContent).toBe('2'))
    expect(screen.getByText('Recent Response Activity')).toBeTruthy()
    await see('Analyst override')
    expect(screen.getAllByRole('row').length).toBeGreaterThan(8)
  })
  it('Dashboard row opens Alert Detail; SHAP and Action are reachable from it', async () => {
    open('/')
    await see('Live Alert Feed')
    const row = (await screen.findAllByText('A-2041'))[0].closest('tr')
    fireEvent.click(row)
    await see('Alert A-2041'); await see('Detection explanation'); await see('Timeline')
    fireEvent.click(screen.getByText('View SHAP explanation'))
    await see('Detection Explanation'); await see('94%'); await see('write_rate')
    fireEvent.click(screen.getByText('Alert A-2041'))
    await see('Detection explanation')
    fireEvent.click(screen.getByText('Override response…'))
    await see('Override automatic response'); await see('Process frozen')
  })
  it('Alerts: full feed, filter, slide-over, open detail', async () => {
    open('/alerts')
    await see('Showing 1–20 of 80')
    fireEvent.change(screen.getByLabelText('Severity'), { target: { value: 'Critical' } })
    await waitFor(() => expect(screen.queryByText('Showing 1–20 of 80')).toBeNull())
    fireEvent.change(screen.getByLabelText('Severity'), { target: { value: '' } })
    await see('Showing 1–20 of 80')
    fireEvent.click((await screen.findAllByText('A-2041'))[0].closest('tr'))
    await see('Open Alert Detail')
    fireEvent.click(screen.getByText('Open Alert Detail'))
    await see('Detection explanation')
  })
  it('Honey Files, Threat Intelligence and Integration Status are not blank', async () => {
    open('/honey-files'); await see('budget_report.docx'); await see('TRIGGERED'); cleanup()
    open('/threat-intelligence'); await see('185.220.101.47'); await see('Indicator detail'); cleanup()
    open('/integrations'); await see('Telemetry contract'); await see('Run all checks')
    expect(screen.getAllByText('Stubbed').length).toBe(5)
    expect(screen.getAllByText('Mock · provisional').length).toBe(5)
  })
  it('SHAP shows a calm message when no explanation exists', async () => {
    open('/alerts/A-2042/shap'); await see('SHAP applies to ML detections only. Honey-file alerts bypass the ML stage.')
  })
})

describe('Loading, empty and error states', () => {
  it('shows an understandable message when Flask is unavailable', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('Failed to fetch'))
    open('/integrations')
    await see('API unreachable')
    expect(screen.getByText('Retry')).toBeTruthy()
  })
  it('shows the server error message for a 500 without technical details', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: false, status: 500, json: async () => ({ error: { code: 'INTERNAL_ERROR', message: 'An internal error occurred.' } }),
    })
    open('/honey-files')
    await see('An internal error occurred.')
  })
  it('treats a non-JSON reply as a malformed response', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({ ok: true, status: 200, json: async () => { throw new Error('bad json') } })
    open('/threat-intelligence')
    await see('Malformed response from server')
  })
  it('shows a not-found message without a pointless Retry button', async () => {
    open('/alerts/A-9999')
    await see('Alert A-9999 was not found.')
    expect(screen.queryByText('Retry')).toBeNull()
  })
  it('rejects an invalid alert id with the API message', async () => {
    open('/alerts/not-an-id')
    await see('Alert ID must look like A-1234.')
  })
  it('shows the empty state when no alerts match the filters', async () => {
    open('/alerts')
    await see('Showing 1–20 of 80')
    fireEvent.change(screen.getByLabelText('Search alerts'), { target: { value: 'zzz-no-match' } })
    await see('No alerts match the current filters.')
    await see('0 results')
  })
  it('renders every screen without React console errors', async () => {
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {})
    for (const [path, text] of [['/', 'Live Alert Feed'], ['/alerts', 'All alerts'], ['/alerts/A-2041', 'Detection explanation'],
      ['/alerts/A-2041/shap', 'Feature contributions'], ['/alerts/A-2041/action', 'Acknowledge'], ['/honey-files', 'Monitored honey files'],
      ['/threat-intelligence', 'Indicators'], ['/integrations', 'Components'], ['/profile', 'Analyst Profile and Settings']]) {
      open(path); await see(text); cleanup()
    }
    expect(errors.mock.calls.map((c) => String(c[0]).slice(0, 120))).toEqual([])
  })
})

describe('Top bar, summary cards, status column and branding', () => {
  const textbox = () => screen.getByLabelText('Search all alerts')

  it('has no notification button; the analyst name is on the Profile page, opened from the nav avatar', async () => {
    open('/')
    await see('Live Alert Feed')
    expect(screen.queryByLabelText('Notifications')).toBeNull()
    expect(screen.queryByText('A. Khan')).toBeNull()
    expect(screen.getByLabelText('Profile and settings').getAttribute('href')).toBe('/profile')
    fireEvent.click(screen.getByLabelText('Profile and settings'))
    await see('Analyst Profile and Settings'); await see('Muhammad Alam')
  })

  it('top search runs against the alert API on Enter, can be cleared, and shares the Alerts filter', async () => {
    open('/')
    await see('Live Alert Feed')
    fireEvent.change(textbox(), { target: { value: 'enc_worker' } })
    fireEvent.keyDown(textbox(), { key: 'Enter' })
    await see('Showing 1–8 of 8')                      // enc_worker alerts only
    expect(screen.queryByText('A-2040')).toBeNull()
    expect(screen.getAllByText('A-2041').length).toBeGreaterThan(0)
    expect(screen.getByLabelText('Search alerts', { selector: '.filters input' }).value).toBe('enc_worker')
    fireEvent.click(screen.getByLabelText('Clear search'))
    await see('Showing 1–20 of 80')
    expect(textbox().value).toBe('')
  })

  it('top search keeps filters that are already applied and Escape clears it', async () => {
    open('/alerts?severity=Critical')
    await waitFor(() => expect(screen.getByText(/Showing 1–\d+ of \d+/)).toBeTruthy())
    fireEvent.change(textbox(), { target: { value: 'HOST-03' } })
    fireEvent.keyDown(textbox(), { key: 'Enter' })
    await waitFor(() => expect(screen.getByLabelText('Severity').value).toBe('Critical'))
    await see('Showing 1–8 of 8')                      // Critical AND HOST-03
    fireEvent.keyDown(textbox(), { key: 'Escape' })
    await waitFor(() => expect(textbox().value).toBe(''))
  })

  it('summary cards are links that open the matching filtered Alerts view', async () => {
    open('/')
    await see('Live Alert Feed')
    const card = (name) => screen.getByText(name).closest('a')
    expect(card('Active Alerts').getAttribute('href')).toBe('/alerts?response_state=Frozen')
    fireEvent.click(card('Critical Alerts'))
    await see('Showing 1–2 of 2')
    expect(screen.getByLabelText('Severity').value).toBe('Critical')
    expect(screen.getByLabelText('Response state').value).toBe('Frozen')
    cleanup()

    open('/')
    await see('Live Alert Feed')
    fireEvent.click(card('Active Alerts'))
    await see('Showing 1–3 of 3')
    expect(screen.getByLabelText('Response state').value).toBe('Frozen')
    cleanup()

    open('/')
    await see('Live Alert Feed')
    fireEvent.click(card('Systems Monitored'))
    await see('Monitored honey files')
  })

  it('status and action are separate table columns so rows line up', async () => {
    open('/alerts')
    await see('Showing 1–20 of 80')
    const row = screen.getAllByText('A-2041')[0].closest('tr')
    const cells = row.querySelectorAll('td')
    expect(cells.length).toBe(9)
    expect(cells[7].textContent).toBe('Open')
    expect(cells[8].textContent).toBe('Investigate')
  })

  it('shows the logo and a nav entry for every screen', async () => {
    open('/')
    await see('Live Alert Feed')
    const logo = document.querySelector('.logo img')
    expect(logo.getAttribute('src')).toMatch(/svg/)
    expect(logo.getAttribute('alt')).toBe('AI-RDR')
    const nav = screen.getByRole('navigation', { name: 'Primary' })
    expect(within(nav).getAllByRole('link').map((a) => a.getAttribute('aria-label'))).toEqual(
      ['Dashboard', 'Alerts', 'Honey Files', 'Threat Intelligence', 'Integrations', 'Profile and settings'])
    expect(within(nav).getByLabelText('Dashboard').getAttribute('aria-current')).toBe('page')
  })
})


describe('Redesign additions', () => {
  const textbox = () => screen.getByLabelText('Search all alerts')

  it('Alert Detail shows only supporting signals the API provides, and the model confidence', async () => {
    open('/alerts/A-2041')
    await see('Risk Fusion Detection'); await see('ML probability 0.94'); await see('Matching malicious file hash'); await see('Matching suspicious IP address')
    await see('Honey-file interaction on this host (budget_report.docx)')
    expect(screen.getByLabelText('ML confidence').textContent).toContain('94%')
  })

  it('Alert Detail for a honey-file alert has no ML confidence panel', async () => {
    open('/alerts/A-2042')
    await see('Risk Fusion Detection'); await see('Honey-file interaction')
    expect(screen.queryByLabelText('ML confidence')).toBeNull()
  })

  it('top search opens a threat-intelligence indicator when the text identifies one', async () => {
    open('/')
    await see('Live Alert Feed')
    fireEvent.change(textbox(), { target: { value: '185.220' } })
    fireEvent.keyDown(textbox(), { key: 'Enter' })
    await see('Indicator detail')
    await waitFor(() => expect(screen.getByText('Open alert A-2041')).toBeTruthy())
    expect(screen.getAllByText('185.220.101.47').length).toBeGreaterThan(0)
  })

  it('long hashes are shown shortened, like 9f2c…e41a', async () => {
    open('/threat-intelligence')
    await see('Indicator detail')
    expect(screen.getAllByText('9f2c…e41a').length).toBeGreaterThan(0)
  })

  it('Honey Files: decoy ids, alert buttons and row selection', async () => {
    open('/honey-files')
    await see('Decoy ID'); await see('D6')
    expect(screen.getAllByText('Alert created').length).toBe(2)
    fireEvent.click(screen.getByText('hr_records.docx').closest('tr'))
    await waitFor(() => expect(screen.getByText(/Selected:/)).toBeTruthy())
    expect(screen.getByText(/Selected:/).textContent).toContain('hr_records.docx on HOST-06')
  })

  it('Integrations: Check is offered for M1-M5 only, because the API rejects M6', async () => {
    open('/integrations')
    await see('Telemetry contract')
    expect(screen.getAllByText('Check').length).toBe(5)
  })

  it('Profile: appearance switches apply to the page and are remembered; profile edits are validated and saved', async () => {
    localStorage.clear()
    setPrefs(DEFAULT_PREFS) // start from the defaults; main.jsx applies saved preferences the same way at start-up
    open('/profile')
    await see('Analyst Profile and Settings')
    expect(screen.getByLabelText('Compact tables').getAttribute('aria-checked')).toBe('true')
    expect(document.documentElement.dataset.density).toBe('compact')
    fireEvent.click(screen.getByLabelText('Compact tables'))
    expect(document.documentElement.dataset.density).toBe('comfortable')
    fireEvent.click(screen.getByLabelText('Dark appearance'))
    expect(document.documentElement.dataset.theme).toBe('dark')
    expect(JSON.parse(localStorage.getItem('ai-rdr-m6.prefs')).dark).toBe(true)
    fireEvent.click(screen.getByLabelText('Dark appearance'))
    fireEvent.click(screen.getByLabelText('Compact tables'))

    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'not-an-email' } })
    fireEvent.click(screen.getByText('Save changes'))
    await see('Enter a valid email address')
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'analyst@example.com' } })
    fireEvent.change(screen.getByLabelText('Full name'), { target: { value: 'Priya Nair Shah' } })
    fireEvent.click(screen.getByText('Save changes'))
    await see('Profile saved in this browser')
    expect(screen.getByText('Priya Nair')).toBeTruthy()
    expect(screen.getByLabelText('Profile and settings').textContent).toBe('P')
    setPrefs(DEFAULT_PREFS)
    localStorage.clear()
  })

  it('Profile: Log Out is disabled because there is no session to end', async () => {
    open('/profile')
    await see('Account')
    expect(screen.getByText('Log Out').closest('button').disabled).toBe(true)
  })
})
