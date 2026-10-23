import { useState } from 'react'
import Icon from '../components/Icon.jsx'
import PageHeader from '../components/PageHeader.jsx'
import Toggle from '../components/Toggle.jsx'
import { useToast } from '../components/Toast.jsx'
import { PROFILE } from '../config.js'
import { displayName, initialOf, setPrefs, usePrefs } from '../utils/prefs.js'

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

// Analyst profile and settings. There is no profile or sign-in API, so this page keeps everything in the browser:
// appearance switches take effect immediately, profile fields are stored with "Save changes".
export default function ProfilePage() {
  const toast = useToast()
  const prefs = usePrefs()
  const [draft, setDraft] = useState({ fullName: prefs.fullName, role: prefs.role, email: prefs.email })
  const edit = (k) => (e) => setDraft((d) => ({ ...d, [k]: e.target.value }))

  const save = () => {
    const next = { fullName: draft.fullName.trim(), role: draft.role.trim(), email: draft.email.trim() }
    if (!next.fullName) return toast('Full name is required')
    if (!next.role) return toast('Role is required')
    if (!EMAIL.test(next.email)) return toast('Enter a valid email address')
    setPrefs(next)
    setDraft(next)
    toast('Profile saved in this browser')
  }
  const row = (label, control) => <div className="setrow"><span>{label}</span>{control}</div>
  const sw = (label, key) => row(label, <Toggle label={label} checked={prefs[key]} onChange={(v) => setPrefs({ [key]: v })} />)

  return (
    <section className="screen">
      <PageHeader title="Analyst Profile and Settings" sub="Manage your analyst profile and preferences" />
      <div className="profile-top">
        <div className="card idcard">
          <div className="big-av" aria-hidden="true">{initialOf(prefs.fullName)}</div>
          <h3>{displayName(prefs.fullName)}</h3>
          <span className="role">{prefs.role.replace(/ Tier (\d)/, ' · Tier $1')}</span>
          <dl>
            <dt>Last sign-in</dt><dd className="mono">{PROFILE.lastSignIn}</dd>
            <dt>Alerts handled</dt><dd>{PROFILE.alertsHandled}</dd>
          </dl>
        </div>
        <div className="card">
          <h3 className="rule" style={{ padding: '14px 18px 14px 22px' }}>Profile<span><button className="btn p" onClick={save}>Save changes</button></span></h3>
          <div className="pad" style={{ paddingTop: 18 }}>
            <div className="field"><label htmlFor="pf-name">Full name</label><input id="pf-name" value={draft.fullName} onChange={edit('fullName')} autoComplete="name" /></div>
            <div className="field"><label htmlFor="pf-role">Role</label><input id="pf-role" value={draft.role} onChange={edit('role')} /></div>
            <div className="field" style={{ marginBottom: 0 }}><label htmlFor="pf-email">Email</label><input id="pf-email" type="email" value={draft.email} onChange={edit('email')} autoComplete="email" /></div>
          </div>
        </div>
      </div>
      <div className="settings">
        <div className="card"><h3 className="rule">Account</h3>
          {row('Two-factor authentication', <span className="tag soft">{PROFILE.twoFactor}</span>)}
          {row('Session timeout', <span className="val">{PROFILE.sessionTimeout}</span>)}
          <div className="setrow" style={{ borderTop: '1px solid var(--hair)' }}>
            <button className="btn logout" disabled title="Sign-in is not part of this build, so there is no session to end"><Icon name="logout" />Log Out</button>
          </div>
        </div>
        <div className="card"><h3 className="rule">Appearance</h3>
          {sw('Dark appearance', 'dark')}
          {sw('Compact tables', 'compact')}
          {row('Language', <span className="val">{PROFILE.language}</span>)}
        </div>
        <div className="card"><h3 className="rule">Notifications</h3>
          {sw('Critical alerts', 'notifyCritical')}
          {sw('Honey-file triggers', 'notifyHoney')}
          {sw('Daily email digest', 'digest')}
          <div className="setfoot">Choices are saved in this browser. Notification delivery is not connected yet.</div>
        </div>
      </div>
    </section>
  )
}
