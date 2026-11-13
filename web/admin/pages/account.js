// The signed-in administrator's own corner: the sign-in screen, changing
// the password, signing out.

import { html, useEffect, useRef, useState } from '../vendor/htm-preact.js';
import { api } from '../lib/api.js';
import { Field, Notice, PageHead, ROLE_NAMES, RelTime, useSession } from '../lib/ui.js';

const ROLE_SCOPE = {
  viewer: 'You can look at everything but not change it.',
  admin: 'You can manage rooms, members, bans and settings.',
  owner: 'You can manage everything, including administrator accounts.',
};

// `notice` says why the screen is showing when the user did not ask for it.
export function SignIn({ notice, onSignedIn }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  // Seconds left of a lockout the server imposed after too many attempts.
  const [wait, setWait] = useState(0);
  const form = useRef(null);

  // The autofocus attribute only works on page load, and this screen also
  // appears later, when a session ends.
  useEffect(() => form.current.elements.username.focus(), []);

  useEffect(() => {
    if (wait <= 0) return undefined;
    const timer = setTimeout(() => setWait(wait - 1), 1000);
    return () => clearTimeout(timer);
  }, [wait]);

  const submit = async (e) => {
    e.preventDefault();
    // Read the fields at submit time: a password manager can fill them
    // without the page ever seeing an input event.
    const fields = new FormData(e.target);
    const username = fields.get('username').trim();
    const password = fields.get('password');
    if (!username || !password) return setError('Enter your user name and password.');
    setBusy(true);
    setError('');
    try {
      const { admin } = await api.signIn(username, password);
      return onSignedIn(admin);
    } catch (err) {
      setError(err.message);
      setWait(err.retryAfter);
      return setBusy(false);
    }
  };

  return html`
    <main class="auth">
      <form class="card auth-card" ref=${form} onSubmit=${submit}>
        <div class="auth-head">
          <img src="/logo.svg" width="48" height="48" alt="" />
          <h1>Sign in to Lanora</h1>
        </div>
        ${notice && !error && html`<${Notice}>${notice}<//>`}
        <div class="form">
          <${Field} label="User name" name="username" autocomplete="username" autocapitalize="none" spellcheck=${false} />
          <${Field} label="Password" name="password" type="password" autocomplete="current-password" />
          ${error && html`<${Notice} kind="error">${error}<//>`}
          <button type="submit" class="btn primary block" disabled=${busy || wait > 0}>
            ${busy ? 'Signing in…' : wait > 0 ? `Try again in ${wait} s` : 'Sign in'}
          </button>
        </div>
      </form>
    </main>
  `;
}

function ChangePassword() {
  const [form, setForm] = useState({ current: '', next: '', repeat: '' });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [done, setDone] = useState(false);
  const set = (key) => (e) => {
    setForm({ ...form, [key]: e.target.value });
    setDone(false);
  };
  const mismatch = form.repeat !== '' && form.repeat !== form.next;

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      await api.put('/me/password', { current: form.current, new: form.next });
      setForm({ current: '', next: '', repeat: '' });
      setDone(true);
    } catch (err) {
      setError(err.message);
    }
    setBusy(false);
  };

  return html`
    <form class="form" onSubmit=${submit}>
      <${Field}
        label="Current password"
        type="password"
        value=${form.current}
        onInput=${set('current')}
        autocomplete="current-password"
      />
      <${Field}
        label="New password"
        type="password"
        value=${form.next}
        onInput=${set('next')}
        maxlength="128"
        autocomplete="new-password"
        hint="At least 10 characters."
      />
      <${Field}
        label="Repeat the new password"
        type="password"
        value=${form.repeat}
        onInput=${set('repeat')}
        maxlength="128"
        autocomplete="new-password"
        error=${mismatch && 'The two passwords are not the same.'}
      />
      ${error && html`<${Notice} kind="error">${error}<//>`}
      ${done && html`<${Notice} kind="ok">Password changed. Other browsers signed in to this account were signed out.<//>`}
      <div class="form-actions">
        <button type="submit" class="btn primary" disabled=${busy || !form.current || !form.next || form.repeat !== form.next}>
          ${busy ? 'Changing…' : 'Change password'}
        </button>
      </div>
    </form>
  `;
}

export function Account() {
  const { me, signOut } = useSession();
  return html`
    <${PageHead} title="Account" />
    <div class="stack narrow">
      <section class="card">
        <div class="card-head"><h2>Signed in</h2></div>
        <div class="card-body stack">
          <dl class="facts">
            <dt>User name</dt>
            <dd>${me.username}</dd>
            <dt>Role</dt>
            <dd>${ROLE_NAMES[me.role]}. ${ROLE_SCOPE[me.role]}</dd>
            <dt>Account created</dt>
            <dd><${RelTime} at=${me.created_at} /></dd>
          </dl>
          <div class="form-actions">
            <button type="button" class="btn" onClick=${signOut}>Sign out</button>
          </div>
        </div>
      </section>
      <section class="card">
        <div class="card-head"><h2>Change password</h2></div>
        <div class="card-body"><${ChangePassword} /></div>
      </section>
    </div>
  `;
}
