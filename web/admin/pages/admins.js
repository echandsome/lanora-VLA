// Administrators: the dashboard accounts. Only owners get this page.

import { html, useState } from '../vendor/htm-preact.js';
import { api } from '../lib/api.js';
import {
  ActionDialog,
  Field,
  Icon,
  PageHead,
  Pending,
  ROLE_NAMES,
  RelTime,
  Stale,
  Table,
  toast,
  useData,
  useSession,
} from '../lib/ui.js';

const ROLES = Object.entries(ROLE_NAMES);
const ROLE_SCOPE = {
  viewer: 'Can look at everything and change nothing.',
  admin: 'Manages rooms, members, bans and settings.',
  owner: 'Can do everything, including managing these accounts.',
};

const PASSWORD_HINT = 'At least 10 characters.';

function NewAdmin({ onClose, reload }) {
  const [form, setForm] = useState({ username: '', password: '', role: 'viewer' });
  const set = (key) => (e) => setForm({ ...form, [key]: e.target.value });
  const create = async () => {
    const { admin } = await api.post('/admins', form);
    toast(`Account ${admin.username} was created.`);
    reload();
  };
  return html`
    <${ActionDialog} title="New administrator" submit="Create account" ready=${form.username && form.password} action=${create} onClose=${onClose}>
      <${Field}
        label="User name"
        value=${form.username}
        onInput=${set('username')}
        maxlength="32"
        autocomplete="off"
        spellcheck=${false}
        autofocus
        hint="2 to 32 letters, digits, dots, dashes or underscores."
      />
      <${Field}
        label="Password"
        type="password"
        value=${form.password}
        onInput=${set('password')}
        maxlength="128"
        autocomplete="new-password"
        hint=${`${PASSWORD_HINT} Pass it on to the account's user yourself; it is not shown again.`}
      />
      <${Field} as="select" label="Role" options=${ROLES} value=${form.role} onChange=${set('role')} hint=${ROLE_SCOPE[form.role]} />
    <//>
  `;
}

function EditAdmin({ admin, onClose, onDelete, reload }) {
  const [role, setRole] = useState(admin.role);
  const [enabled, setEnabled] = useState(!admin.disabled);
  const [password, setPassword] = useState('');

  // Only what changed is sent, so an untouched password stays as it is.
  const changes = {};
  if (role !== admin.role) changes.role = role;
  if (enabled === admin.disabled) changes.disabled = !enabled;
  if (password) changes.password = password;

  const save = async () => {
    await api.patch(`/admins/${admin.id}`, changes);
    toast(`Account ${admin.username} was updated.`);
    reload();
  };
  const remove = html`<button type="button" class="btn danger" onClick=${onDelete}>Delete account</button>`;
  return html`
    <${ActionDialog}
      title=${`Edit ${admin.username}`}
      submit="Save changes"
      ready=${Object.keys(changes).length > 0}
      extra=${remove}
      action=${save}
      onClose=${onClose}
    >
      <${Field}
        as="select"
        label="Role"
        options=${ROLES}
        value=${role}
        onChange=${(e) => setRole(e.target.value)}
        hint=${ROLE_SCOPE[role]}
      />
      <div class="field">
        <label class="check">
          <input type="checkbox" checked=${enabled} onChange=${(e) => setEnabled(e.target.checked)} />
          Account is enabled
        </label>
        <p class="hint">A disabled account cannot sign in and is signed out everywhere.</p>
      </div>
      <${Field}
        label="New password (optional)"
        type="password"
        value=${password}
        onInput=${(e) => setPassword(e.target.value)}
        maxlength="128"
        autocomplete="new-password"
        hint=${`${PASSWORD_HINT} Setting one signs the account out everywhere.`}
      />
    <//>
  `;
}

export function Admins() {
  const { me } = useSession();
  const { data, error, reload } = useData(() => api.get('/admins'));
  // { type: 'new' } | { type: 'edit' | 'delete', admin }
  const [dialog, setDialog] = useState(null);
  const close = () => setDialog(null);

  const head = (actions) => html`
    <${PageHead} title="Administrators" sub="Accounts that can sign in to this dashboard, and what each may do.">${actions}<//>
  `;
  if (!data) return html`${head()}<${Pending} error=${error} reload=${reload} />`;

  const columns = [
    {
      head: 'User name',
      cls: 'primary',
      cell: (a) => html`<span class="cell">${a.username}${a.id === me.id && html`<span class="badge">You</span>`}</span>`,
    },
    { head: 'Role', cell: (a) => ROLE_NAMES[a.role] || a.role },
    {
      head: 'Status',
      cell: (a) => (a.disabled ? html`<span class="badge warn">Disabled</span>` : html`<span class="muted">Active</span>`),
    },
    { head: 'Last sign-in', cls: 'nowrap', cell: (a) => html`<${RelTime} at=${a.last_login_at} />` },
    { head: 'Created', cls: 'nowrap', cell: (a) => html`<${RelTime} at=${a.created_at} />` },
    {
      head: 'Actions',
      hidden: true,
      cls: 'actions',
      // Your own role and password are changed under Account, where a
      // password change keeps you signed in.
      cell: (a) =>
        a.id === me.id
          ? html`<a class="btn small" href="#/account">Account</a>`
          : html`<button type="button" class="btn small" onClick=${() => setDialog({ type: 'edit', admin: a })}>Edit</button>`,
    },
  ];

  return html`
    ${head(html`
      <button type="button" class="btn primary" onClick=${() => setDialog({ type: 'new' })}>
        <${Icon} name="plus" />New administrator
      </button>
    `)}
    <${Stale} error=${error} />
    <div class="card"><${Table} label="Administrators" columns=${columns} rows=${data.admins} rowKey=${(a) => a.id} /></div>
    ${dialog && dialog.type === 'new' && html`<${NewAdmin} reload=${reload} onClose=${close} />`}
    ${dialog &&
    dialog.type === 'edit' &&
    html`<${EditAdmin}
      admin=${dialog.admin}
      reload=${reload}
      onClose=${close}
      onDelete=${() => setDialog({ type: 'delete', admin: dialog.admin })}
    />`}
    ${dialog &&
    dialog.type === 'delete' &&
    html`
      <${ActionDialog}
        title=${`Delete ${dialog.admin.username}?`}
        submit="Delete account"
        danger
        onClose=${close}
        action=${async () => {
          await api.del(`/admins/${dialog.admin.id}`);
          toast(`Account ${dialog.admin.username} was deleted.`);
          reload();
        }}
      >
        <p>The account is removed and signed out everywhere. What it did stays in the log.</p>
      <//>
    `}
  `;
}
