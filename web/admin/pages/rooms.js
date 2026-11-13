// Rooms: the searchable list, the "New room" dialog, and the dialog that
// shows a room password the one time the server reveals it.

import { html, useState } from '../vendor/htm-preact.js';
import { api } from '../lib/api.js';
import { fmtCount, fmtInt } from '../lib/format.js';
import {
  ActionDialog,
  CopyButton,
  Dialog,
  Empty,
  Field,
  Icon,
  Notice,
  PageHead,
  Pending,
  Search,
  Stale,
  Table,
  can,
  useData,
  useDebounced,
  useSession,
} from '../lib/ui.js';

const PAGE = 100;

// The server returns a room password in plain text only in the response to
// creating the room or resetting the password. This dialog is that moment.
export function SecretDialog({ room, password, changed, onClose }) {
  const footer = html`
    <${CopyButton} class="btn" label="Copy ID and password" text=${`Room ID: ${room.display_id}\nPassword: ${password}`} />
    <button type="button" class="btn primary" onClick=${onClose}>Done</button>
  `;
  return html`
    <${Dialog} title=${changed ? 'New room password' : 'Room created'} onClose=${onClose} footer=${footer} persistent>
      ${changed
        ? html`<p>
            The password of <strong>${room.name}</strong> was changed. Everyone who was connected has to join again
            with the new one.
          </p>`
        : html`<p><strong>${room.name}</strong> is ready. People join it with the room ID and the password.</p>`}
      <div class="field">
        <span class="label">Room ID</span>
        <div class="secret"><code>${room.display_id}</code><${CopyButton} text=${room.display_id} /></div>
      </div>
      <div class="field">
        <span class="label">Password</span>
        <div class="secret"><code>${password}</code><${CopyButton} text=${password} /></div>
      </div>
      <${Notice} kind="warn">
        This password will not be shown again. Copy it now; if it gets lost, the only way forward is to reset it.
      <//>
    <//>
  `;
}

function NewRoomDialog({ onClose, onCreated }) {
  const { settings } = useSession();
  const [form, setForm] = useState({ name: '', description: '', capacity: '', password: '', subnet: '' });
  const set = (key) => (e) => setForm({ ...form, [key]: e.target.value });

  const create = async () => {
    // Capacity 0 asks the server for its default.
    onCreated(await api.post('/rooms', { ...form, capacity: Number(form.capacity) || 0 }));
  };
  const fallback = settings ? ` (${settings.default_capacity})` : '';
  return html`
    <${ActionDialog} title="New room" submit="Create room" ready=${form.name.trim() !== ''} action=${create} onClose=${onClose}>
      <${Field} label="Name" value=${form.name} onInput=${set('name')} maxlength="64" autocomplete="off" autofocus />
      <${Field}
        as="textarea"
        label="Description (optional)"
        value=${form.description}
        onInput=${set('description')}
        maxlength="280"
        rows="2"
      />
      <div class="form-row">
        <${Field}
          label="Capacity"
          type="number"
          min="2"
          max="253"
          value=${form.capacity}
          onInput=${set('capacity')}
          placeholder=${settings ? settings.default_capacity : ''}
          hint=${`2 to 253 members. Empty uses the default${fallback}.`}
        />
        <${Field}
          label="Subnet (optional)"
          class="mono"
          value=${form.subnet}
          onInput=${set('subnet')}
          placeholder="10.214.7.0/24"
          autocomplete="off"
          hint="An IPv4 /24. Empty takes the next free one from the address pool."
        />
      </div>
      <${Field}
        label="Password (optional)"
        value=${form.password}
        onInput=${set('password')}
        maxlength="128"
        autocomplete="off"
        spellcheck=${false}
        hint="At least 8 characters. Leave it empty and the server generates one."
      />
    <//>
  `;
}

export function Rooms() {
  const { me } = useSession();
  const admin = can(me, 'admin');
  const [search, setSearch] = useState('');
  const q = useDebounced(search.trim());
  const [limit, setLimit] = useState(PAGE);
  const { data, error, reload } = useData(() => api.list('/rooms', 'rooms', 'id', { q }, limit), [q, limit]);
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState(null);

  // The button appears in the header and again, quieter, in the empty state.
  const newRoom = (cls) => html`
    <button type="button" class=${cls} onClick=${() => setCreating(true)}><${Icon} name="plus" />New room</button>
  `;
  const columns = [
    { head: 'Name', cls: 'primary', cell: (r) => html`<a href=${`#/rooms/${r.id}`}>${r.name}</a>` },
    { head: 'Room ID', cls: 'mono nowrap', cell: (r) => r.display_id },
    { head: 'Subnet', cls: 'mono nowrap', cell: (r) => r.subnet },
    { head: 'Online / capacity', num: true, cell: (r) => `${fmtInt(r.online)} / ${fmtInt(r.capacity)}` },
    {
      head: 'Status',
      // Enabled is the normal case and stays quiet; only the exception gets a badge.
      cell: (r) => (r.enabled ? html`<span class="muted">Enabled</span>` : html`<span class="badge warn">Disabled</span>`),
    },
  ];

  let body;
  if (!data) {
    body = html`<${Pending} error=${error} reload=${reload} />`;
  } else if (data.items.length === 0) {
    body = q
      ? html`<${Empty} icon="search" title="No rooms match">Nothing is named, described or numbered “${q}”.<//>`
      : html`
          <${Empty} icon="rooms" title="No rooms yet">
            <p>A room is a private virtual network that people join with an ID and a password.</p>
            ${admin && newRoom('btn')}
          <//>
        `;
  } else {
    body = html`
      <${Table} label="Rooms" columns=${columns} rows=${data.items} rowKey=${(r) => r.id} />
      ${data.items.length < data.total &&
      html`
        <div class="more">
          <button type="button" class="btn" onClick=${() => setLimit(limit + PAGE)}>
            Show more (${fmtInt(data.items.length)} of ${fmtInt(data.total)})
          </button>
        </div>
      `}
    `;
  }

  return html`
    <${PageHead} title="Rooms" sub="Each room is its own virtual LAN with a /24 subnet.">${admin && newRoom('btn primary')}<//>
    <${Stale} error=${data && error} />
    <div class="toolbar">
      <${Search} value=${search} onInput=${setSearch} label="Search rooms by name, description or ID" placeholder="Search rooms" />
      ${data && html`<span class="count">${fmtCount(data.total, 'room')}</span>`}
    </div>
    <div class="card">${body}</div>
    ${creating &&
    html`<${NewRoomDialog}
      onClose=${() => setCreating(false)}
      onCreated=${(result) => {
        setCreated(result);
        reload();
      }}
    />`}
    ${created &&
    html`<${SecretDialog} room=${created.room} password=${created.password} onClose=${() => setCreated(null)} />`}
  `;
}
