// One room: its settings, its members with their live sessions, and the
// actions an administrator can take on either.

import { html, useState } from '../vendor/htm-preact.js';
import { api } from '../lib/api.js';
import { fmtBytes, fmtInt, fmtLatency } from '../lib/format.js';
import {
  ActionDialog,
  CopyButton,
  Empty,
  Field,
  Fingerprint,
  Icon,
  Mark,
  Notice,
  PageHead,
  PathSummary,
  Pending,
  RelTime,
  Stale,
  Table,
  can,
  toast,
  useData,
  useSession,
} from '../lib/ui.js';
import { SecretDialog } from './rooms.js';

const BACK = { href: '#/rooms', label: 'Rooms' };
const VIA = { direct: ['', 'Direct'], relay: ['warn', 'Relayed'], none: ['bad', 'Unreachable'] };

// Addresses sort by value, so 10.0.0.10 comes after 10.0.0.9.
const addressValue = (ip) => ip.split('.').reduce((n, part) => n * 256 + Number(part), 0);

function DetailsForm({ room, reload }) {
  // The form follows the server until someone starts typing; a refresh in
  // the background must not overwrite a half-finished edit.
  const [draft, setDraft] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const values = draft || { name: room.name, description: room.description, capacity: String(room.capacity) };
  const set = (key) => (e) => setDraft({ ...values, [key]: e.target.value });

  const save = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      await api.patch(`/rooms/${room.id}`, {
        name: values.name,
        description: values.description,
        capacity: Number(values.capacity),
      });
      // Drop the draft only once the saved values are back, or the form
      // would show the old ones for a moment.
      await reload();
      setDraft(null);
      toast('Room details saved.');
    } catch (err) {
      setError(err.message);
    }
    setBusy(false);
  };

  return html`
    <form class="form narrow" onSubmit=${save} novalidate>
      <div class="form-row">
        <${Field} label="Name" value=${values.name} onInput=${set('name')} maxlength="64" autocomplete="off" />
        <${Field}
          label="Capacity"
          type="number"
          min="2"
          max="253"
          value=${values.capacity}
          onInput=${set('capacity')}
          hint="2 to 253 members connected at the same time."
        />
      </div>
      <${Field}
        as="textarea"
        label="Description"
        value=${values.description}
        onInput=${set('description')}
        maxlength="280"
        rows="2"
      />
      ${error && html`<${Notice} kind="error">${error}<//>`}
      <div class="form-actions">
        <button type="submit" class="btn primary" disabled=${!draft || busy}>${busy ? 'Saving…' : 'Save changes'}</button>
        ${draft &&
        html`
          <button
            type="button"
            class="btn quiet"
            disabled=${busy}
            onClick=${() => {
              setDraft(null);
              setError('');
            }}
          >
            Discard
          </button>
        `}
      </div>
    </form>
  `;
}

function MemberDetail({ member, names, admin, onAction }) {
  const session = member.session;
  const peers = (session && session.peers) || [];
  return html`
    <div class="detail-body">
      ${admin &&
      html`
        <div class="detail-actions">
          ${member.online && html`<button type="button" class="btn small" onClick=${() => onAction('kick', member)}>Kick</button>`}
          ${member.banned
            ? html`<button type="button" class="btn small" onClick=${() => onAction('unban', member)}>Lift ban</button>`
            : html`<button type="button" class="btn small danger" onClick=${() => onAction('ban', member)}>Ban</button>`}
          <button type="button" class="btn small danger" onClick=${() => onAction('remove', member)}>Remove</button>
        </div>
      `}
      <dl class="facts">
        <dt>First seen</dt>
        <dd><${RelTime} at=${member.first_seen_at} /></dd>
        ${member.banned &&
        html`
          <dt>Ban reason</dt>
          <dd>${member.ban_reason || html`<span class="muted">none given</span>`}</dd>
        `}
        ${session &&
        html`
          <dt>Relay</dt>
          <dd>
            ${session.relay_bound
              ? `Bound; ${fmtBytes(session.relay_rx_bytes)} sent and ${fmtBytes(session.relay_tx_bytes)} received through it`
              : 'Not bound'}
          </dd>
          <dt>Endpoints</dt>
          <dd>
            ${session.endpoints.length
              ? html`
                  <details class="endpoints">
                    <summary>${session.endpoints.length} advertised to peers</summary>
                    <ul class="mono">
                      ${session.endpoints.map((endpoint) => html`<li key=${endpoint}>${endpoint}</li>`)}
                    </ul>
                  </details>
                `
              : 'None advertised to peers'}
          </dd>
        `}
      </dl>
      ${session &&
      (peers.length
        ? html`
            <table class="table subtable">
              <caption>
                Paths to peers
              </caption>
              <thead>
                <tr>
                  <th scope="col">Peer</th>
                  <th scope="col">Path</th>
                  <th scope="col" class="num">Latency</th>
                </tr>
              </thead>
              <tbody>
                ${peers.map((peer) => {
                  const [kind, text] = VIA[peer.via] || VIA.none;
                  return html`
                    <tr key=${peer.ip}>
                      <td>${names.get(peer.ip) || 'Unknown'} <span class="mono muted">${peer.ip}</span></td>
                      <td>
                        <span class="cell"><${Mark} kind=${kind} />${text}</span>
                      </td>
                      <td class="num">${fmtLatency(peer.rtt_ms)}</td>
                    </tr>
                  `;
                })}
              </tbody>
            </table>
          `
        : html`<p class="muted">
            ${session.reported ? 'No other member is connected.' : 'The client has not reported its paths yet.'}
          </p>`)}
    </div>
  `;
}

// The confirmation behind every destructive button on this page.
function RoomDialog({ dialog, room, onClose, reload, onPassword }) {
  const [text, setText] = useState('');
  const base = `/rooms/${room.id}`;
  const member = dialog.member;
  const here = member && `${base}/members/${member.id}`;

  switch (dialog.type) {
    case 'disable':
      return html`
        <${ActionDialog}
          title="Disable this room?"
          submit="Disable room"
          danger
          onClose=${onClose}
          action=${async () => {
            await api.patch(base, { enabled: false });
            toast(`${room.name} is disabled.`);
            reload();
          }}
        >
          <p>
            Nobody can join <strong>${room.name}</strong> while it is disabled, and everyone connected now is
            disconnected. Members, addresses and the password are kept.
          </p>
        <//>
      `;
    case 'password':
      return html`
        <${ActionDialog}
          title="Reset the room password"
          submit="Reset password"
          danger
          onClose=${onClose}
          action=${async () => {
            onPassword((await api.post(`${base}/password`, { password: text })).password);
            reload();
          }}
        >
          <${Field}
            label="New password (optional)"
            value=${text}
            onInput=${(e) => setText(e.target.value)}
            maxlength="128"
            autocomplete="off"
            spellcheck=${false}
            hint="At least 8 characters. Leave it empty and the server generates one."
          />
          <${Notice} kind="warn">
            The old password stops working at once. Everyone connected is disconnected and has to join again with
            the new one.
          <//>
        <//>
      `;
    case 'delete':
      return html`
        <${ActionDialog}
          title="Delete this room?"
          submit="Delete room"
          danger
          ready=${text === room.name}
          onClose=${onClose}
          action=${async () => {
            await api.del(base);
            toast(`${room.name} was deleted.`);
            location.hash = '#/rooms';
          }}
        >
          <p>
            This removes <strong>${room.name}</strong> with all of its memberships and address assignments, and
            disconnects everyone in it. It cannot be undone.
          </p>
          <${Field}
            label=${html`Type <strong>${room.name}</strong> to confirm`}
            value=${text}
            onInput=${(e) => setText(e.target.value)}
            autocomplete="off"
            spellcheck=${false}
          />
        <//>
      `;
    case 'kick':
      return html`
        <${ActionDialog}
          title=${`Kick ${member.nickname}?`}
          submit="Kick"
          danger
          onClose=${onClose}
          action=${async () => {
            await api.post(`${here}/kick`);
            toast(`${member.nickname} was disconnected.`);
            reload();
          }}
        >
          <p>The member is disconnected at once. It stays a member and can join again with the room password.</p>
        <//>
      `;
    case 'ban':
      return html`
        <${ActionDialog}
          title=${`Ban ${member.nickname} from this room?`}
          submit="Ban"
          danger
          onClose=${onClose}
          action=${async () => {
            await api.post(`${here}/ban`, { reason: text });
            toast(`${member.nickname} is banned from ${room.name}.`);
            reload();
          }}
        >
          <p>
            The device is disconnected and cannot join this room again until the ban is lifted. Other rooms are not
            affected.
          </p>
          <${Field}
            label="Reason (optional)"
            value=${text}
            onInput=${(e) => setText(e.target.value)}
            maxlength="200"
            hint="Shown to the banned member and kept with the ban."
          />
        <//>
      `;
    default:
      return html`
        <${ActionDialog}
          title=${`Remove ${member.nickname} from this room?`}
          submit="Remove"
          danger
          onClose=${onClose}
          action=${async () => {
            await api.del(here);
            toast(`${member.nickname} was removed and ${member.ip} is free again.`);
            reload();
          }}
        >
          <p>
            The membership is deleted and its address <span class="mono">${member.ip}</span> is released. The device
            can join again with the room password, possibly under a different address.
          </p>
        <//>
      `;
  }
}

export function Room({ id }) {
  const { me } = useSession();
  const admin = can(me, 'admin');
  // Presence events cover joins and leaves; path reports and relay counters
  // change without one, hence the timer.
  const { data, error, reload } = useData(() => api.get(`/rooms/${id}`), [id], 10000);
  const [dialog, setDialog] = useState(null);
  const [password, setPassword] = useState('');
  const [open, setOpen] = useState(() => new Set());

  if (!data) return html`<${PageHead} title="Room" back=${BACK} /><${Pending} error=${error} reload=${reload} />`;

  const { room } = data;
  const members = [...data.members].sort((a, b) => addressValue(a.ip) - addressValue(b.ip));
  const names = new Map(members.map((m) => [m.ip, m.nickname]));

  const toggle = (memberId) => {
    const next = new Set(open);
    if (!next.delete(memberId)) next.add(memberId);
    setOpen(next);
  };
  const act = async (type, member) => {
    if (type !== 'unban') return setDialog({ type, member });
    try {
      await api.post(`/rooms/${room.id}/members/${member.id}/unban`);
      toast(`The ban on ${member.nickname} was lifted.`);
      reload();
    } catch (err) {
      toast(err.message, 'error');
    }
    return undefined;
  };
  const enable = async () => {
    try {
      await api.patch(`/rooms/${room.id}`, { enabled: true });
      toast(`${room.name} is enabled.`);
      reload();
    } catch (err) {
      toast(err.message, 'error');
    }
  };

  const columns = [
    {
      head: 'Member',
      cls: 'primary',
      // The name itself opens the member's details: a bigger target than a chevron alone.
      cell: (m) => html`
        <span class="cell">
          <button type="button" class="expander" aria-expanded=${open.has(m.id) ? 'true' : 'false'} onClick=${() => toggle(m.id)}>
            <${Icon} name="chevron" size=${14} />
            <${Mark} kind=${m.online ? '' : 'off'} label=${m.online ? 'Online' : 'Offline'} />
            ${m.nickname}
          </button>
          ${m.banned && html`<span class="badge bad">Banned</span>`}
        </span>
      `,
    },
    { head: 'Virtual IP', cls: 'mono nowrap', cell: (m) => m.ip },
    { head: 'Device', cell: (m) => html`<${Fingerprint} identity=${m.identity} />` },
    { head: 'Client', cls: 'nowrap', cell: (m) => `${m.platform} · ${m.client_version}` },
    {
      head: 'Address',
      cls: 'mono addr',
      cell: (m) => (m.session ? m.session.remote_addr : html`<span class="muted">${m.last_addr}</span>`),
    },
    {
      head: 'Last seen',
      cls: 'nowrap',
      cell: (m) =>
        m.session ? html`Connected <${RelTime} at=${m.session.connected_at} />` : html`<${RelTime} at=${m.last_seen_at} />`,
    },
    { head: 'Paths', cell: (m) => m.session && html`<${PathSummary} session=${m.session} />` },
    { head: 'Latency', num: true, cell: (m) => m.session && fmtLatency(m.session.avg_rtt_ms) },
  ];
  const detail = (m) =>
    open.has(m.id) && html`<${MemberDetail} member=${m} names=${names} admin=${admin} onAction=${act} />`;

  const meta = html`
    ${room.enabled ? html`<span class="badge good">Enabled</span>` : html`<span class="badge warn">Disabled</span>`}
    <span class="cell">
      Room ID <span class="mono">${room.display_id}</span>
      <${CopyButton} class="btn quiet small" label="Copy" text=${room.display_id} />
    </span>
    <span class="cell">Subnet <span class="mono">${room.subnet}</span></span>
  `;

  return html`
    <${PageHead} title=${room.name} back=${BACK} meta=${meta}>
      ${admin &&
      html`
        ${room.enabled
          ? html`<button type="button" class="btn" onClick=${() => setDialog({ type: 'disable' })}>Disable</button>`
          : html`<button type="button" class="btn" onClick=${enable}>Enable</button>`}
        <button type="button" class="btn" onClick=${() => setDialog({ type: 'password' })}>Reset password</button>
        <button type="button" class="btn danger" onClick=${() => setDialog({ type: 'delete' })}>Delete</button>
      `}
    <//>
    <${Stale} error=${error} />
    <div class="stack">
      <section class="card">
        <div class="card-head"><h2>Details</h2></div>
        <div class="card-body stack">
          ${admin
            ? html`<${DetailsForm} room=${room} reload=${reload} />`
            : html`
                <dl class="facts">
                  <dt>Description</dt>
                  <dd>${room.description || html`<span class="muted">none</span>`}</dd>
                  <dt>Capacity</dt>
                  <dd>${fmtInt(room.capacity)} members</dd>
                </dl>
              `}
          <p class="hint">
            Created <${RelTime} at=${room.created_at} />, last changed <${RelTime} at=${room.updated_at} />.
          </p>
        </div>
      </section>
      <section class="card">
        <div class="card-head">
          <h2>Members</h2>
          <span class="card-note">
            ${fmtInt(room.online)} online, ${fmtInt(room.members)} registered, capacity ${fmtInt(room.capacity)}
          </span>
        </div>
        ${members.length
          ? html`<${Table} label="Members" columns=${columns} rows=${members} rowKey=${(m) => m.id} detail=${detail} />`
          : html`
              <${Empty} icon="devices" title="No members yet">
                <p>Devices appear here once they join with the room ID and the password.</p>
              <//>
            `}
      </section>
    </div>
    ${dialog &&
    html`<${RoomDialog}
      key=${dialog.type}
      dialog=${dialog}
      room=${room}
      reload=${reload}
      onClose=${() => setDialog(null)}
      onPassword=${setPassword}
    />`}
    ${password &&
    html`<${SecretDialog} room=${room} password=${password} changed onClose=${() => setPassword('')} />`}
  `;
}
