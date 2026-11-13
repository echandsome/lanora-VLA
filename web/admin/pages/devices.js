// Devices: every device identity the server has seen, and one device's
// memberships. A device is banned from the whole server from its own page.

import { html, useState } from '../vendor/htm-preact.js';
import { api } from '../lib/api.js';
import { fmtCount, fmtInt, shortId } from '../lib/format.js';
import {
  ActionDialog,
  CopyButton,
  Empty,
  Field,
  Mark,
  PageHead,
  Pending,
  RelTime,
  Search,
  Stale,
  Table,
  can,
  toast,
  useData,
  useDebounced,
  useSession,
} from '../lib/ui.js';

const PAGE = 100;

function Presence({ online }) {
  if (!online) return html`<span class="cell"><${Mark} kind="off" />Offline</span>`;
  return html`<span class="cell"><${Mark} />${online > 1 ? `Online in ${fmtCount(online, 'room')}` : 'Online'}</span>`;
}

const listColumns = [
  {
    head: 'Device',
    cls: 'primary',
    cell: (d) => html`
      <span class="cell">
        <a href=${`#/devices/${d.identity}`}>${d.nickname}</a>
        ${d.banned && html`<span class="badge bad">Banned from server</span>`}
        ${!d.banned && d.banned_rooms > 0 && html`<span class="badge warn">Banned in ${fmtCount(d.banned_rooms, 'room')}</span>`}
      </span>
    `,
  },
  { head: 'Fingerprint', cls: 'mono nowrap', cell: (d) => html`<span title=${d.identity}>${shortId(d.identity)}</span>` },
  { head: 'Status', cls: 'nowrap', cell: (d) => html`<${Presence} online=${d.online} />` },
  { head: 'Rooms', num: true, cell: (d) => fmtInt(d.rooms) },
  { head: 'Client', cls: 'nowrap', cell: (d) => `${d.platform} · ${d.client_version}` },
  { head: 'Last address', cls: 'mono addr', cell: (d) => d.last_addr },
  { head: 'Last seen', cls: 'nowrap', cell: (d) => html`<${RelTime} at=${d.last_seen_at} />` },
];

export function Devices() {
  const [search, setSearch] = useState('');
  const q = useDebounced(search.trim());
  const [limit, setLimit] = useState(PAGE);
  const { data, error, reload } = useData(() => api.list('/devices', 'devices', 'identity', { q }, limit), [q, limit]);

  let body;
  if (!data) {
    body = html`<${Pending} error=${error} reload=${reload} />`;
  } else if (data.items.length === 0) {
    body = q
      ? html`<${Empty} icon="search" title="No devices match">No nickname, address or fingerprint contains “${q}”.<//>`
      : html`<${Empty} icon="devices" title="No devices yet">A device is listed once it has joined a room.<//>`;
  } else {
    body = html`
      <${Table} label="Devices" columns=${listColumns} rows=${data.items} rowKey=${(d) => d.identity} />
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
    <${PageHead} title="Devices" sub="A device is one installation of the client, recognised by its key in every room it joins." />
    <${Stale} error=${data && error} />
    <div class="toolbar">
      <${Search} value=${search} onInput=${setSearch} label="Search devices by nickname, address or fingerprint" placeholder="Search devices" />
      ${data && html`<span class="count">${fmtCount(data.total, 'device')}</span>`}
    </div>
    <div class="card">${body}</div>
  `;
}

const membershipColumns = [
  { head: 'Room', cls: 'primary', cell: (m) => html`<a href=${`#/rooms/${m.room_id}`}>${m.room_name}</a>` },
  { head: 'Room ID', cls: 'mono nowrap', cell: (m) => m.room_display_id },
  { head: 'Nickname', cell: (m) => m.nickname },
  { head: 'Virtual IP', cls: 'mono nowrap', cell: (m) => m.ip },
  {
    head: 'Status',
    cls: 'nowrap',
    cell: (m) => html`
      <span class="cell">
        <${Presence} online=${m.online ? 1 : 0} />
        ${m.banned && html`<span class="badge bad" title=${m.ban_reason}>Banned</span>`}
      </span>
    `,
  },
  { head: 'Last address', cls: 'mono addr', cell: (m) => m.last_addr },
  { head: 'Last seen', cls: 'nowrap', cell: (m) => html`<${RelTime} at=${m.last_seen_at} />` },
];

function BanDevice({ identity, nickname, onClose, reload }) {
  const [reason, setReason] = useState('');
  const ban = async () => {
    await api.post('/bans', { kind: 'identity', value: identity, reason });
    toast(`${nickname} is banned from the server.`);
    reload();
  };
  return html`
    <${ActionDialog} title=${`Ban ${nickname} from the server?`} submit="Ban device" danger action=${ban} onClose=${onClose}>
      <p>The device is disconnected from every room and cannot join any room until the ban is lifted.</p>
      <${Field}
        label="Reason (optional)"
        value=${reason}
        onInput=${(e) => setReason(e.target.value)}
        maxlength="200"
        hint="Kept with the ban, for you and other administrators."
      />
    <//>
  `;
}

export function Device({ identity }) {
  const { me } = useSession();
  const { data, error, reload } = useData(() => api.get(`/devices/${identity}`), [identity]);
  const [banning, setBanning] = useState(false);
  const back = { href: '#/devices', label: 'Devices' };

  if (!data) return html`<${PageHead} title="Device" back=${back} /><${Pending} error=${error} reload=${reload} />`;

  // Memberships arrive most recently seen first; that one names the device.
  const latest = data.memberships[0];
  const liftBan = async () => {
    try {
      // The device knows that it is banned but not under which ban, so look it up.
      const { bans } = await api.get('/bans');
      const ban = bans.find((b) => b.kind === 'identity' && b.value === data.identity);
      if (ban) await api.del(`/bans/${ban.id}`);
      toast(`The server ban on ${latest.nickname} was lifted.`);
      reload();
    } catch (err) {
      toast(err.message, 'error');
    }
  };
  const meta = html`
    ${data.banned && html`<span class="badge bad">Banned from server</span>`}
    <span>${latest.platform} · ${latest.client_version}</span>
    <span>first seen <${RelTime} at=${Math.min(...data.memberships.map((m) => Date.parse(m.first_seen_at)))} /></span>
  `;

  return html`
    <${PageHead} title=${latest.nickname} back=${back} meta=${meta}>
      ${can(me, 'admin') &&
      (data.banned
        ? html`<button type="button" class="btn" onClick=${liftBan}>Lift server ban</button>`
        : html`<button type="button" class="btn danger" onClick=${() => setBanning(true)}>Ban from server</button>`)}
    <//>
    <${Stale} error=${error} />
    <div class="stack">
      <section class="card">
        <div class="card-head"><h2>Fingerprint</h2></div>
        <div class="card-body">
          <div class="secret">
            <code>${data.identity}</code>
            <${CopyButton} text=${data.identity} />
          </div>
        </div>
      </section>
      <section class="card">
        <div class="card-head">
          <h2>Rooms</h2>
          <span class="card-note">${fmtCount(data.memberships.length, 'membership')}</span>
        </div>
        <${Table} label="Rooms of this device" columns=${membershipColumns} rows=${data.memberships} rowKey=${(m) => m.id} />
      </section>
    </div>
    ${banning &&
    html`<${BanDevice} identity=${data.identity} nickname=${latest.nickname} reload=${reload} onClose=${() => setBanning(false)} />`}
  `;
}
