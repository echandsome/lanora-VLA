// Connections: every live session on the server, across all rooms.

import { html, useState } from '../vendor/htm-preact.js';
import { api } from '../lib/api.js';
import { fmtBytes, fmtCount, fmtInt, fmtLatency } from '../lib/format.js';
import { Empty, PageHead, PathSummary, Pending, RelTime, Search, Stale, Table, useData } from '../lib/ui.js';

// The API returns every session in one answer, so the page draws them in
// portions to stay responsive on a busy server.
const PAGE = 200;

const addressValue = (ip) => ip.split('.').reduce((n, part) => n * 256 + Number(part), 0);

const columns = [
  { head: 'Member', cls: 'primary', cell: (c) => c.nickname },
  {
    head: 'Room',
    cell: (c) => html`<a href=${`#/rooms/${c.room_id}`}>${c.room_name || c.room_display_id}</a>`,
  },
  { head: 'Virtual IP', cls: 'mono nowrap', cell: (c) => c.ip },
  { head: 'Address', cls: 'mono addr', cell: (c) => c.remote_addr },
  { head: 'Connected', cls: 'nowrap', cell: (c) => html`<${RelTime} at=${c.connected_at} />` },
  { head: 'Paths', cell: (c) => html`<${PathSummary} session=${c} />` },
  { head: 'Latency', num: true, cell: (c) => fmtLatency(c.avg_rtt_ms) },
  // The relay counts from its own side: what it received is what the member sent.
  { head: 'Relay sent', num: true, cell: (c) => (c.relay_bound ? fmtBytes(c.relay_rx_bytes) : '—') },
  { head: 'Relay received', num: true, cell: (c) => (c.relay_bound ? fmtBytes(c.relay_tx_bytes) : '—') },
];

export function Connections() {
  // Path reports and traffic counters change without a presence event.
  const { data, error, reload } = useData(() => api.get('/connections'), [], 10000);
  const [search, setSearch] = useState('');
  const [shown, setShown] = useState(PAGE);

  const head = html`<${PageHead} title="Connections" sub="Members connected right now, and how each one reaches its peers." />`;
  if (!data) return html`${head}<${Pending} error=${error} reload=${reload} />`;

  const term = search.trim().toLowerCase();
  const rows = data.connections
    .filter(
      (c) =>
        !term ||
        // The room fields are missing for a session whose room was just deleted.
        [c.nickname, c.room_name, c.room_display_id, c.ip, c.remote_addr].some((v) => (v || '').toLowerCase().includes(term)),
    )
    .sort(
      (a, b) =>
        (a.room_name || '').localeCompare(b.room_name || '') ||
        a.room_id - b.room_id ||
        addressValue(a.ip) - addressValue(b.ip),
    );

  let body;
  if (data.connections.length === 0) {
    body = html`<${Empty} icon="connections" title="Nobody is connected">Sessions appear here as soon as a member joins a room.<//>`;
  } else if (rows.length === 0) {
    body = html`<${Empty} icon="search" title="No connections match">Nothing connected matches “${search.trim()}”.<//>`;
  } else {
    body = html`
      <${Table}
        label="Connections"
        columns=${columns}
        rows=${rows.slice(0, shown)}
        rowKey=${(c) => `${c.room_id}/${c.member_id}`}
      />
      ${rows.length > shown &&
      html`
        <div class="more">
          <button type="button" class="btn" onClick=${() => setShown(shown + PAGE)}>
            Show more (${fmtInt(shown)} of ${fmtInt(rows.length)})
          </button>
        </div>
      `}
    `;
  }

  return html`
    ${head}
    <${Stale} error=${error} />
    <div class="toolbar">
      <${Search} value=${search} onInput=${setSearch} label="Filter connections by member, room or address" placeholder="Filter connections" />
      <span class="count">
        ${term ? `${fmtInt(rows.length)} of ` : ''}${fmtCount(data.connections.length, 'connection')}
      </span>
    </div>
    <div class="card">${body}</div>
  `;
}
