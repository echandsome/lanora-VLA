// Bans: server-wide bans on a device identity or a source address range.
// (A ban from a single room lives with that room's member list.)

import { html, useState } from '../vendor/htm-preact.js';
import { api } from '../lib/api.js';
import {
  ActionDialog,
  Empty,
  Field,
  Fingerprint,
  Icon,
  PageHead,
  Pending,
  RelTime,
  Stale,
  Table,
  can,
  toast,
  useData,
  useSession,
} from '../lib/ui.js';

const KINDS = {
  identity: {
    name: 'Device',
    label: 'Device identity',
    placeholder: '',
    hint: 'The fingerprint shown on the device’s page: 64 hex digits, or the same key in base64.',
  },
  ip: {
    name: 'Address',
    label: 'IP address or range',
    placeholder: '203.0.113.0/24',
    hint: 'One address, or a range in CIDR form. IPv4 and IPv6 both work.',
  },
};

function AddBan({ onClose, reload }) {
  const [kind, setKind] = useState('identity');
  const [value, setValue] = useState('');
  const [reason, setReason] = useState('');
  const add = async () => {
    await api.post('/bans', { kind, value, reason });
    toast('The ban is in force.');
    reload();
  };
  return html`
    <${ActionDialog} title="Add a server-wide ban" submit="Add ban" danger ready=${value.trim() !== ''} action=${add} onClose=${onClose}>
      <fieldset class="choice">
        <legend>Ban by</legend>
        ${Object.entries(KINDS).map(
          ([key, k]) => html`
            <label class="check" key=${key}>
              <input type="radio" name="kind" value=${key} checked=${kind === key} onChange=${() => setKind(key)} />
              ${k.label}
            </label>
          `,
        )}
      </fieldset>
      <${Field}
        label=${KINDS[kind].label}
        class="mono"
        value=${value}
        onInput=${(e) => setValue(e.target.value)}
        placeholder=${KINDS[kind].placeholder}
        hint=${KINDS[kind].hint}
        autocomplete="off"
        spellcheck=${false}
      />
      <${Field} label="Reason (optional)" value=${reason} onInput=${(e) => setReason(e.target.value)} maxlength="200" />
      <p class="hint">Anyone the ban covers is disconnected at once and cannot join any room.</p>
    <//>
  `;
}

export function Bans() {
  const { me } = useSession();
  const admin = can(me, 'admin');
  const { data, error, reload } = useData(() => api.get('/bans'));
  const [adding, setAdding] = useState(false);
  const [lifting, setLifting] = useState(null);

  // In the header and again, quieter, in the empty state.
  const addButton = (cls) => html`
    <button type="button" class=${cls} onClick=${() => setAdding(true)}><${Icon} name="plus" />Add ban</button>
  `;
  const columns = [
    { head: 'Type', cls: 'primary', cell: (b) => (KINDS[b.kind] || { name: b.kind }).name },
    {
      head: 'Banned',
      cell: (b) => (b.kind === 'identity' ? html`<${Fingerprint} identity=${b.value} />` : html`<span class="mono">${b.value}</span>`),
    },
    { head: 'Reason', cls: 'wrap', cell: (b) => b.reason },
    { head: 'Added', cls: 'nowrap', cell: (b) => html`<${RelTime} at=${b.created_at} />` },
  ];
  if (admin) {
    columns.push({
      head: 'Actions',
      hidden: true,
      cls: 'actions',
      cell: (b) => html`<button type="button" class="btn small" onClick=${() => setLifting(b)}>Lift ban</button>`,
    });
  }

  let body;
  if (!data) {
    body = html`<${Pending} error=${error} reload=${reload} />`;
  } else if (data.bans.length === 0) {
    body = html`
      <${Empty} icon="bans" title="No server-wide bans">
        <p>Ban a device from its page under Devices, or add a ban by identity or address here.</p>
        ${admin && addButton('btn')}
      <//>
    `;
  } else {
    body = html`<${Table} label="Server-wide bans" columns=${columns} rows=${data.bans} rowKey=${(b) => b.id} />`;
  }

  return html`
    <${PageHead}
      title="Bans"
      sub="Server-wide bans keep a device or an address range out of every room. A ban from a single room is managed in that room’s member list."
    >
      ${admin && addButton('btn primary')}
    <//>
    <${Stale} error=${data && error} />
    <div class="card">${body}</div>
    ${adding && html`<${AddBan} reload=${reload} onClose=${() => setAdding(false)} />`}
    ${lifting &&
    html`
      <${ActionDialog}
        title="Lift this ban?"
        submit="Lift ban"
        onClose=${() => setLifting(null)}
        action=${async () => {
          await api.del(`/bans/${lifting.id}`);
          toast('The ban was lifted.');
          reload();
        }}
      >
        <p>
          ${lifting.kind === 'identity' ? 'The device' : 'The address range'}
          ${' '}<span class="mono">${lifting.value}</span> will be able to join rooms again.
        </p>
      <//>
    `}
  `;
}
