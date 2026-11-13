// Settings: the options an administrator can change while the server runs.
// The server is the judge of what is valid; its verdict is shown above the
// save button. The limits are spelled out next to each field so that the
// verdict rarely comes as a surprise.

import { html, useState } from '../vendor/htm-preact.js';
import { api } from '../lib/api.js';
import { Field, Notice, PageHead, Pending, can, useData, useSession } from '../lib/ui.js';

const GROUPS = [
  {
    title: 'General',
    fields: [
      {
        key: 'server_name',
        label: 'Server name',
        maxlength: 48,
        hint: 'Shown to clients when they connect and at the top of this dashboard. Up to 48 characters.',
      },
    ],
  },
  {
    title: 'Addressing',
    fields: [
      {
        key: 'address_pool',
        label: 'Address pool',
        mono: true,
        hint: 'The IPv4 range, in CIDR form, that every new room takes its /24 subnet from. Between /8 and /24, for example 10.214.0.0/16. Existing rooms keep their subnet.',
      },
      {
        key: 'mtu',
        label: 'MTU',
        unit: 'bytes',
        min: 576,
        max: 1400,
        hint: 'Largest packet the virtual adapter carries. 576 to 1400; 1280 fits through every common connection without fragmentation. Clients pick it up when they next join.',
      },
    ],
  },
  {
    title: 'Rooms',
    fields: [
      {
        key: 'default_capacity',
        label: 'Default room capacity',
        unit: 'members',
        min: 2,
        max: 253,
        hint: 'Used when a room is created without a capacity of its own. 2 to 253.',
      },
      {
        key: 'max_rooms',
        label: 'Maximum number of rooms',
        unit: 'rooms',
        min: 0,
        max: 1000000,
        hint: '0 to 1,000,000. 0 means no limit.',
      },
    ],
  },
  {
    title: 'Sessions',
    fields: [
      {
        key: 'session_hours',
        label: 'Room session lifetime',
        unit: 'hours',
        min: 1,
        max: 720,
        hint: 'Lifetime of the token a client receives when it joins a room. Once it runs out the client has to join again with the room password. 1 hour to 30 days (720 hours).',
      },
      {
        key: 'admin_session_hours',
        label: 'Dashboard session lifetime',
        unit: 'hours',
        min: 1,
        max: 720,
        hint: 'How long an administrator stays signed in without using the dashboard. 1 hour to 30 days (720 hours).',
      },
    ],
  },
  {
    title: 'Relay and clients',
    fields: [
      {
        key: 'relay_limit_kbps',
        label: 'Relay limit per client',
        unit: 'kbit/s',
        min: 0,
        max: 10000000,
        hint: 'How much traffic one client may put through the relay. 0 to 10,000,000 kbit/s. 0 means no limit.',
      },
      {
        key: 'min_client_version',
        label: 'Minimum client version',
        mono: true,
        hint: 'Older clients are refused. It cannot be lower than the oldest version this server supports; leave the field empty to use exactly that version.',
      },
    ],
  },
  {
    title: 'Logs',
    fields: [
      {
        key: 'log_retention_days',
        label: 'Log retention',
        unit: 'days',
        min: 1,
        max: 3650,
        hint: 'Events older than this are deleted. 1 to 3650 days.',
      },
    ],
  },
];

const FIELDS = GROUPS.flatMap((g) => g.fields);
const isNumber = (f) => f.min !== undefined;

export function Settings() {
  const { me, setSettings } = useSession();
  const editable = can(me, 'admin');
  const { data, error, reload } = useData(() => api.get('/settings'));
  // null while the form mirrors the server; an object of strings once edited.
  const [draft, setDraft] = useState(null);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState('');
  const [invalid, setInvalid] = useState({});
  const [saved, setSaved] = useState(false);

  const sub = 'Saved changes take effect immediately, without restarting the server.';
  if (!data) return html`<${PageHead} title="Settings" sub=${sub} /><${Pending} error=${error} reload=${reload} />`;

  const values = draft || Object.fromEntries(FIELDS.map((f) => [f.key, String(data.settings[f.key])]));
  const edit = (key) => (e) => {
    setDraft({ ...values, [key]: e.target.value });
    setSaved(false);
    if (invalid[key]) setInvalid({ ...invalid, [key]: '' });
  };

  const save = async (e) => {
    e.preventDefault();
    // JSON needs real numbers. Whether they are within range is for the server to say.
    const problems = {};
    const next = {};
    for (const f of FIELDS) {
      const text = values[f.key].trim();
      if (!isNumber(f)) next[f.key] = text;
      else if (/^-?\d+$/.test(text)) next[f.key] = Number(text);
      else problems[f.key] = 'Enter a whole number.';
    }
    setInvalid(problems);
    setFailure('');
    const [first] = Object.keys(problems);
    // The form is long; put the cursor in the first field that needs attention.
    if (first) return e.target.elements[first].focus();

    setBusy(true);
    try {
      const { settings } = await api.put('/settings', next);
      setSettings(settings);
      await reload();
      setDraft(null);
      setSaved(true);
    } catch (err) {
      setFailure(err.message);
    }
    return setBusy(false);
  };

  return html`
    <${PageHead} title="Settings" sub=${sub} />
    <form class="card narrow" onSubmit=${save} novalidate>
      <div class="card-body stack">
        ${!editable && html`<${Notice}>Your account can read the settings but not change them.<//>`}
        ${GROUPS.map(
          (group) => html`
            <section class="settings-group" key=${group.title}>
              <h2 class="section-title">${group.title}</h2>
              <div class="form">
                ${group.fields.map(
                  (f) => html`
                    <${Field}
                      key=${f.key}
                      name=${f.key}
                      label=${f.label}
                      hint=${f.hint}
                      error=${invalid[f.key]}
                      unit=${f.unit}
                      class=${f.mono ? 'mono' : ''}
                      type=${isNumber(f) ? 'number' : 'text'}
                      inputmode=${isNumber(f) ? 'numeric' : undefined}
                      min=${f.min}
                      max=${f.max}
                      maxlength=${f.maxlength}
                      value=${values[f.key]}
                      onInput=${edit(f.key)}
                      disabled=${!editable}
                      autocomplete="off"
                      spellcheck=${false}
                    />
                  `,
                )}
              </div>
            </section>
          `,
        )}
        ${editable &&
        html`
          ${failure && html`<${Notice} kind="error">${failure}<//>`}
          ${saved && html`<${Notice} kind="ok">Settings saved.<//>`}
          <div class="form-actions">
            <button type="submit" class="btn primary" disabled=${!draft || busy}>${busy ? 'Saving…' : 'Save settings'}</button>
            ${draft &&
            html`
              <button
                type="button"
                class="btn quiet"
                disabled=${busy}
                onClick=${() => {
                  setDraft(null);
                  setFailure('');
                  setInvalid({});
                }}
              >
                Discard changes
              </button>
            `}
          </div>
        `}
      </div>
    </form>
  `;
}
