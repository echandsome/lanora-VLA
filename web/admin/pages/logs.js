// Logs: the server's event log, newest first, with filters and paging
// backwards through history.

import { html, useEffect, useRef, useState } from '../vendor/htm-preact.js';
import { api } from '../lib/api.js';
import { Empty, PageHead, Pending, RelTime, Search, Stale, Table, toast, useDebounced, useRefresh } from '../lib/ui.js';

const PAGE = 100;
// Rows kept while the page refreshes itself; older ones are dropped again
// (and can be reloaded) unless the reader asked for more than this.
const KEEP = 1000;

const LEVELS = [
  ['', 'All levels'],
  ['info', 'Info'],
  ['warn', 'Warning'],
  ['error', 'Error'],
];

// The value is the prefix of the event kind that the server filters on.
const CATEGORIES = [
  ['', 'All categories'],
  ['room.', 'Rooms (room.)'],
  ['auth.', 'Join attempts (auth.)'],
  ['admin.', 'Administration (admin.)'],
  ['server.', 'Server (server.)'],
];

// Info is the normal case and stays quiet; warnings and errors get a badge.
function level(event) {
  if (event.level === 'warn') return html`<span class="badge warn">Warning</span>`;
  if (event.level === 'error') return html`<span class="badge bad">Error</span>`;
  return html`<span class="muted">Info</span>`;
}

const columns = [
  { head: 'Time', cls: 'nowrap', cell: (e) => html`<${RelTime} at=${e.time} />` },
  { head: 'Level', cell: level },
  { head: 'Event', cls: 'mono nowrap', cell: (e) => e.kind },
  // Kept on one line so that a long message wraps instead of squeezing the name.
  { head: 'Who', cls: 'nowrap', cell: (e) => e.actor },
  { head: 'Address', cls: 'mono addr', cell: (e) => e.addr },
  {
    head: 'Message',
    cls: 'wrap',
    // Events carry the room's number but not its name.
    cell: (e) => [e.message, e.room_id && html`<a class="room-ref" href=${`#/rooms/${e.room_id}`}>room</a>`],
  },
];

function Select({ label, options, value, onChange }) {
  return html`
    <select class="input" aria-label=${label} value=${value} onChange=${(e) => onChange(e.target.value)}>
      ${options.map(([key, text]) => html`<option value=${key}>${text}</option>`)}
    </select>
  `;
}

export function Logs() {
  const [levelFilter, setLevelFilter] = useState('');
  const [kind, setKind] = useState('');
  const [search, setSearch] = useState('');
  const q = useDebounced(search.trim());
  const [state, setState] = useState({ events: null, more: false, error: null });
  const [busy, setBusy] = useState(false);
  const filter = { level: levelFilter, kind, q, limit: PAGE };
  // Bumped whenever the filter changes, so an answer to an old filter is dropped.
  const generation = useRef(0);

  // Fetches the newest page. With `reset` it replaces the list; otherwise it
  // puts what is new on top and keeps the older pages already loaded.
  const refresh = async (reset) => {
    const mine = generation.current;
    try {
      const page = await api.get('/events', filter);
      if (mine !== generation.current) return;
      setState((s) => {
        const known = reset ? null : s.events;
        if (!known || !known.length) return { events: page.events, more: page.more, error: null };
        const fresh = page.events.filter((e) => e.id > known[0].id);
        // A whole page of new events means some may be missing between it
        // and the old list; start over rather than show a log with a hole.
        if (fresh.length === page.events.length && page.more) return { events: page.events, more: true, error: null };
        const limit = Math.max(KEEP, known.length);
        const events = [...fresh, ...known];
        return { events: events.slice(0, limit), more: s.more || events.length > limit, error: null };
      });
    } catch (error) {
      if (mine === generation.current) setState((s) => ({ ...s, error }));
    }
  };

  const loadOlder = async () => {
    const mine = generation.current;
    const oldest = state.events[state.events.length - 1].id;
    setBusy(true);
    try {
      const page = await api.get('/events', { ...filter, before: oldest });
      if (mine === generation.current) {
        setState((s) => ({ ...s, events: [...s.events, ...page.events.filter((e) => e.id < oldest)], more: page.more }));
      }
    } catch (error) {
      toast(error.message, 'error');
    }
    setBusy(false);
  };

  useEffect(() => {
    generation.current++;
    refresh(true);
  }, [levelFilter, kind, q]);
  // Many events (failed sign-ins, settings changes) come without a presence
  // event, so the newest page is polled as well.
  useRefresh(() => refresh(false), [levelFilter, kind, q], 15000);

  const { events, more, error } = state;
  let body;
  if (!events) {
    body = html`<${Pending} error=${error} reload=${() => refresh(true)} />`;
  } else if (events.length === 0) {
    body =
      levelFilter || kind || q
        ? html`<${Empty} icon="search" title="No events match">Try a wider filter or a different search.<//>`
        : html`<${Empty} icon="logs" title="The log is empty">Joins, sign-ins and administrative changes are recorded here.<//>`;
  } else {
    body = html`
      <${Table} label="Events" columns=${columns} rows=${events} rowKey=${(e) => e.id} />
      ${more &&
      html`
        <div class="more">
          <button type="button" class="btn" disabled=${busy} onClick=${loadOlder}>${busy ? 'Loading…' : 'Load older'}</button>
        </div>
      `}
    `;
  }

  return html`
    <${PageHead} title="Logs" sub="Connections, join attempts and everything administrators change." />
    <${Stale} error=${events && error} />
    <div class="toolbar">
      <${Select} label="Level" options=${LEVELS} value=${levelFilter} onChange=${setLevelFilter} />
      <${Select} label="Category" options=${CATEGORIES} value=${kind} onChange=${setKind} />
      <${Search} value=${search} onInput=${setSearch} label="Search the log by message, name or address" placeholder="Search the log" />
    </div>
    <div class="card">${body}</div>
  `;
}
