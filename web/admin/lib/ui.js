// Building blocks shared by the pages: icons, dialogs, form fields, tables,
// feedback, and the hook that loads a page's data and keeps it fresh.

import {
  html,
  createContext,
  useContext,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from '../vendor/htm-preact.js';
import { onPresence } from './live.js';
import { fmtAgo, fmtDateTime, shortId } from './format.js';

// ---------- Session ----------

// { me, settings, setSettings, signOut } for whoever is signed in.
export const Session = createContext({});
export const useSession = () => useContext(Session);

const RANK = { viewer: 1, admin: 2, owner: 3 };
export const ROLE_NAMES = { viewer: 'Viewer', admin: 'Administrator', owner: 'Owner' };

// Mirrors the server's role check, so controls an account cannot use are not drawn at all.
export const can = (me, role) => (RANK[me && me.role] || 0) >= RANK[role];

// ---------- Icons ----------

// Line icons on a 24-unit grid, drawn for this dashboard.
const ICONS = {
  overview: 'M3 3h7v9H3zM14 3h7v5h-7zM14 12h7v9h-7zM3 16h7v5H3z',
  rooms:
    'M9.5 5a2.5 2.5 0 1 0 5 0a2.5 2.5 0 1 0-5 0M2.5 18.5a2.5 2.5 0 1 0 5 0a2.5 2.5 0 1 0-5 0M16.5 18.5a2.5 2.5 0 1 0 5 0a2.5 2.5 0 1 0-5 0M10.8 7.2 6.2 16.3M13.2 7.2l4.6 9.1M7.5 18.5h9',
  connections: 'M3 12h4l3-7 4 14 3-7h4',
  devices: 'M3 4h18v12H3zM8 20h8M12 16v4',
  bans: 'M3 12a9 9 0 1 0 18 0a9 9 0 1 0-18 0M5.6 5.6l12.8 12.8',
  logs: 'M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01',
  settings:
    'M4 6h8M16 6h4M4 12h2M10 12h10M4 18h10M18 18h2M12 6a2 2 0 1 0 4 0a2 2 0 1 0-4 0M6 12a2 2 0 1 0 4 0a2 2 0 1 0-4 0M14 18a2 2 0 1 0 4 0a2 2 0 1 0-4 0',
  admins: 'M12 3l7 3v5c0 4.6-3 8.4-7 10-4-1.6-7-5.4-7-10V6z',
  account: 'M8 8a4 4 0 1 0 8 0a4 4 0 1 0-8 0M4 21c0-4 3.6-6.5 8-6.5s8 2.5 8 6.5',
  menu: 'M4 6h16M4 12h16M4 18h16',
  close: 'M6 6l12 12M18 6 6 18',
  plus: 'M12 5v14M5 12h14',
  search: 'M4 11a7 7 0 1 0 14 0a7 7 0 1 0-14 0M21 21l-4.3-4.3',
  copy: 'M9 9h12v12H9zM5 15H3V3h12v2',
  check: 'M5 12.5l4.5 4.5L19 7.5',
  chevron: 'M9 6l6 6-6 6',
  back: 'M19 12H5M11 6l-6 6 6 6',
  warn: 'M12 4 2.5 20h19zM12 10v4.5M12 17.5h.01',
  info: 'M3 12a9 9 0 1 0 18 0a9 9 0 1 0-18 0M12 11v5.5M12 7.5h.01',
  error: 'M3 12a9 9 0 1 0 18 0a9 9 0 1 0-18 0M12 7v6M12 16.5h.01',
  ok: 'M3 12a9 9 0 1 0 18 0a9 9 0 1 0-18 0M8 12.5l3 3 5-6',
};

export function Icon({ name, size = 16 }) {
  return html`
    <svg class="icon" width=${size} height=${size} viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path d=${ICONS[name]} />
    </svg>
  `;
}

// ---------- Small pieces ----------

let lastUid = 0;
const useUid = (prefix) => useMemo(() => `${prefix}${++lastUid}`, []);

export function useDebounced(value, ms = 250) {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setSettled(value), ms);
    return () => clearTimeout(timer);
  }, [value]);
  return settled;
}

// One clock for every relative time on the page.
const clockSubs = new Set();
setInterval(() => clockSubs.forEach((fn) => fn()), 15000);

// "3 min ago", with the exact time on hover.
export function RelTime({ at }) {
  const [, bump] = useState(0);
  useEffect(() => {
    const fn = () => bump((n) => n + 1);
    clockSubs.add(fn);
    return () => clockSubs.delete(fn);
  }, []);
  const date = new Date(at);
  // Go's zero time stands for "never".
  if (!at || date.getFullYear() < 1971) return html`<span class="muted">never</span>`;
  return html`<time datetime=${date.toISOString()} title=${fmtDateTime(date)}>${fmtAgo(date)}</time>`;
}

// A status mark. With a label it stands on its own; without one it only
// decorates the text next to it and is hidden from assistive technology.
export function Mark({ kind = '', label }) {
  return label
    ? html`<span class=${`mark ${kind}`} role="img" aria-label=${label} title=${label}></span>`
    : html`<span class=${`mark ${kind}`} aria-hidden="true"></span>`;
}

export function Notice({ kind = 'info', class: extra = '', children }) {
  return html`
    <div class=${`notice ${kind} ${extra}`} role=${kind === 'error' ? 'alert' : 'status'}>
      <${Icon} name=${kind} />
      <div>${children}</div>
    </div>
  `;
}

export function Empty({ icon, title, children }) {
  return html`
    <div class="empty">
      <${Icon} name=${icon} size=${24} />
      <strong>${title}</strong>
      ${children}
    </div>
  `;
}

export function PageHead({ title, sub, back, meta, children }) {
  return html`
    <header class="page-head">
      <div>
        ${back && html`<a class="back" href=${back.href}><${Icon} name="back" size=${14} />${back.label}</a>`}
        <h1>${title}</h1>
        ${sub && html`<p class="page-sub">${sub}</p>`}
        ${meta && html`<div class="page-meta">${meta}</div>`}
      </div>
      ${children && html`<div class="page-actions">${children}</div>`}
    </header>
  `;
}

// `label` says what is searched, for assistive technology; the placeholder
// has to fit a phone and stays short.
export function Search({ value, onInput, label, placeholder }) {
  return html`
    <div class="search">
      <${Icon} name="search" />
      <input
        class="input"
        type="search"
        aria-label=${label}
        placeholder=${placeholder}
        value=${value}
        onInput=${(e) => onInput(e.target.value)}
      />
    </div>
  `;
}

// A device identity, shortened, linking to the device's page.
export function Fingerprint({ identity }) {
  return html`<a class="mono nowrap" href=${`#/devices/${identity}`} title=${identity}>${shortId(identity)}</a>`;
}

// How a member reaches its peers, worst news first in the mark.
export function PathSummary({ session }) {
  if (!session.reported) return html`<span class="muted" title="The client has not sent a path report yet">—</span>`;
  const { direct, relayed, unreachable } = session;
  if (direct + relayed + unreachable === 0) return html`<span class="muted">no peers</span>`;
  const parts = [
    direct && `${direct} direct`,
    relayed && `${relayed} relayed`,
    unreachable && `${unreachable} unreachable`,
  ].filter(Boolean);
  const kind = unreachable ? 'bad' : relayed ? 'warn' : '';
  return html`<span class="cell"><${Mark} kind=${kind} />${parts.join(', ')}</span>`;
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // No clipboard API outside a secure context (plain HTTP on a LAN address).
  }
  const area = document.createElement('textarea');
  area.value = text;
  area.readOnly = true;
  area.className = 'sr-only';
  // An open modal dialog makes the rest of the page inert, so the helper
  // has to live inside it to be selectable.
  (document.querySelector('dialog[open]') || document.body).append(area);
  area.select();
  let ok = false;
  try {
    ok = document.execCommand('copy');
  } catch {
    /* ok stays false */
  }
  area.remove();
  return ok;
}

export function CopyButton({ text, label = 'Copy', class: cls = 'btn small' }) {
  const [state, setState] = useState('');
  useEffect(() => {
    if (!state) return undefined;
    const timer = setTimeout(() => setState(''), 2000);
    return () => clearTimeout(timer);
  }, [state]);
  const copy = async () => setState((await copyText(text)) ? 'done' : 'failed');
  return html`
    <button type="button" class=${cls} onClick=${copy}>
      <${Icon} name=${state === 'done' ? 'check' : 'copy'} size=${14} />
      <span aria-live="polite">${state === 'done' ? 'Copied' : state === 'failed' ? 'Copy failed' : label}</span>
    </button>
  `;
}

// ---------- Toasts: feedback for actions that leave nothing else behind ----------

let toasts = [];
const toastSubs = new Set();

function setToasts(next) {
  toasts = next;
  toastSubs.forEach((fn) => fn(next));
}

const dismiss = (id) => setToasts(toasts.filter((t) => t.id !== id));

export function toast(message, kind = 'ok') {
  const id = ++lastUid;
  setToasts([...toasts, { id, message, kind }]);
  setTimeout(() => dismiss(id), kind === 'error' ? 8000 : 4000);
}

export function Toasts() {
  const [list, setList] = useState(toasts);
  useEffect(() => {
    toastSubs.add(setList);
    return () => toastSubs.delete(setList);
  }, []);
  return html`
    <div class="toasts" role="status" aria-live="polite">
      ${list.map(
        (t) => html`
          <div key=${t.id} class=${`toast ${t.kind}`}>
            <${Icon} name=${t.kind} />
            <p>${t.message}</p>
            <button type="button" class="btn quiet icon-only" aria-label="Dismiss" onClick=${() => dismiss(t.id)}>
              <${Icon} name="close" size=${14} />
            </button>
          </div>
        `,
      )}
    </div>
  `;
}

// ---------- Dialogs ----------

// A modal built on <dialog>: the browser keeps focus inside it, makes the
// page behind it inert and hands focus back to the opener when it closes.
// Escape and the close button always dismiss; a click on the backdrop does
// too unless the dialog is `persistent` (it shows something unrepeatable).
export function Dialog({ title, onClose, onSubmit, footer, busy = false, persistent = false, children }) {
  const ref = useRef(null);
  const titleId = useUid('dialog');
  const pressedOutside = useRef(false);
  const mounted = useRef(true);

  useEffect(() => {
    const dialog = ref.current;
    dialog.showModal();
    return () => {
      // close() fires a "close" event after this component is gone; without
      // the flag it would reach the parent and could close a dialog opened since.
      mounted.current = false;
      dialog.close();
    };
  }, []);

  const close = () => {
    if (!busy) onClose();
  };
  // Forms skip the browser's own validation bubbles: the server decides
  // what is valid and its answer is shown in the dialog.
  const Box = onSubmit ? 'form' : 'div';
  return html`
    <dialog
      ref=${ref}
      class="dialog"
      aria-labelledby=${titleId}
      onCancel=${(e) => {
        e.preventDefault(); // Escape: closing is the parent's decision, not while a request runs
        close();
      }}
      onClose=${() => mounted.current && onClose()}
      onMouseDown=${(e) => {
        pressedOutside.current = e.target === ref.current;
      }}
      onClick=${(e) => {
        // Only a click that both starts and ends on the backdrop dismisses, so
        // dragging a text selection out of the dialog does not.
        if (e.target === ref.current && pressedOutside.current && !persistent) close();
      }}
    >
      <${Box} class="dialog-box" onSubmit=${onSubmit} novalidate=${Boolean(onSubmit)}>
        <div class="dialog-head">
          <h2 id=${titleId}>${title}</h2>
          <button type="button" class="btn quiet icon-only" aria-label="Close" onClick=${close}>
            <${Icon} name="close" />
          </button>
        </div>
        <div class="dialog-body">${children}</div>
        ${footer && html`<div class="dialog-foot">${footer}</div>`}
      <//>
    </dialog>
  `;
}

// A dialog around one request: it runs `action`, shows a failure in place
// and closes on success. With `danger` the confirming button is red.
export function ActionDialog({ title, submit, danger, ready = true, action, onClose, extra, children }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const onSubmit = async (e) => {
    e.preventDefault();
    if (busy || !ready) return;
    setBusy(true);
    setError('');
    try {
      await action();
      onClose();
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  };
  const footer = html`
    ${extra && html`<span class="left">${extra}</span>`}
    <button type="button" class="btn" disabled=${busy} onClick=${onClose}>Cancel</button>
    <button type="submit" class=${danger ? 'btn danger-solid' : 'btn primary'} disabled=${busy || !ready}>
      ${busy ? 'Working…' : submit}
    </button>
  `;
  return html`
    <${Dialog} title=${title} onClose=${onClose} onSubmit=${onSubmit} busy=${busy} footer=${footer}>
      ${children}
      ${error && html`<${Notice} kind="error">${error}<//>`}
    <//>
  `;
}

// ---------- Forms ----------

// A labelled control with its hint and error wired up for assistive technology.
export function Field({ label, hint, error, as = 'input', options, unit, ...props }) {
  const id = useUid('field');
  const describedBy = [hint && `${id}-hint`, error && `${id}-error`].filter(Boolean).join(' ');
  const control = {
    id,
    class: `input ${props.class || ''}`,
    'aria-describedby': describedBy || undefined,
    'aria-invalid': error ? 'true' : undefined,
  };
  const input =
    as === 'select'
      ? html`<select ...${props} ...${control}>
          ${options.map(([value, text]) => html`<option value=${value}>${text}</option>`)}
        </select>`
      : as === 'textarea'
        ? html`<textarea ...${props} ...${control}></textarea>`
        : html`<input ...${props} ...${control} />`;
  return html`
    <div class="field">
      <label for=${id}>${label}</label>
      ${unit ? html`<div class="with-unit">${input}<span>${unit}</span></div>` : input}
      ${hint && html`<p class="hint" id=${`${id}-hint`}>${hint}</p>`}
      ${error && html`<p class="field-error" id=${`${id}-error`}>${error}</p>`}
    </div>
  `;
}

// ---------- Tables ----------

// True when the table inside `wrap` is wider than its container and should
// be drawn as stacked cards instead, so nothing ever scrolls sideways. A
// table can only tell how much room it wants while it is a table; that
// width is remembered to decide when it may become one again.
function useStacked(wrap) {
  const [stacked, setStacked] = useState(false);
  const state = useRef({ stacked, needed: 0 });
  state.current.stacked = stacked;

  const measure = () => {
    const el = wrap.current;
    if (!state.current.stacked) state.current.needed = el.scrollWidth;
    setStacked(state.current.needed > el.clientWidth);
  };
  useEffect(() => {
    const observer = new ResizeObserver(measure);
    observer.observe(wrap.current);
    return () => observer.disconnect();
  }, []);
  // New rows can be wider than the old ones without the container resizing.
  useLayoutEffect(measure);
  return stacked;
}

// columns: [{ head, cell(row), num, cls, hidden }]. `head` doubles as the
// label of the cell when the table is stacked into cards.
// `detail(row)` may return content for a full-width row underneath.
export function Table({ label, columns, rows, rowKey, detail }) {
  const wrap = useRef(null);
  const stacked = useStacked(wrap);
  const cellClass = (c) => [c.num && 'num', c.cls].filter(Boolean).join(' ');
  return html`
    <div class="table-wrap" ref=${wrap}>
      <table class=${stacked ? 'table stacked' : 'table'} aria-label=${label}>
        <thead>
          <tr>
            ${columns.map(
              (c) => html`
                <th scope="col" class=${c.num ? 'num' : ''}>
                  ${c.hidden ? html`<span class="sr-only">${c.head}</span>` : c.head}
                </th>
              `,
            )}
          </tr>
        </thead>
        <tbody>
          ${rows.flatMap((row) => {
            const key = rowKey(row);
            const extra = detail && detail(row);
            const main = html`
              <tr key=${key}>
                ${columns.map((c) => html`<td class=${cellClass(c)} data-label=${c.head}>${c.cell(row)}</td>`)}
              </tr>
            `;
            if (!extra) return [main];
            return [main, html`<tr key=${`${key}/detail`} class="detail"><td colspan=${columns.length}>${extra}</td></tr>`];
          })}
        </tbody>
      </table>
    </div>
  `;
}

// ---------- Data ----------

// Calls `refresh` whenever the server announces a presence change and, when
// `every` is set, on a timer as well, for values that no event announces
// (path reports, traffic counters). Returns nothing; pages own their state.
export function useRefresh(refresh, deps, every = 0) {
  const latest = useRef(refresh);
  latest.current = refresh;
  useEffect(() => {
    let timer = 0;
    const off = onPresence(() => {
      // Changes come in bursts; one reload shortly after the last is enough.
      clearTimeout(timer);
      timer = setTimeout(() => latest.current(), 250);
    });
    const tick = every && setInterval(() => document.hidden || latest.current(), every);
    return () => {
      off();
      clearTimeout(timer);
      clearInterval(tick);
    };
  }, deps);
}

// Loads what a page shows and keeps it fresh. While a reload is under way
// the previous data stays on screen, so nothing flashes or jumps.
export function useData(load, deps = [], every = 0) {
  const [state, setState] = useState({ data: undefined, error: null });
  const latest = useRef(load);
  latest.current = load;
  const run = useRef(0);
  const gone = useRef(false);

  const reload = async () => {
    if (gone.current) return; // no point in polling for something that was deleted
    const mine = ++run.current;
    try {
      const data = await latest.current();
      if (mine === run.current) setState({ data, error: null });
    } catch (error) {
      if (mine !== run.current) return;
      // A failed refresh keeps the old data visible, unless the thing is gone.
      gone.current = error.status === 404;
      setState((s) => ({ data: gone.current ? undefined : s.data, error }));
    }
  };

  useEffect(() => {
    gone.current = false;
    reload();
    return () => {
      run.current++; // answers to an outdated request are ignored
    };
  }, deps);
  useRefresh(reload, deps, every);

  return { ...state, reload };
}

// What to show instead of a page's content while it has no data.
export function Pending({ error, reload }) {
  if (!error) return html`<p class="loading">Loading…</p>`;
  return html`
    <${Notice} kind="error">
      <p>${error.message}</p>
      ${error.status !== 404 && html`<button type="button" class="btn small" onClick=${reload}>Try again</button>`}
    <//>
  `;
}

// Shown above data that could not be refreshed.
export function Stale({ error }) {
  return error && html`<${Notice} kind="warn" class="banner">Showing the last known state. ${error.message}<//>`;
}
