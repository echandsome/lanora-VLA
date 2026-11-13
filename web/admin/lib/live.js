// The live side of the dashboard: one Server-Sent Events connection shared by
// every page. The server sends "stats" every two seconds and "presence" when
// rooms or members change.

import { useEffect, useState } from '../vendor/htm-preact.js';
import { api } from './api.js';

// The window the sparklines cover. It matches overview.history, which holds
// five minutes of samples, so seeding and live data line up.
export const WINDOW_MS = 5 * 60 * 1000;

export const live = {
  state: 'connecting', // 'connecting' | 'live' | 'down'
  stats: null, // the latest "stats" event
  system: [], // resource samples, oldest first, each with t = time in ms
  relay: [], // relay throughput, { t, v } with v in bytes per second
};

const statsSubs = new Set();
const stateSubs = new Set();
const presenceSubs = new Set();
const emit = (subs) => subs.forEach((fn) => fn());

function trim(list) {
  const cutoff = list[list.length - 1].t - WINDOW_MS;
  while (list[0].t < cutoff) list.shift();
}

// Merges the history delivered with the overview into what the stream has
// collected, so the sparklines are full as soon as the page opens.
export function seedSystem(history) {
  const known = new Set(live.system.map((s) => s.t));
  const merged = history
    .map((s) => ({ ...s, t: Date.parse(s.time) }))
    .filter((s) => !known.has(s.t))
    .concat(live.system)
    .sort((a, b) => a.t - b.t);
  if (merged.length) trim(merged);
  live.system = merged;
  emit(statsSubs);
}

function onStats(stats) {
  const previous = live.stats;
  live.stats = stats;

  // Several stats events can carry the same resource sample.
  const t = Date.parse(stats.system.time);
  const last = live.system[live.system.length - 1];
  if (!last || t > last.t) {
    live.system.push({ ...stats.system, t });
    trim(live.system);
  }

  // The API reports a running byte total; the rate is its slope.
  if (previous && previous.relay && stats.relay) {
    const now = Date.parse(stats.time);
    const seconds = (now - Date.parse(previous.time)) / 1000;
    const bytes = stats.relay.bytes - previous.relay.bytes;
    // The total starts again from zero when the server restarts: skip that
    // interval instead of plotting a negative rate.
    if (seconds > 0 && bytes >= 0) {
      live.relay.push({ t: now, v: bytes / seconds });
      trim(live.relay);
    }
  }
  emit(statsSubs);
}

let source = null;
let retry = 0;
let wanted = false;

function setState(state) {
  if (live.state === state) return;
  live.state = state;
  emit(stateSubs);
}

function open() {
  if (source) return;
  source = new EventSource('/api/admin/stream');
  source.addEventListener('stats', (event) => {
    // Back after an interruption: anything a page shows may have changed.
    if (live.state === 'down') emit(presenceSubs);
    setState('live');
    onStats(JSON.parse(event.data));
  });
  source.addEventListener('presence', () => emit(presenceSubs));
  source.onerror = () => {
    setState('down');
    // The browser retries a dropped connection by itself, but gives up when
    // the server answers with an error status. In that case ask who we are:
    // a 401 takes the app to the sign-in screen, anything else is retried.
    if (source.readyState !== EventSource.CLOSED) return;
    source = null;
    retry = setTimeout(async () => {
      try {
        await api.get('/me');
      } catch {
        /* a 401 has been dealt with by the API layer */
      }
      if (wanted) open();
    }, 5000);
  };
}

export function startLive() {
  if (wanted) return;
  wanted = true;
  open();
}

export function stopLive() {
  wanted = false;
  clearTimeout(retry);
  if (source) source.close();
  source = null;
  Object.assign(live, { state: 'connecting', stats: null, system: [], relay: [] });
}

function useSubscription(subs) {
  const [, bump] = useState(0);
  useEffect(() => {
    const fn = () => bump((n) => n + 1);
    subs.add(fn);
    return () => subs.delete(fn);
  }, []);
}

// Re-renders the calling component on every stats event.
export function useLive() {
  useSubscription(statsSubs);
  return live;
}

// Re-renders only when the connection goes up or down.
export function useLiveState() {
  useSubscription(stateSubs);
  return live.state;
}

export function onPresence(fn) {
  presenceSubs.add(fn);
  return () => presenceSubs.delete(fn);
}
