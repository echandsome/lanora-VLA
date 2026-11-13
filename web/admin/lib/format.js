// Formatting helpers. Words are English like the rest of the interface;
// digits and dates follow the browser's locale.

const NBSP = '\u00a0'; // keeps a number and its unit on one line

const integer = new Intl.NumberFormat();
const dateTime = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium' });
const dateOnly = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' });
const timeOnly = new Intl.DateTimeFormat(undefined, { timeStyle: 'medium' });

export const fmtInt = (n) => integer.format(n);
export const fmtDateTime = (date) => dateTime.format(date);
export const fmtTime = (date) => timeOnly.format(date);

// "1 room", "2 rooms"
export const fmtCount = (n, noun) => `${integer.format(n)} ${noun}${n === 1 ? '' : 's'}`;

function scaled(value, base, units) {
  let unit = 0;
  while (value >= base && unit < units.length - 1) {
    value /= base;
    unit++;
  }
  // Three significant digits are as much as anyone reads off a dashboard.
  const digits = unit === 0 || value >= 100 ? 0 : value >= 10 ? 1 : 2;
  return value.toLocaleString(undefined, { maximumFractionDigits: digits }) + NBSP + units[unit];
}

// Memory and traffic volumes in binary units; link speeds in decimal bits per
// second, the way network gear and the relay limit setting quote them.
export const fmtBytes = (bytes) => scaled(bytes, 1024, ['B', 'KiB', 'MiB', 'GiB', 'TiB']);
export const fmtBitRate = (bytesPerSecond) => scaled(bytesPerSecond * 8, 1000, ['bit/s', 'kbit/s', 'Mbit/s', 'Gbit/s']);

export const fmtPercent = (value) =>
  value.toLocaleString(undefined, { maximumFractionDigits: value < 10 ? 1 : 0 }) + NBSP + '%';

export const fmtLatency = (ms) => (ms < 0 ? '—' : fmtInt(ms) + NBSP + 'ms');

export function fmtDuration(seconds) {
  const s = Math.max(0, Math.floor(seconds));
  if (s < 60) return `${s}${NBSP}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}${NBSP}min`;
  const h = Math.floor(m / 60);
  if (h < 48) return m % 60 ? `${h}${NBSP}h ${m % 60}${NBSP}min` : `${h}${NBSP}h`;
  const d = Math.floor(h / 24);
  return h % 24 ? `${d}${NBSP}d ${h % 24}${NBSP}h` : `${d}${NBSP}d`;
}

export function fmtAgo(date, now = Date.now()) {
  const s = Math.round((now - date) / 1000);
  // Also covers a browser clock that is behind the server's, which would
  // otherwise put the moment in the future.
  if (s < 5) return 'just now';
  if (s < 60) return `${s} sec ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} h ago`;
  const d = Math.floor(h / 24);
  if (d < 30) return d === 1 ? '1 day ago' : `${d} days ago`;
  return dateOnly.format(date);
}

// A device identity is 64 hex digits; the two ends are enough to recognise one.
export const shortId = (hex) => (hex.length > 16 ? `${hex.slice(0, 8)}…${hex.slice(-4)}` : hex);
