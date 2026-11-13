// Overview: headline numbers, relay throughput, the server's resource use
// and the facts an administrator needs when helping someone connect.

import { html, useState } from '../vendor/htm-preact.js';
import { api } from '../lib/api.js';
import { WINDOW_MS, seedSystem, useLive } from '../lib/live.js';
import { fmtBitRate, fmtBytes, fmtCount, fmtDateTime, fmtDuration, fmtInt, fmtPercent, fmtTime } from '../lib/format.js';
import { CopyButton, Notice, PageHead, Pending, Stale, useData } from '../lib/ui.js';
import { Sparkline, StatTile, describe, hoverKeys } from '../lib/charts.js';

// `floor` is the smallest full-scale value of a chart: an idle server's
// CPU use should look idle, not like a mountain range.
const METRICS = [
  { key: 'cpu_percent', name: 'CPU', note: 'of one core', floor: 10, format: fmtPercent },
  { key: 'rss_bytes', name: 'Memory', note: 'resident', format: fmtBytes },
  { key: 'goroutines', name: 'Goroutines', format: fmtInt },
  { key: 'open_fds', name: 'Open files', format: fmtInt },
  { key: 'load1', name: 'Load', note: '1 min average', floor: 1, format: (v) => v.toFixed(2) },
];

const TLS_MODES = {
  selfsigned: 'Self-signed certificate, pinned by clients',
  files: 'Certificate from files',
  autocert: 'Automatic certificate (ACME)',
  off: 'Off; a reverse proxy in front terminates TLS',
};

const KEYS_HINT = 'Use the left and right arrow keys to read earlier values.';

// The sample to print: the one under the crosshair, or else the newest.
const pick = (list, hover) => (list.length ? list[hover === null ? list.length - 1 : Math.min(hover, list.length - 1)] : null);

function Resources({ samples }) {
  const [hover, setHover] = useState(null);
  const shown = pick(samples, hover);
  return html`
    <section class="card">
      <div class="card-head">
        <h2>Server resources</h2>
        <span class="card-note">${hover === null || !shown ? 'Last 5 minutes' : fmtTime(shown.t)}</span>
      </div>
      <div
        class="metrics"
        role="group"
        tabindex="0"
        aria-label=${`Resource history. ${KEYS_HINT}`}
        onKeyDown=${hoverKeys(samples.length, hover, setHover)}
        onBlur=${() => setHover(null)}
      >
        ${METRICS.map((m) => {
          const points = samples.map((s) => ({ t: s.t, v: s[m.key] }));
          return html`
            <div class="metric" key=${m.key}>
              <div class="metric-name">${m.name}${m.note && html`<small>${m.note}</small>`}</div>
              <${Sparkline}
                points=${points}
                span=${WINDOW_MS}
                floor=${m.floor}
                hover=${hover}
                onHover=${setHover}
                label=${describe(m.name, points, m.format)}
              />
              <div class="metric-value">${shown ? m.format(shown[m.key]) : '—'}</div>
            </div>
          `;
        })}
      </div>
    </section>
  `;
}

function RelayCard({ relay, rates }) {
  const [hover, setHover] = useState(null);
  if (!relay) {
    return html`
      <section class="card">
        <div class="card-head"><h2>Relay throughput</h2></div>
        <div class="card-body">
          <p class="muted">The built-in relay is not in use; stand-alone relay nodes carry the relayed traffic.</p>
        </div>
      </section>
    `;
  }
  const shown = pick(rates, hover);
  const drops = [
    [relay.dropped_no_peer, 'peer not connected'],
    [relay.dropped_unbound, 'sender not bound'],
    [relay.dropped_limited, 'over the rate limit'],
    [relay.dropped_queue, 'queue full'],
  ].filter(([n]) => n > 0);
  const dropped = drops.reduce((sum, [n]) => sum + n, 0);
  return html`
    <section class="card">
      <div class="card-head">
        <h2>Relay throughput</h2>
        <span class="card-note">${hover === null || !shown ? 'Last 5 minutes' : fmtTime(shown.t)}</span>
      </div>
      <div class="card-body stack">
        <div>
          <p class="figure">${shown ? fmtBitRate(shown.v) : '—'}</p>
          <p class="figure-note">${hover === null ? 'forwarded right now' : 'forwarded at that moment'}</p>
        </div>
        <div
          class="metrics"
          role="group"
          tabindex="0"
          aria-label=${`Relay throughput history. ${KEYS_HINT}`}
          onKeyDown=${hoverKeys(rates.length, hover, setHover)}
          onBlur=${() => setHover(null)}
        >
          <${Sparkline}
            points=${rates}
            span=${WINDOW_MS}
            floor=${1250}
            height=${56}
            hover=${hover}
            onHover=${setHover}
            label=${describe('Relay throughput', rates, fmtBitRate)}
          />
        </div>
        <dl class="facts">
          <dt>Forwarded</dt>
          <dd>${fmtBytes(relay.bytes)} in ${fmtCount(relay.packets, 'packet')} since the server started</dd>
          <dt>Dropped</dt>
          <dd>
            ${fmtCount(dropped, 'packet')}${dropped > 0 && ` (${drops.map(([n, why]) => `${fmtInt(n)} ${why}`).join(', ')})`}
          </dd>
        </dl>
      </div>
    </section>
  `;
}

function relayNodes(server) {
  // A node without a host means "the address the client used for the server".
  const nodes = server.relay_nodes.map((n) => (n.startsWith(':') ? `UDP port ${n.slice(1)} of this server` : n));
  if (server.relay_builtin) return `Built in, on ${nodes.join(', ')}`;
  return `${server.relay_healthy} of ${nodes.length} stand-alone nodes healthy: ${nodes.join(', ')}`;
}

function ServerCard({ server, stats }) {
  const host = stats.system;
  // Both times are the server's, so the browser's clock does not matter.
  const uptime = (Date.parse(stats.time) - Date.parse(server.started_at)) / 1000;
  const address = `https://${location.host}/#pin=${server.tls_pin}`;
  return html`
    <section class="card">
      <div class="card-head"><h2>Server</h2></div>
      <div class="card-body stack">
        <dl class="facts">
          <dt>Version</dt>
          <dd>${server.version}${server.commit && ` (${server.commit.slice(0, 8)})`}, protocol ${server.protocol}</dd>
          <dt>Uptime</dt>
          <dd title=${`Started ${fmtDateTime(new Date(server.started_at))}`}>${fmtDuration(uptime)}</dd>
          <dt>TLS</dt>
          <dd>${TLS_MODES[server.tls] || server.tls}</dd>
          ${server.tls === 'selfsigned' &&
          server.tls_pin &&
          html`
            <dt>Certificate pin</dt>
            <dd class="copyable"><code>${server.tls_pin}</code><${CopyButton} text=${server.tls_pin} /></dd>
            <dt>Address for clients</dt>
            <dd class="copyable"><code>${address}</code><${CopyButton} text=${address} /></dd>
          `}
          <dt>Relay</dt>
          <dd>${relayNodes(server)}</dd>
          ${host.mem_total_bytes > 0 &&
          html`
            <dt>Host</dt>
            <dd>
              ${fmtCount(host.cpus, 'CPU')}, ${fmtBytes(host.mem_avail_bytes)} of ${fmtBytes(host.mem_total_bytes)} memory available
            </dd>
          `}
        </dl>
        ${server.tls === 'selfsigned' &&
        html`<p class="hint">
          Clients need the address with the pin: it is how they recognise this server's self-signed certificate.
        </p>`}
        ${server.events_dropped > 0 &&
        html`<${Notice} kind="warn">
          ${fmtInt(server.events_dropped)} log events were dropped since the server started because they arrived faster
          than they could be written.
        <//>`}
      </div>
    </section>
  `;
}

export function Overview() {
  const feed = useLive();
  const { data, error, reload } = useData(async () => {
    const overview = await api.get('/overview');
    seedSystem(overview.history);
    return overview;
  });

  if (!data) return html`<${PageHead} title="Overview" /><${Pending} error=${error} reload=${reload} />`;
  const stats = feed.stats || data.live;
  const relay = stats.relay;
  return html`
    <${PageHead} title="Overview" />
    <${Stale} error=${error} />
    <div class="stack">
      <div class="tiles">
        <${StatTile}
          label="Members online"
          value=${fmtInt(stats.online)}
          sub=${`of ${fmtInt(data.registered)} registered memberships`}
        />
        <${StatTile}
          label="Active rooms"
          value=${fmtInt(stats.active_rooms)}
          of=${fmtInt(data.rooms)}
          sub="rooms with someone online"
        />
        <${StatTile} label="Registered devices" value=${fmtInt(data.devices)} sub="distinct device identities" />
        <${StatTile}
          label="Relay sessions"
          value=${relay ? fmtInt(relay.sessions) : '—'}
          sub=${relay ? 'clients bound to the relay' : 'handled by stand-alone nodes'}
        />
      </div>
      <div class="cols">
        <${Resources} samples=${feed.system} />
        <div class="stack">
          <${RelayCard} relay=${relay} rates=${feed.relay} />
          <${ServerCard} server=${data.server} stats=${stats} />
        </div>
      </div>
    </div>
  `;
}
