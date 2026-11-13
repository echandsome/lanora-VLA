// Figures for the overview: stat tiles and sparklines.
//
// A sparkline here is one series, so it needs no legend or axis; its row
// names it and prints the current value next to it. Pointing at it (or
// stepping with the arrow keys) moves a crosshair, and the owner swaps the
// printed value for the one under the crosshair.

import { html, useEffect, useRef, useState } from '../vendor/htm-preact.js';

export function StatTile({ label, value, of, sub }) {
  return html`
    <div class="card tile">
      <p class="tile-label">${label}</p>
      <p class="tile-value">${value}${of !== undefined && html`<small>/ ${of}</small>`}</p>
      ${sub && html`<p class="tile-sub">${sub}</p>`}
    </div>
  `;
}

const PAD = 5; // keeps the 4 px end marker and its ring inside the drawing
const GAP_MS = 7000; // samples come every 2 s; a longer silence breaks the line

// points: [{ t, v }], oldest first, t in milliseconds. The x axis always
// covers `span` ms ending at the newest point, so a short history leaves the
// left of the chart empty rather than stretching to fill it. The y axis
// starts at zero; `floor` is the smallest full-scale value, which keeps idle
// noise from looking like load.
export function Sparkline({ points, span, floor = 0, height = 40, hover = null, onHover, label }) {
  const box = useRef(null);
  const [width, setWidth] = useState(0);

  // Drawn in real pixels: stretching a fixed viewBox to fit would distort
  // the marker and the line weight.
  useEffect(() => {
    const observer = new ResizeObserver(([entry]) => setWidth(Math.floor(entry.contentRect.width)));
    observer.observe(box.current);
    return () => observer.disconnect();
  }, []);

  const count = points.length;
  const base = height - PAD;
  let drawing = null;
  let locate;

  if (width && count) {
    const end = points[count - 1].t;
    const top = Math.max(floor, ...points.map((p) => p.v)) * 1.1 || 1;
    const x = (p) => width - PAD - ((end - p.t) / span) * (width - 2 * PAD);
    const y = (p) => base - (p.v / top) * (base - PAD);
    const at = (p) => `${x(p).toFixed(1)} ${y(p).toFixed(1)}`;

    const runs = [];
    points.forEach((p, i) => {
      if (i === 0 || p.t - points[i - 1].t > GAP_MS) runs.push([]);
      runs[runs.length - 1].push(p);
    });
    const line = runs.map((run) => `M${run.map(at).join('L')}`).join('');
    const area = runs
      .map((run) => `M${x(run[0]).toFixed(1)} ${base}L${run.map(at).join('L')}L${x(run[run.length - 1]).toFixed(1)} ${base}Z`)
      .join('');

    const marked = points[hover === null ? count - 1 : Math.min(hover, count - 1)];
    drawing = html`
      <path class="spark-area" d=${area} />
      <path class="spark-line" d=${line} />
      ${hover !== null && html`<line class="spark-cross" x1=${x(marked)} x2=${x(marked)} y1="0" y2=${height} />`}
      <circle class="spark-dot" cx=${x(marked)} cy=${y(marked)} r="4" />
    `;

    // The pointer only has to be nearest to a sample, not on the line.
    locate = (event) => {
      const px = event.clientX - box.current.getBoundingClientRect().left;
      let best = 0;
      for (let i = 1; i < count; i++) {
        if (Math.abs(x(points[i]) - px) < Math.abs(x(points[best]) - px)) best = i;
      }
      onHover(best);
    };
  }

  return html`
    <div class="spark" ref=${box}>
      <svg
        width=${width}
        height=${height}
        role="img"
        aria-label=${label}
        onPointerMove=${onHover && locate}
        onPointerDown=${onHover && locate}
        onPointerLeave=${onHover && (() => onHover(null))}
      >
        <line class="spark-base" x1="0" x2=${width} y1=${base + 0.5} y2=${base + 0.5} />
        ${drawing}
      </svg>
    </div>
  `;
}

// Key handler for a focusable group of sparklines: the arrow keys step
// through the samples so a keyboard gets the same readout as a pointer.
export function hoverKeys(count, hover, setHover) {
  return (event) => {
    const last = count - 1;
    // The first key press starts at the newest sample.
    const here = hover === null ? null : Math.min(hover, last);
    const target = {
      ArrowLeft: here === null ? last : here - 1,
      ArrowRight: here === null ? last : here + 1,
      Home: 0,
      End: last,
    }[event.key];
    if (event.key === 'Escape') {
      setHover(null);
    } else if (target !== undefined && count) {
      event.preventDefault();
      setHover(Math.max(0, Math.min(last, target)));
    }
  };
}

// The sentence a screen reader gets in place of the drawing.
export function describe(name, points, format) {
  if (!points.length) return `${name}: no data yet`;
  const values = points.map((p) => p.v);
  return `${name} over the last five minutes: now ${format(values[values.length - 1])}, lowest ${format(
    Math.min(...values),
  )}, highest ${format(Math.max(...values))}`;
}
