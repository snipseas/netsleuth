// Hand-written SVG charts (no third-party code): stacked timeline with
// crosshair tooltip and brush selection, horizontal bar lists, two-series
// activity chart.
import { h, svg, clear, bytes, num, compact, utc, protoColor, protoOrder, showTip, hideTip } from './util.js';

const NAMED = ['TLS', 'HTTP', 'DNS', 'TCP', 'UDP', 'ICMP', 'SSH', 'ARP'];

function niceMax(v) {
  if (v <= 0) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (v <= m * p) return m * p;
  return 10 * p;
}
function fmtMetric(metric, v) { return metric === 'bytes' ? bytes(Math.round(v)) : compact(v); }

/** Fold every protocol without a fixed colour slot into "Other". */
export function foldSeries(series, metric) {
  const out = new Map();
  for (const [name, s] of Object.entries(series)) {
    const key = NAMED.includes(name) ? name : 'Other';
    const arr = s[metric];
    if (!out.has(key)) out.set(key, { name: key, values: arr.slice(), members: [name] });
    else { const o = out.get(key); arr.forEach((v, i) => { o.values[i] += v; }); o.members.push(name); }
  }
  return [...out.values()].sort((a, b) => protoOrder(a.name) - protoOrder(b.name));
}

export function legend(items) {
  return h('div', { class: 'legend' }, items.map(it =>
    h('span', { title: it.title || null }, h('i', { style: { background: it.color } }), it.label)));
}

/**
 * Stacked bar timeline.
 * opts: metric ('bytes'|'packets'), height, onRange(t0, t1) | onRange(null), markers [{ts, severity, title}]
 */
export function timelineChart(container, data, opts = {}) {
  clear(container);
  const metric = opts.metric || 'bytes';
  const series = foldSeries(data.series || {}, metric);
  if (!data.buckets || !series.length) {
    container.append(h('div', { class: 'empty' }, 'No packets in this range.'));
    return;
  }
  container.append(legend(series.map(s => ({
    label: s.name, color: protoColor(s.name),
    title: s.name === 'Other' ? `Includes: ${s.members.join(', ')}` : null }))));
  const wrap = h('div', { class: 'chart' });
  container.append(wrap);
  const W = Math.max(320, container.clientWidth || 800), H = opts.height || 190;
  const m = { l: 52, r: 8, t: opts.markers ? 16 : 6, b: 20 };
  const pw = W - m.l - m.r, ph = H - m.t - m.b;
  const n = data.buckets;
  const totals = Array.from({ length: n }, (_, i) => series.reduce((a, s) => a + s.values[i], 0));
  const ymax = niceMax(Math.max(...totals));
  const bw = pw / n;
  const root = svg('svg', { viewBox: `0 0 ${W} ${H}`, height: H, role: 'img',
    'aria-label': `Traffic over time by protocol (${metric})` });
  for (let i = 0; i <= 3; i++) {
    const y = m.t + ph - (ph * i) / 3;
    root.append(svg('line', { class: i ? 'grid-line' : 'axis-line', x1: m.l, x2: W - m.r, y1: y, y2: y }));
    root.append(svg('text', { x: m.l - 6, y: y + 3.5, 'text-anchor': 'end' },
      fmtMetric(metric, (ymax * i) / 3) + (metric === 'bytes' ? '' : '')));
  }
  const tAt = i => data.start + i * data.width;
  const ticks = Math.min(6, n);
  for (let k = 0; k < ticks; k++) {
    const i = Math.round((k * (n - 1)) / Math.max(1, ticks - 1));
    root.append(svg('text', { x: m.l + (i + 0.5) * bw, y: H - 5,
      'text-anchor': k === 0 ? 'start' : k === ticks - 1 ? 'end' : 'middle' }, utc(tAt(i), false)));
  }
  const gap = bw > 4 ? 1.5 : bw > 2 ? 0.5 : 0;
  for (let i = 0; i < n; i++) {
    let y = m.t + ph;
    for (const s of series) {
      const v = s.values[i];
      if (!v) continue;
      const hh = Math.max((v / ymax) * ph, 1);
      y -= hh;
      root.append(svg('rect', { x: m.l + i * bw + gap / 2, y, width: Math.max(bw - gap, 0.6),
        height: Math.max(hh - (hh > 3 ? 1 : 0), 0.6), fill: protoColor(s.name) }));
    }
  }
  for (const mk of opts.markers || []) {
    if (mk.ts == null) continue;
    const x = m.l + ((mk.ts - data.start) / (n * data.width)) * pw;
    if (x < m.l || x > W - m.r) continue;
    const tri = svg('path', { d: `M${x - 5},2 L${x + 5},2 L${x},11 Z`, fill: `var(--sev-${mk.severity})`,
      stroke: 'var(--surface)', 'stroke-width': 1.5, style: 'cursor:pointer' });
    tri.addEventListener('mousemove', e => { e.stopPropagation(); showTip(e, h('div', null,
      h('div', { class: 't' }, `${mk.severity.toUpperCase()} · ${utc(mk.ts)}`), mk.title)); });
    tri.addEventListener('mouseleave', hideTip);
    if (mk.onClick) tri.addEventListener('click', mk.onClick);
    root.append(tri);
  }
  const cross = svg('line', { class: 'cross', y1: m.t, y2: m.t + ph, visibility: 'hidden' });
  const brush = svg('rect', { class: 'brush', y: m.t, height: ph, visibility: 'hidden' });
  const hit = svg('rect', { x: m.l, y: m.t, width: pw, height: ph, fill: 'transparent',
    style: opts.onRange ? 'cursor:crosshair' : '' });
  root.append(brush, cross, hit);
  wrap.append(root);

  const px = e => { const r = root.getBoundingClientRect(); return ((e.clientX - r.left) / r.width) * W; };
  let dragFrom = null;
  hit.addEventListener('mousemove', e => {
    const x = Math.min(Math.max(px(e), m.l), m.l + pw - 0.01);
    const i = Math.floor((x - m.l) / bw);
    cross.setAttribute('x1', m.l + (i + 0.5) * bw); cross.setAttribute('x2', m.l + (i + 0.5) * bw);
    cross.setAttribute('visibility', 'visible');
    if (dragFrom != null) {
      brush.setAttribute('x', Math.min(dragFrom, x)); brush.setAttribute('width', Math.abs(x - dragFrom));
      brush.setAttribute('visibility', 'visible');
    }
    const rows = series.filter(s => s.values[i]).slice().reverse().map(s => h('div', { class: 'row' },
      h('span', null, h('i', { style: { background: protoColor(s.name) } }), s.name),
      h('b', null, metric === 'bytes' ? bytes(s.values[i]) : num(s.values[i]))));
    showTip(e, h('div', null,
      h('div', { class: 't' }, `${utc(tAt(i))}${data.width > 1 ? ` (+${data.width}s)` : ''}`),
      rows.length ? rows : 'no traffic',
      rows.length > 1 ? h('div', { class: 'row', style: { marginTop: '3px', borderTop: '1px solid var(--line)', paddingTop: '3px' } },
        h('span', null, 'Total'), h('b', null, metric === 'bytes' ? bytes(totals[i]) : num(totals[i]))) : null));
  });
  hit.addEventListener('mouseleave', () => { cross.setAttribute('visibility', 'hidden'); hideTip(); });
  if (opts.onRange) {
    hit.addEventListener('mousedown', e => { dragFrom = px(e); e.preventDefault(); });
    window.addEventListener('mouseup', function up(e) {
      if (!root.isConnected) { window.removeEventListener('mouseup', up); return; }
      if (dragFrom == null) return;
      const x = Math.min(Math.max(px(e), m.l), m.l + pw);
      const a = Math.min(dragFrom, x), b = Math.max(dragFrom, x);
      dragFrom = null; brush.setAttribute('visibility', 'hidden');
      if (b - a < 5) return;
      const span = n * data.width;
      opts.onRange(data.start + ((a - m.l) / pw) * span, data.start + ((b - m.l) / pw) * span);
    });
    hit.addEventListener('dblclick', () => opts.onRange(null));
  }
}

/** Sorted horizontal bars with direct value labels. items: [{label, value, text, href, title}] */
export function barList(items, opts = {}) {
  if (!items.length) return h('div', { class: 'empty' }, opts.empty || 'Nothing to show.');
  const max = Math.max(...items.map(i => i.value), 1);
  const box = h('div', { class: 'bars' });
  for (const it of items) {
    box.append(
      h('div', { class: 'lbl' + (opts.mono ? ' mono' : ''), title: it.title || it.label },
        it.href ? h('a', { href: it.href }, it.label) : it.label, it.extra || null),
      h('div', { class: 'track' }, h('div', { class: 'fill', style: {
        width: `${Math.max((it.value / max) * 100, 0.5)}%`, background: it.color || null } })),
      h('div', { class: 'val' }, it.text));
  }
  return box;
}

/** Two-series (sent / received) bar chart for a single host; shared axis. */
export function activityChart(container, t) {
  clear(container);
  const n = t.buckets;
  if (!n) { container.append(h('div', { class: 'empty' }, 'No activity.')); return; }
  container.append(legend([{ label: 'Sent', color: 'var(--s1)' }, { label: 'Received', color: 'var(--s2)' }]));
  const wrap = h('div', { class: 'chart' }); container.append(wrap);
  const W = Math.max(320, container.clientWidth || 700), H = 150, m = { l: 52, r: 8, t: 6, b: 20 };
  const pw = W - m.l - m.r, ph = H - m.t - m.b, mid = m.t + ph / 2, bw = pw / n;
  const ymax = niceMax(Math.max(...t.sent, ...t.received));
  const root = svg('svg', { viewBox: `0 0 ${W} ${H}`, height: H, role: 'img', 'aria-label': 'Bytes sent and received over time' });
  root.append(svg('line', { class: 'axis-line', x1: m.l, x2: W - m.r, y1: mid, y2: mid }));
  root.append(svg('text', { x: m.l - 6, y: m.t + 8, 'text-anchor': 'end' }, bytes(ymax)));
  root.append(svg('text', { x: m.l - 6, y: m.t + ph, 'text-anchor': 'end' }, bytes(ymax)));
  root.append(svg('text', { x: m.l, y: H - 5 }, utc(t.start, false)));
  root.append(svg('text', { x: W - m.r, y: H - 5, 'text-anchor': 'end' }, utc(t.start + n * t.width, false)));
  const gap = bw > 4 ? 1.5 : 0.4;
  for (let i = 0; i < n; i++) {
    const s = (t.sent[i] / ymax) * (ph / 2 - 1), r = (t.received[i] / ymax) * (ph / 2 - 1);
    if (t.sent[i]) root.append(svg('rect', { x: m.l + i * bw + gap / 2, y: mid - 1 - Math.max(s, 1), width: Math.max(bw - gap, 0.6), height: Math.max(s, 1), fill: 'var(--s1)' }));
    if (t.received[i]) root.append(svg('rect', { x: m.l + i * bw + gap / 2, y: mid + 1, width: Math.max(bw - gap, 0.6), height: Math.max(r, 1), fill: 'var(--s2)' }));
  }
  const hit = svg('rect', { x: m.l, y: m.t, width: pw, height: ph, fill: 'transparent' });
  hit.addEventListener('mousemove', e => {
    const r = root.getBoundingClientRect();
    const i = Math.min(n - 1, Math.max(0, Math.floor((((e.clientX - r.left) / r.width) * W - m.l) / bw)));
    showTip(e, h('div', null, h('div', { class: 't' }, utc(t.start + i * t.width)),
      h('div', { class: 'row' }, h('span', null, h('i', { style: { background: 'var(--s1)' } }), 'Sent'), h('b', null, bytes(t.sent[i]))),
      h('div', { class: 'row' }, h('span', null, h('i', { style: { background: 'var(--s2)' } }), 'Received'), h('b', null, bytes(t.received[i])))));
  });
  hit.addEventListener('mouseleave', hideTip);
  root.append(hit); wrap.append(root);
}
