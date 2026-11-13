// DOM and formatting helpers. All capture-derived text is inserted as text
// nodes (never as HTML), so hostile strings inside a capture cannot inject
// markup into the interface.

export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'style' && typeof v === 'object') {
        for (const [p, val] of Object.entries(v)) {
          if (p.startsWith('--')) el.style.setProperty(p, val); else el.style[p] = val;
        }
      }
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (k === 'href') el.setAttribute('href', safeHref(v));
      else el.setAttribute(k, v === true ? '' : v);
    }
  }
  append(el, children);
  return el;
}
function append(el, children) {
  for (const c of children) {
    if (c == null || c === false) continue;
    if (Array.isArray(c)) append(el, c);
    else el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}
function safeHref(v) {
  const s = String(v);
  return (s.startsWith('#') || s.startsWith('/api/')) ? s : '#';
}
const SVG_NS = 'http://www.w3.org/2000/svg';
export function svg(tag, attrs, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  if (attrs) for (const [k, v] of Object.entries(attrs)) if (v != null) el.setAttribute(k, v);
  for (const c of children) if (c != null) el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return el;
}
export function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }
/** Replace an element's children; null/false/arrays are handled like h(). */
export function fill(el, ...children) { clear(el); append(el, children); return el; }

export function bytes(n) {
  if (n == null) return '';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0; n = Number(n);
  while (Math.abs(n) >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return i === 0 ? `${n} B` : `${n.toFixed(n < 10 ? 2 : 1)} ${u[i]}`;
}
export function num(n) { return n == null ? '' : Number(n).toLocaleString('en-US'); }
export function compact(n) {
  n = Number(n) || 0;
  if (n >= 1e9) return (n / 1e9).toFixed(1) + 'B';
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e4) return (n / 1e3).toFixed(0) + 'k';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'k';
  return String(n);
}
export function duration(s) {
  if (s == null) return '';
  s = Number(s);
  if (s < 0.001) return s === 0 ? '0 s' : '<1 ms';
  if (s < 1) return `${(s * 1000).toFixed(0)} ms`;
  if (s < 120) return `${s.toFixed(s < 10 ? 2 : 1)} s`;
  if (s < 7200) return `${(s / 60).toFixed(1)} min`;
  return `${(s / 3600).toFixed(1)} h`;
}
export function utc(ts, withDate = true) {
  if (ts == null) return '';
  const iso = new Date(ts * 1000).toISOString();
  return withDate ? iso.slice(0, 19).replace('T', ' ') + ' UTC' : iso.slice(11, 19);
}
export function utcMs(ts) { return ts == null ? '' : new Date(ts * 1000).toISOString().slice(11, 23); }
export function rel(ts, start) { return ts == null ? '' : (ts - start).toFixed(6); }

const FLAG_BITS = [[2, 'SYN'], [1, 'FIN'], [4, 'RST'], [8, 'PSH'], [16, 'ACK'], [32, 'URG']];
export function tcpFlags(f) { return f == null ? '' : FLAG_BITS.filter(([b]) => f & b).map(([, n]) => n).join(' '); }

// Fixed protocol -> categorical slot mapping: colour follows the entity,
// never its rank, so a protocol keeps its colour across every chart.
const PROTO_SLOT = { TLS: 1, HTTP: 2, DNS: 3, TCP: 4, UDP: 5, ICMP: 6, SSH: 7, ARP: 8 };
export function protoColor(p) { const s = PROTO_SLOT[p]; return s ? `var(--s${s})` : 'var(--s-other)'; }
export function protoOrder(p) { return PROTO_SLOT[p] || 99; }
export function cssVar(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }

export function sevBadge(sev) { return h('span', { class: `sev ${sev}` }, sev); }
export function confLabel(c) { return c >= 0.7 ? 'high' : c >= 0.4 ? 'medium' : 'low'; }
export function confidence(c) {
  return h('span', { class: 'meter', title: 'How closely the observed data matches the pattern (not the probability of an attack)' },
    h('span', { class: 'bar' }, h('i', { style: { width: `${Math.round(c * 100)}%` } })),
    `confidence ${c.toFixed(2)} (${confLabel(c)})`);
}
export function appTag(app, by) {
  if (!app) return null;
  return h('span', { class: 'tag' + (by === 'port' ? ' inferred' : ''),
    title: by === 'port' ? 'Inferred from the port number only' : 'Identified from payload' }, app);
}

const tip = () => document.getElementById('tooltip');
export function showTip(evt, content) {
  const t = tip(); clear(t); t.append(content); t.hidden = false;
  const pad = 14, r = t.getBoundingClientRect();
  let x = evt.clientX + pad, y = evt.clientY + pad;
  if (x + r.width > innerWidth - 8) x = evt.clientX - r.width - pad;
  if (y + r.height > innerHeight - 8) y = evt.clientY - r.height - pad;
  t.style.left = `${Math.max(4, x)}px`; t.style.top = `${Math.max(4, y)}px`;
}
export function hideTip() { tip().hidden = true; }
export function debounce(fn, ms = 250) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }
export function enc(s) { return encodeURIComponent(s); }
