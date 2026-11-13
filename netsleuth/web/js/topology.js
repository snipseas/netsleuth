// Force-directed network topology on a canvas: pan, zoom, drag, hover, select.
import { cssVar, bytes } from './util.js';

const SCOPE_VAR = { internal: '--s1', external: '--s2' };

export class Topology {
  constructor(canvas, { onSelect, onHover }) {
    this.canvas = canvas; this.ctx = canvas.getContext('2d');
    this.onSelect = onSelect; this.onHover = onHover;
    this.nodes = []; this.edges = []; this.view = { x: 0, y: 0, k: 1 };
    this.alpha = 0; this.hover = null; this.selected = null; this.highlight = '';
    this._bind(); this._resize();
    this._ro = new ResizeObserver(() => { this._resize(); this.draw(); });
    this._ro.observe(canvas);
  }
  destroy() { this._ro.disconnect(); cancelAnimationFrame(this._raf); this._dead = true; }

  setData(data, filter = {}) {
    const keep = n => !filter.internalOnly || n.scope === 'internal';
    const byIp = new Map();
    const prev = new Map(this.nodes.map(n => [n.ip, n]));
    const index = new Map(data.nodes.map(n => [n.ip, n]));
    const edges = data.edges.filter(e => {
      const a = index.get(e.a), b = index.get(e.b);
      return a && b && keep(a) && keep(b);
    });
    const used = new Set(); edges.forEach(e => { used.add(e.a); used.add(e.b); });
    const list = data.nodes.filter(n => used.has(n.ip));
    const maxBytes = Math.max(...list.map(n => n.bytes_out + n.bytes_in), 1);
    list.forEach((n, i) => {
      const old = prev.get(n.ip), ang = i * 2.399963, rad = 30 * Math.sqrt(i + 1);
      const node = { ...n, total: n.bytes_out + n.bytes_in,
        x: old ? old.x : Math.cos(ang) * rad, y: old ? old.y : Math.sin(ang) * rad, vx: 0, vy: 0, deg: 0,
        r: 5 + 17 * Math.sqrt((n.bytes_out + n.bytes_in) / maxBytes) };
      byIp.set(n.ip, node);
    });
    const maxE = Math.max(...edges.map(e => e.bytes), 1);
    this.edges = edges.map(e => {
      const s = byIp.get(e.a), t = byIp.get(e.b); s.deg++; t.deg++;
      return { ...e, s, t, w: 0.6 + 4.4 * Math.sqrt(e.bytes / maxE) };
    });
    this.nodes = [...byIp.values()];
    this.selected = this.selected && byIp.get(this.selected.ip) || null;
    // Pre-compute most of the layout synchronously so the graph appears
    // settled and centred immediately (and does not depend on animation
    // frames, which browsers throttle in background tabs).
    this.alpha = 1;
    const budget = this.nodes.length > 250 ? 120 : 260;
    for (let i = 0; i < budget; i++) this._tick();
    this.fit(); this._fitted = true; this.draw(); this._loop();
  }

  _loop() {
    if (this._running || this._dead) return;
    this._running = true;
    const step = () => {
      if (this._dead) return;
      // several simulation ticks per frame while hot, so layout settles fast
      const ticks = this.alpha > 0.3 ? 4 : 1;
      for (let i = 0; i < ticks && this.alpha > 0.005; i++) this._tick();
      if (!this._fitted && this.alpha < 0.5) { this.fit(); this._fitted = true; }
      this.draw();
      if (this.alpha > 0.005 || this._drag) this._raf = requestAnimationFrame(step);
      else this._running = false;
    };
    this._raf = requestAnimationFrame(step);
  }

  _tick() {
    const N = this.nodes, a = this.alpha;
    for (let i = 0; i < N.length; i++) {
      const p = N[i];
      for (let j = i + 1; j < N.length; j++) {
        const q = N[j];
        let dx = p.x - q.x, dy = p.y - q.y, d2 = dx * dx + dy * dy;
        if (d2 < 1) { dx = (Math.random() - 0.5); dy = (Math.random() - 0.5); d2 = 1; }
        if (d2 > 250000) continue;
        const f = (2600 * a) / d2, d = Math.sqrt(d2);
        const fx = (dx / d) * f, fy = (dy / d) * f;
        p.vx += fx; p.vy += fy; q.vx -= fx; q.vy -= fy;
      }
      p.vx -= p.x * 0.012 * a; p.vy -= p.y * 0.012 * a;      // gentle gravity
    }
    for (const e of this.edges) {
      const dx = e.t.x - e.s.x, dy = e.t.y - e.s.y, d = Math.sqrt(dx * dx + dy * dy) || 1;
      const rest = 70 + e.s.r + e.t.r + 6 * Math.min(Math.max(e.s.deg, e.t.deg), 12);
      const f = ((d - rest) / d) * 0.09 * a;
      const ws = 1 / Math.sqrt(e.s.deg), wt = 1 / Math.sqrt(e.t.deg);
      e.s.vx += dx * f * ws; e.s.vy += dy * f * ws; e.t.vx -= dx * f * wt; e.t.vy -= dy * f * wt;
    }
    for (const p of N) {
      if (p.fixed) { p.vx = p.vy = 0; continue; }
      p.vx *= 0.82; p.vy *= 0.82; p.x += p.vx; p.y += p.vy;
    }
    this.alpha *= 0.985;
  }

  fit() {
    if (!this.nodes.length) return;
    let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    for (const n of this.nodes) { x0 = Math.min(x0, n.x - n.r); x1 = Math.max(x1, n.x + n.r); y0 = Math.min(y0, n.y - n.r); y1 = Math.max(y1, n.y + n.r); }
    const w = this.canvas.clientWidth, hgt = this.canvas.clientHeight;
    const k = Math.min(2.2, 0.88 * Math.min(w / (x1 - x0 + 1), hgt / (y1 - y0 + 1)));
    this.view = { k, x: w / 2 - ((x0 + x1) / 2) * k, y: hgt / 2 - ((y0 + y1) / 2) * k };
  }

  _resize() {
    const dpr = window.devicePixelRatio || 1, c = this.canvas;
    c.width = Math.max(1, c.clientWidth * dpr); c.height = Math.max(1, c.clientHeight * dpr); this.dpr = dpr;
  }
  _world(e) {
    const r = this.canvas.getBoundingClientRect();
    return { x: (e.clientX - r.left - this.view.x) / this.view.k, y: (e.clientY - r.top - this.view.y) / this.view.k };
  }
  _pick(e) {
    const p = this._world(e); let best = null, bd = Infinity;
    for (const n of this.nodes) {
      const d = Math.hypot(n.x - p.x, n.y - p.y) - n.r;
      if (d < 6 / this.view.k && d < bd) { bd = d; best = n; }
    }
    return best;
  }
  _bind() {
    const c = this.canvas;
    c.addEventListener('mousedown', e => {
      const n = this._pick(e), p = this._world(e);
      this._drag = n ? { node: n, moved: false } : { pan: true, sx: e.clientX, sy: e.clientY, vx: this.view.x, vy: this.view.y, moved: false };
      if (n) { n.fixed = true; this._off = { x: n.x - p.x, y: n.y - p.y }; }
      c.classList.add('dragging');
    });
    window.addEventListener('mousemove', this._mm = e => {
      if (this._dead) { window.removeEventListener('mousemove', this._mm); return; }
      const d = this._drag;
      if (d && d.node) {
        const p = this._world(e); d.node.x = p.x + this._off.x; d.node.y = p.y + this._off.y; d.moved = true;
        this.alpha = Math.max(this.alpha, 0.25); this._loop();
      } else if (d && d.pan) {
        this.view.x = d.vx + e.clientX - d.sx; this.view.y = d.vy + e.clientY - d.sy;
        if (Math.abs(e.clientX - d.sx) + Math.abs(e.clientY - d.sy) > 3) d.moved = true;
        this.draw();
      } else if (e.target === c) {
        const n = this._pick(e);
        if (n !== this.hover) { this.hover = n; this.draw(); }
        this.onHover && this.onHover(n, e);
      }
    });
    window.addEventListener('mouseup', this._mu = e => {
      if (this._dead) { window.removeEventListener('mouseup', this._mu); return; }
      const d = this._drag; if (!d) return;
      this._drag = null; c.classList.remove('dragging');
      if (d.node) d.node.fixed = false;
      if (!d.moved) { this.selected = d.node || null; this.onSelect && this.onSelect(this.selected); this.draw(); }
    });
    c.addEventListener('mouseleave', () => { this.hover = null; this.onHover && this.onHover(null); this.draw(); });
    c.addEventListener('wheel', e => {
      e.preventDefault();
      const r = c.getBoundingClientRect(), mx = e.clientX - r.left, my = e.clientY - r.top;
      const k = Math.min(6, Math.max(0.08, this.view.k * Math.exp(-e.deltaY * 0.0015)));
      this.view.x = mx - ((mx - this.view.x) / this.view.k) * k;
      this.view.y = my - ((my - this.view.y) / this.view.k) * k; this.view.k = k; this.draw();
    }, { passive: false });
  }
  zoom(f) {
    const w = this.canvas.clientWidth / 2, hh = this.canvas.clientHeight / 2, k = Math.min(6, Math.max(0.08, this.view.k * f));
    this.view.x = w - ((w - this.view.x) / this.view.k) * k; this.view.y = hh - ((hh - this.view.y) / this.view.k) * k;
    this.view.k = k; this.draw();
  }

  draw() {
    const ctx = this.ctx, v = this.view, dpr = this.dpr;
    const col = { surface: cssVar('--surface'), line: cssVar('--text-3'), text: cssVar('--text'), text2: cssVar('--text-2'),
      other: cssVar('--s-other'), accent: cssVar('--accent') };
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, this.canvas.clientWidth, this.canvas.clientHeight);
    ctx.translate(v.x, v.y); ctx.scale(v.k, v.k);
    const focus = this.hover || this.selected;
    const near = focus ? new Set([focus]) : null;
    if (focus) for (const e of this.edges) { if (e.s === focus) near.add(e.t); if (e.t === focus) near.add(e.s); }
    const hl = this.highlight.toLowerCase();
    const matches = n => hl && (n.ip.includes(hl) || (n.names || []).some(x => x.toLowerCase().includes(hl)));
    ctx.lineCap = 'round';
    for (const e of this.edges) {
      const on = focus && (e.s === focus || e.t === focus);
      ctx.globalAlpha = focus ? (on ? 0.9 : 0.07) : 0.3;
      ctx.strokeStyle = on ? col.accent : col.line; ctx.lineWidth = e.w / Math.sqrt(v.k);
      ctx.beginPath(); ctx.moveTo(e.s.x, e.s.y); ctx.lineTo(e.t.x, e.t.y); ctx.stroke();
    }
    const labelled = [];
    for (const n of this.nodes) {
      const dim = (near && !near.has(n)) || (hl && !matches(n));
      ctx.globalAlpha = dim ? 0.2 : 1;
      ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, 6.2832);
      ctx.fillStyle = SCOPE_VAR[n.scope] ? cssVar(SCOPE_VAR[n.scope]) : col.other; ctx.fill();
      ctx.lineWidth = 2 / v.k; ctx.strokeStyle = col.surface; ctx.stroke();       // surface ring separates overlaps
      if (n.max_severity) {
        ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 3.5 / v.k, 0, 6.2832);
        ctx.lineWidth = 2.5 / v.k; ctx.strokeStyle = cssVar(`--sev-${n.max_severity}`); ctx.stroke();
      }
      if (n === this.selected) {
        ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 7 / v.k, 0, 6.2832);
        ctx.lineWidth = 1.5 / v.k; ctx.strokeStyle = col.text; ctx.stroke();
      }
      if (!dim && (n === focus || (near && near.has(n)) || matches(n) || n.max_severity || n.r * v.k > 11)) labelled.push(n);
    }
    // labels: screen-space font, skipped when they would collide
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.globalAlpha = 1;
    ctx.font = '11px system-ui, sans-serif'; ctx.textBaseline = 'middle';
    const boxes = [];
    labelled.sort((a, b) => (b === focus) - (a === focus) || b.r - a.r);
    for (const n of labelled) {
      const sx = n.x * v.k + v.x + n.r * v.k + 6, sy = n.y * v.k + v.y;
      const text = n.ip, w = ctx.measureText(text).width;
      const box = [sx - 2, sy - 8, sx + w + 2, sy + 8];
      if (n !== focus && boxes.some(b => box[0] < b[2] && box[2] > b[0] && box[1] < b[3] && box[3] > b[1])) continue;
      boxes.push(box);
      ctx.lineWidth = 3; ctx.strokeStyle = col.surface; ctx.strokeText(text, sx, sy);
      ctx.fillStyle = n === focus ? col.text : col.text2; ctx.fillText(text, sx, sy);
    }
  }
}
export function nodeSummary(n) { return `${n.ip} · ${bytes(n.total)}`; }
