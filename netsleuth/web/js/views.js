// The capture pages. Each view receives { page, id, row, summary, route, go }
// and may return a cleanup function.
import { api } from './api.js';
import { h, clear, fill, bytes, num, duration, utc, utcMs, rel, tcpFlags, sevBadge, confidence, appTag,
         showTip, hideTip, debounce, enc, protoColor } from './util.js';
import { dataTable, pager, kv, filterBar, section, errorBox, loading } from './components.js';
import { timelineChart, barList, activityChart, legend } from './charts.js';
import { Topology } from './topology.js';

const hostLink = (id, ip) => h('a', { href: `#/c/${id}/hosts/${enc(ip)}`, class: 'mono' }, ip);
const head = (title, sub, ...right) => h('div', { class: 'page-head' },
  h('div', null, h('h1', null, title), sub ? h('p', null, sub) : null), right.length ? h('div', { class: 'toolbar', style: { margin: 0 } }, ...right) : null);
const tile = (value, label, sub) => h('div', { class: 'tile' }, h('div', { class: 'v' }, value),
  h('div', { class: 'l' }, label), sub ? h('div', { class: 's' }, sub) : null);
const names = list => (list && list.length ? list.slice(0, 2).join(', ') : '');
const scopeTag = s => (s ? h('span', { class: 'tag' }, s) : null);

function warnings(summary) {
  const w = summary.warnings || [];
  if (!w.length) return null;
  return h('div', { class: 'notice', role: 'note' }, h('b', null, 'Analysis notes: '),
    w.length === 1 ? w[0] : h('ul', { style: { margin: '4px 0 0', paddingLeft: '18px' } }, w.map(x => h('li', null, x))));
}

// ---------------------------------------------------------------- overview ---
async function overview({ page, id, summary: s, go }) {
  const [ov, tl] = await Promise.all([api.get(id, 'overview'), api.get(id, 'timeline', { buckets: 160 })]);
  const sev = s.findings_by_severity || {};
  const scopes = s.hosts_by_scope || {};
  const protoAgg = new Map();
  for (const p of ov.protocols) {
    const key = p.app || p.transport || p.net;
    const a = protoAgg.get(key) || { label: key, packets: 0, bytes: 0, inferred: false };
    a.packets += p.packets; a.bytes += p.bytes || 0; a.inferred = a.inferred || p.app_by === 'port';
    protoAgg.set(key, a);
  }
  const protos = [...protoAgg.values()].sort((a, b) => b.bytes - a.bytes).slice(0, 12);
  const tlBox = h('div');
  const top = ov.findings.slice(0, 6);

  fill(page, 
    head('Overview', `${s.filename} · ${utc(s.start_ts)} → ${utc(s.end_ts)}`),
    warnings(s),
    h('div', { class: 'tiles' },
      tile(num(s.packets), 'Packets', bytes(s.bytes)),
      tile(duration(s.duration), 'Duration', (s.link_types || []).join(', ')),
      tile(num(s.hosts), 'Hosts', `${scopes.internal || 0} internal · ${scopes.external || 0} external`),
      tile(num(s.flows), 'Connections', Object.entries(s.flows_by_proto || {}).map(([k, v]) => `${num(v)} ${k}`).join(' · ')),
      tile(num(s.findings), 'Findings', ['high', 'medium', 'low', 'info'].filter(k => sev[k]).map(k => `${sev[k]} ${k}`).join(' · ') || 'none'),
      tile(num(s.malformed_packets), 'Malformed packets', s.fragments ? `${num(s.fragments)} fragments` : `${s.format} file`)),
    h('div', { class: 'grid wide-left', style: { marginBottom: '14px' } },
      section('Traffic over time', tlBox,
        h('div', { class: 'hint', style: { margin: '6px 0 0' } }, 'Bytes per interval, stacked by protocol. ',
          h('a', { href: `#/c/${id}/timeline` }, 'Open the interactive timeline →'))),
      section('Findings to review',
        top.length ? top.map(f => h('a', { href: `#/c/${id}/alerts?f=${f.id}`,
          style: { display: 'block', padding: '7px 0', borderTop: '1px solid var(--line-soft)', color: 'inherit', textDecoration: 'none' } },
          h('div', { style: { display: 'flex', gap: '10px', alignItems: 'baseline' } }, sevBadge(f.severity),
            h('span', { style: { fontWeight: 600 } }, f.title)),
          h('div', { class: 'muted', style: { fontSize: '12px' } }, f.summary)))
          : h('div', { class: 'empty' }, 'No detector matched this capture. That is not proof the traffic is benign.'),
        ov.findings.length > top.length ? h('a', { href: `#/c/${id}/alerts`, style: { display: 'block', marginTop: '8px' } },
          `All ${ov.findings.length} findings →`) : null)),
    h('div', { class: 'grid c3' },
      section('Protocol distribution', barList(protos.map(p => ({ label: p.label, value: p.bytes,
        text: `${bytes(p.bytes)} · ${num(p.packets)} pkts`, color: protoColor(p.label),
        href: `#/c/${id}/flows?q=${enc('app:' + p.label)}`,
        title: p.inferred ? `${p.label} (includes flows labelled by port only)` : p.label })))),
      section('Top talkers', barList(ov.top_hosts.map(x => ({ label: x.ip, value: x.bytes_out + x.bytes_in,
        text: bytes(x.bytes_out + x.bytes_in), href: `#/c/${id}/hosts/${enc(x.ip)}`,
        title: `${x.ip} ${names(x.names)} (${x.scope})` })), { mono: true })),
      section('Most queried DNS names', barList(ov.top_domains.map(d => ({ label: d.qname, value: d.queries,
        text: `${d.queries} · ${d.clients} client${d.clients === 1 ? '' : 's'}` })), { mono: true, empty: 'No DNS traffic.' }))),
    h('div', { class: 'grid c2', style: { marginTop: '14px' } },
      section('Top conversations', dataTable([
        { label: 'Endpoint A', render: r => hostLink(id, r.a) }, { label: 'Endpoint B', render: r => hostLink(id, r.b) },
        { label: 'Conns', cls: 'r', render: r => num(r.flows) }, { label: 'Bytes', cls: 'r', render: r => bytes(r.bytes) },
        { label: 'Protocols', key: 'protos' }], ov.top_conversations,
        { onRow: r => go(`c/${id}/flows`, { q: `ip:${r.a} ip:${r.b}` }) })),
      section('Top services', dataTable([
        { label: 'Service', render: r => `${r.port}/${r.proto.toLowerCase()}` }, { label: 'Protocol', render: r => r.app || '' },
        { label: 'Conns', cls: 'r', render: r => num(r.flows) }, { label: 'Clients', cls: 'r', key: 'clients' },
        { label: 'Servers', cls: 'r', key: 'servers' }, { label: 'Bytes', cls: 'r', render: r => bytes(r.bytes) }],
        ov.top_services, { onRow: r => go(`c/${id}/flows`, { q: `proto:${r.proto} dport:${r.port}` }) }))));
  timelineChart(tlBox, tl, { metric: 'bytes', height: 180 });
  const onResize = debounce(() => timelineChart(tlBox, tl, { metric: 'bytes', height: 180 }), 150);
  window.addEventListener('resize', onResize);
  return () => window.removeEventListener('resize', onResize);
}

// -------------------------------------------------------------- detections ---
function evidenceValue(id, key, v) {
  if (key === 'flow_ids' && Array.isArray(v)) {
    return h('span', null, v.slice(0, 12).map((f, i) => [i ? ', ' : '', h('a', { href: `#/c/${id}/flows?q=${enc('id:' + f)}` }, `#${f}`)]),
      v.length > 12 ? ` … (+${v.length - 12})` : '');
  }
  if (Array.isArray(v)) {
    if (v.length && typeof v[0] === 'object') return h('div', null, v.map(o => h('div', null, Object.entries(o).filter(([, x]) => x != null).map(([k, x]) => `${k.replace(/_/g, ' ')}: ${x}`).join(' · '))));
    return v.join(', ');
  }
  if (v && typeof v === 'object') return Object.entries(v).map(([k, x]) => `${k.replace(/_/g, ' ')}: ${x}`).join(' · ');
  if (typeof v === 'boolean') return v ? 'yes' : 'no';
  return String(v);
}

function findingCard(id, f, open) {
  const ev = Object.entries(f.evidence || {}).filter(([, v]) => v != null && !(Array.isArray(v) && !v.length));
  return h('details', { class: `finding ${f.severity}`, open: open || null, id: `finding-${f.id}` },
    h('summary', null, sevBadge(f.severity),
      h('div', null, h('div', { class: 'title' }, f.title), h('div', { class: 'sum' }, f.summary)),
      h('div', { style: { textAlign: 'right' } }, confidence(f.confidence),
        h('div', { class: 'muted', style: { fontSize: '11.5px' } }, f.category))),
    h('div', { class: 'body' },
      h('h3', null, 'Why this was flagged'), h('p', null, f.explanation),
      h('h3', null, 'Evidence'),
      h('div', { class: 'ev' }, kv(ev.map(([k, v]) => [k.replace(/_/g, ' '), evidenceValue(id, k, v)]))),
      h('div', { class: 'muted', style: { margin: '6px 0' } },
        f.first_ts != null ? `Observed ${utc(f.first_ts)} → ${utc(f.last_ts)} · ` : '', 'Hosts: ',
        f.hosts.slice(0, 8).map((ip, i) => [i ? ', ' : '', hostLink(id, ip)])),
      h('h3', null, 'Benign explanations to rule out'), h('ul', null, f.caveats.map(c => h('li', null, c))),
      h('h3', null, 'Recommended next steps'), h('ul', null, f.recommendations.map(c => h('li', null, c))),
      f.mitre.length ? h('div', { class: 'muted' }, 'Possibly related ATT&CK techniques: ',
        f.mitre.map((m, i) => [i ? ' ' : '', h('span', { class: 'tag' }, `${m.id} ${m.name}`)])) : null));
}

async function alerts({ page, id, route }) {
  const all = await api.get(id, 'findings');
  const focus = Number(route.params.get('f')) || null;
  let sevFilter = '', catFilter = '', text = '';
  const list = h('div');
  const cats = [...new Set(all.map(f => f.category))].sort();
  const counts = k => all.filter(f => f.severity === k).length;
  function draw() {
    const q = text.toLowerCase();
    const rows = all.filter(f => (!sevFilter || f.severity === sevFilter) && (!catFilter || f.category === catFilter)
      && (!q || `${f.title} ${f.summary} ${f.hosts.join(' ')} ${f.detector}`.toLowerCase().includes(q)));
    clear(list);
    if (!rows.length) list.append(h('div', { class: 'card empty' }, all.length ? 'No findings match the filters.'
      : 'No detector matched this capture. That is not proof the traffic is benign.'));
    rows.forEach(f => list.append(findingCard(id, f, f.id === focus)));
  }
  const seg = h('div', { class: 'seg', role: 'group', 'aria-label': 'Severity filter' },
    [['', `All ${all.length}`], ...['high', 'medium', 'low', 'info'].map(k => [k, `${k} ${counts(k)}`])].map(([k, label]) =>
      h('button', { class: k === sevFilter ? 'on' : null, onclick: e => {
        sevFilter = k; [...seg.children].forEach(b => b.classList.remove('on')); e.target.classList.add('on'); draw(); } }, label)));
  fill(page, 
    head('Detections', 'Heuristic findings with evidence, severity and confidence. Expand a finding for details.'),
    h('div', { class: 'notice' }, 'Each finding describes traffic that matches a pattern associated with malicious activity. ',
      h('b', null, 'Severity'), ' is how much it would matter if confirmed; ', h('b', null, 'confidence'),
      ' is how closely the data matches the pattern. Neither is a verdict - every finding lists benign explanations to rule out.'),
    h('div', { class: 'toolbar' }, seg,
      h('select', { class: 'input', 'aria-label': 'Category', onchange: e => { catFilter = e.target.value; draw(); } },
        h('option', { value: '' }, 'All categories'), cats.map(c => h('option', { value: c }, c))),
      h('input', { class: 'input', type: 'search', placeholder: 'Search findings or hosts…', style: { flex: '1 1 200px' },
        oninput: debounce(e => { text = e.target.value; draw(); }, 150) })),
    list);
  draw();
  if (focus) { const el = document.getElementById(`finding-${focus}`); if (el) el.scrollIntoView({ block: 'start' }); }
}

// ---------------------------------------------------------------- topology ---
async function topology({ page, id }) {
  let data = await api.get(id, 'topology', { max_edges: 300 });
  let internalOnly = false;
  const canvas = h('canvas', { role: 'img', 'aria-label': 'Network topology graph. A table of the same hosts is available on the Hosts page.' });
  const panel = h('div', { class: 'topo-panel', hidden: true });
  const note = h('span', { class: 'muted' });
  function setNote() {
    note.textContent = data.truncated
      ? `Showing the ${data.edges.length} busiest of ${num(data.total_edges)} host pairs.`
      : `${data.nodes.length} hosts · ${data.edges.length} host pairs`;
  }
  const topo = new Topology(canvas, {
    onHover: (n, e) => {
      if (!n) { hideTip(); return; }
      showTip(e, h('div', null, h('div', { class: 'mono' }, n.ip), n.names && n.names.length ? h('div', { class: 't' }, names(n.names)) : null,
        h('div', { class: 'row' }, h('span', null, n.scope), h('b', null, bytes(n.total))),
        n.max_severity ? h('div', null, sevBadge(n.max_severity), ` ${n.findings} finding(s)`) : null));
    },
    onSelect: async n => {
      if (!n) { panel.hidden = true; return; }
      panel.hidden = false;
      fill(panel, h('div', { class: 'drawer-head' }, h('b', { class: 'mono' }, n.ip),
        h('button', { class: 'btn small', onclick: () => { panel.hidden = true; topo.selected = null; topo.draw(); } }, 'Close')),
        h('span', { class: 'spinner' }));
      try {
        const host = await api.get(id, `hosts/${enc(n.ip)}`);
        fill(panel, 
          h('div', { class: 'drawer-head' }, h('b', { class: 'mono' }, n.ip),
            h('button', { class: 'btn small', onclick: () => { panel.hidden = true; topo.selected = null; topo.draw(); } }, 'Close')),
          kv([['Scope', host.scope], ['Names', names(host.names)], ['MAC', host.mac], ['Sent', bytes(host.bytes_out)],
            ['Received', bytes(host.bytes_in)], ['Peers', host.peers], ['Services', (host.services || []).slice(0, 6).join(', ')]]),
          host.finding_list.length ? h('h3', null, 'Findings') : null,
          host.finding_list.slice(0, 6).map(f => h('a', { href: `#/c/${id}/alerts?f=${f.id}`, style: { display: 'block', padding: '3px 0' } },
            sevBadge(f.severity), ' ', f.title)),
          h('h3', null, 'Top peers'),
          host.peer_list.slice(0, 6).map(p => h('div', { style: { display: 'flex', justifyContent: 'space-between' } },
            hostLink(id, p.peer), h('span', { class: 'muted num' }, bytes(p.bytes_sent + p.bytes_received)))),
          h('div', { style: { marginTop: '12px', display: 'flex', gap: '8px' } },
            h('a', { class: 'btn small primary', href: `#/c/${id}/hosts/${enc(n.ip)}` }, 'Investigate host'),
            h('a', { class: 'btn small', href: `#/c/${id}/flows?q=${enc('ip:' + n.ip)}` }, 'Connections')));
      } catch (err) { fill(panel, errorBox(err)); }
    },
  });
  fill(page, 
    head('Topology', 'Who talked to whom. Node size is traffic volume; a coloured ring marks hosts with findings.',
      h('input', { class: 'input', type: 'search', placeholder: 'Highlight address or name…',
        oninput: e => { topo.highlight = e.target.value.trim(); topo.draw(); } }),
      h('select', { class: 'input', 'aria-label': 'Detail level', onchange: async e => {
        data = await api.get(id, 'topology', { max_edges: e.target.value }); setNote(); topo.setData(data, { internalOnly }); } },
        [150, 300, 600, 1200].map(n => h('option', { value: n, selected: n === 300 || null }, `Top ${n} pairs`))),
      h('label', { class: 'dim' }, h('input', { type: 'checkbox', onchange: e => { internalOnly = e.target.checked; topo.setData(data, { internalOnly }); } }), ' Internal only'),
      h('div', { class: 'seg' }, h('button', { onclick: () => topo.zoom(1.3), 'aria-label': 'Zoom in' }, '+'),
        h('button', { onclick: () => topo.zoom(1 / 1.3), 'aria-label': 'Zoom out' }, '−'),
        h('button', { onclick: () => { topo.fit(); topo.draw(); } }, 'Fit'))),
    h('div', { class: 'topo' }, canvas, panel,
      h('div', { class: 'topo-legend' }, h('div', { class: 'legend' },
        h('span', null, h('i', { style: { background: 'var(--s1)', borderRadius: '50%' } }), 'Internal'),
        h('span', null, h('i', { style: { background: 'var(--s2)', borderRadius: '50%' } }), 'External'),
        h('span', null, h('i', { style: { background: 'var(--s-other)', borderRadius: '50%' } }), 'Multicast / other'),
        h('span', null, h('i', { class: 'ring', style: { '--c': 'var(--sev-high)' } }), 'High'),
        h('span', null, h('i', { class: 'ring', style: { '--c': 'var(--sev-medium)' } }), 'Medium'),
        h('span', null, h('i', { class: 'ring', style: { '--c': 'var(--sev-low)' } }), 'Low finding')))),
    h('div', { class: 'pager' }, note, h('span', null, 'Drag to pan, scroll to zoom, click a node for details.')));
  setNote();
  topo._resize(); topo.setData(data, { internalOnly });
  return () => topo.destroy();
}

// ---------------------------------------------------------------- timeline ---
async function timeline({ page, id, summary: s, go }) {
  const findings = await api.get(id, 'findings');
  let metric = 'bytes', range = null, data = null;
  const chartBox = h('div'), info = h('div', { class: 'toolbar' }), below = h('div');
  const markers = findings.filter(f => f.first_ts != null && f.severity !== 'info').map(f => ({
    ts: f.first_ts, severity: f.severity, title: f.title, onClick: () => go(`c/${id}/alerts`, { f: f.id }) }));
  async function load() {
    data = await api.get(id, 'timeline', { buckets: 240, t0: range ? range[0] : null, t1: range ? range[1] : null });
    draw();
    clear(info);
    if (range) {
      info.append(h('span', { class: 'tag' }, `${utc(range[0])} → ${utc(range[1], false)} (${duration(range[1] - range[0])})`),
        h('button', { class: 'btn small', onclick: () => { range = null; load(); } }, 'Reset zoom'),
        h('a', { class: 'btn small', href: `#/c/${id}/packets?t0=${range[0].toFixed(3)}&t1=${range[1].toFixed(3)}` }, 'Packets in range'),
        h('a', { class: 'btn small', href: `#/c/${id}/flows?t0=${range[0].toFixed(3)}&t1=${range[1].toFixed(3)}` }, 'Connections in range'));
    } else info.append(h('span', { class: 'muted' }, 'Drag across the chart to zoom into a time range; double-click to reset. Triangles mark when findings begin.'));
    loadBelow();
  }
  function draw() {
    timelineChart(chartBox, data, { metric, height: 260, markers,
      onRange: (a, b) => { range = a == null ? null : [a, b]; load(); } });
  }
  async function loadBelow() {
    const p = { limit: 12, sort: 'bytes', order: 'desc', t0: range ? range[0] : null, t1: range ? range[1] : null };
    const fl = await api.get(id, 'flows', p);
    const inRange = findings.filter(f => f.first_ts != null && (!range || (f.last_ts >= range[0] && f.first_ts <= range[1])));
    fill(below, h('div', { class: 'grid c2' },
      section(`Largest connections ${range ? 'in range' : 'in capture'} (${num(fl.total)} total)`, flowTable(id, fl.items, { compact: true,
        onRow: r => go(`c/${id}/flows`, { q: `id:${r.id}` }) })),
      section(`Findings ${range ? 'active in range' : ''} (${inRange.length})`,
        inRange.length ? inRange.slice(0, 12).map(f => h('a', { href: `#/c/${id}/alerts?f=${f.id}`,
          style: { display: 'flex', gap: '10px', padding: '5px 0', borderTop: '1px solid var(--line-soft)', color: 'inherit' } },
          sevBadge(f.severity), h('span', null, f.title), h('span', { class: 'muted', style: { marginLeft: 'auto' } }, utc(f.first_ts, false))))
          : h('div', { class: 'empty' }, 'None.'))));
  }
  const seg = h('div', { class: 'seg' }, ['bytes', 'packets'].map(mt => h('button', { class: mt === metric ? 'on' : null,
    onclick: e => { metric = mt; [...seg.children].forEach(b => b.classList.remove('on')); e.target.classList.add('on'); draw(); } }, mt)));
  fill(page, head('Timeline', `${utc(s.start_ts)} → ${utc(s.end_ts)} · ${duration(s.duration)}`, seg),
    h('div', { class: 'card', style: { marginBottom: '14px' } }, chartBox), info, below);
  await load();
  const onResize = debounce(draw, 150);
  window.addEventListener('resize', onResize);
  return () => window.removeEventListener('resize', onResize);
}

// ------------------------------------------------------------------- hosts ---
async function hosts(ctx) {
  const { page, id, route, go } = ctx;
  if (route.parts[3]) return hostDetail(ctx, route.parts[3]);
  const st = { q: route.params.get('q') || '', scope: route.params.get('scope') || '', sort: 'bytes', order: 'desc', offset: 0, limit: 100 };
  const box = h('div');
  async function load() {
    let res;
    try { res = await api.get(id, 'hosts', st); } catch (err) { fill(box, errorBox(err)); return; }
    fill(box, dataTable([
      { label: 'Address', sort: 'ip', render: r => hostLink(id, r.ip) },
      { label: 'Scope', render: r => scopeTag(r.scope) },
      { label: 'Names', render: r => names(r.names) },
      { label: 'Findings', sort: 'severity', render: r => (r.findings ? h('span', null, sevBadge(r.max_severity), ` ${r.findings}`) : '') },
      { label: 'Sent', cls: 'r', sort: 'bytes_out', render: r => bytes(r.bytes_out) },
      { label: 'Received', cls: 'r', sort: 'bytes_in', render: r => bytes(r.bytes_in) },
      { label: 'Packets', cls: 'r', sort: 'packets', render: r => num(r.pkts_out + r.pkts_in) },
      { label: 'Conns', cls: 'r', sort: 'flows', render: r => num(r.flows_out + r.flows_in) },
      { label: 'Peers', cls: 'r', sort: 'peers', key: 'peers' },
      { label: 'Services offered', render: r => (r.services || []).slice(0, 4).join(', ') },
      { label: 'MAC', cls: 'mono', key: 'mac' }],
      res.items, { sort: st.sort, order: st.order, onRow: r => go(`c/${id}/hosts/${enc(r.ip)}`),
        onSort: k => { if (st.sort === k) st.order = st.order === 'asc' ? 'desc' : 'asc'; else { st.sort = k; st.order = 'desc'; } st.offset = 0; load(); } }),
      pager(res.total, st.limit, st.offset, o => { st.offset = o; load(); }));
  }
  fill(page, head('Hosts', 'Every address seen in the capture. Click a host to investigate it.'),
    h('div', { class: 'toolbar' },
      h('input', { class: 'input', type: 'search', value: st.q, placeholder: 'Search address, name or MAC…', style: { flex: '1 1 260px' },
        oninput: debounce(e => { st.q = e.target.value.trim(); st.offset = 0; load(); }) }),
      h('select', { class: 'input', 'aria-label': 'Scope', onchange: e => { st.scope = e.target.value; st.offset = 0; load(); } },
        [['', 'All scopes'], ['internal', 'Internal'], ['external', 'External'], ['multicast', 'Multicast'], ['broadcast', 'Broadcast']]
          .map(([v, l]) => h('option', { value: v, selected: v === st.scope || null }, l)))),
    box);
  await load();
}

async function hostDetail({ page, id, go }, ip) {
  const x = await api.get(id, `hosts/${enc(ip)}`);
  const act = h('div');
  fill(page, 
    head(h('span', null, h('a', { href: `#/c/${id}/hosts`, class: 'muted', style: { fontWeight: 400 } }, 'Hosts / '), h('span', { class: 'mono', style: { fontSize: '19px' } }, x.ip)),
      [x.scope, names(x.names), x.mac].filter(Boolean).join(' · '),
      h('a', { class: 'btn', href: `#/c/${id}/flows?q=${enc('ip:' + x.ip)}` }, 'Connections'),
      h('a', { class: 'btn', href: `#/c/${id}/packets?q=${enc('ip:' + x.ip)}` }, 'Packets')),
    h('div', { class: 'tiles' },
      tile(bytes(x.bytes_out), 'Sent', `${num(x.pkts_out)} packets`), tile(bytes(x.bytes_in), 'Received', `${num(x.pkts_in)} packets`),
      tile(num(x.peers), 'Peers'), tile(num(x.flows_out), 'Connections opened'), tile(num(x.flows_in), 'Connections received'),
      tile(duration(x.last_ts - x.first_ts), 'Active for', `${utc(x.first_ts, false)} → ${utc(x.last_ts, false)}`)),
    x.finding_list.length ? section(`Findings involving this host (${x.finding_list.length})`,
      x.finding_list.map(f => h('a', { href: `#/c/${id}/alerts?f=${f.id}`,
        style: { display: 'block', padding: '6px 0', borderTop: '1px solid var(--line-soft)', color: 'inherit', textDecoration: 'none' } },
        h('div', { style: { display: 'flex', gap: '10px', alignItems: 'baseline' } }, sevBadge(f.severity), h('b', null, f.title), confidence(f.confidence)),
        h('div', { class: 'muted' }, f.summary)))) : null,
    h('div', { style: { height: '14px' } }),
    section('Activity over time', act),
    h('div', { class: 'grid c2', style: { marginTop: '14px' } },
      section('Peers', dataTable([
        { label: 'Peer', render: r => hostLink(id, r.peer) }, { label: 'Scope', render: r => scopeTag(r.scope) },
        { label: 'Names', render: r => names(r.names) }, { label: 'Conns', cls: 'r', render: r => num(r.flows) },
        { label: 'Sent', cls: 'r', render: r => bytes(r.bytes_sent) }, { label: 'Received', cls: 'r', render: r => bytes(r.bytes_received) }],
        x.peer_list, { onRow: r => go(`c/${id}/flows`, { q: `ip:${x.ip} ip:${r.peer}` }) })),
      h('div', { class: 'grid' },
        section('Ports this host contacted', dataTable([
          { label: 'Port', render: r => `${r.port}/${r.proto.toLowerCase()}` }, { label: 'Protocol', render: r => r.app || '' },
          { label: 'Conns', cls: 'r', render: r => num(r.flows) }, { label: 'Hosts', cls: 'r', key: 'hosts' },
          { label: 'Bytes', cls: 'r', render: r => bytes(r.bytes) }], x.ports_contacted.slice(0, 15),
          { onRow: r => go(`c/${id}/flows`, { q: `src:${x.ip} dport:${r.port}` }), empty: 'This host opened no connections.' })),
        section('Services this host answered on', dataTable([
          { label: 'Port', render: r => `${r.port}/${r.proto.toLowerCase()}` }, { label: 'Protocol', render: r => r.app || '' },
          { label: 'Conns', cls: 'r', render: r => num(r.flows) }, { label: 'Clients', cls: 'r', key: 'clients' },
          { label: 'Bytes', cls: 'r', render: r => bytes(r.bytes) }], x.ports_served.slice(0, 15),
          { onRow: r => go(`c/${id}/flows`, { q: `dst:${x.ip} dport:${r.port}` }), empty: 'No answered connections to this host.' })))),
    h('div', { class: 'grid c3', style: { marginTop: '14px' } },
      section('DNS names queried', dataTable([{ label: 'Name', cls: 'mono', key: 'qname' }, { label: 'Type', key: 'qtype' },
        { label: 'Count', cls: 'r', key: 'count' }, { label: 'Result', key: 'rcode' }], x.dns_queries.slice(0, 20), { empty: 'No DNS queries.' })),
      section('HTTP requests', dataTable([{ label: 'Host', cls: 'mono', key: 'host' }, { label: 'Method', key: 'method' },
        { label: 'Count', cls: 'r', key: 'count' }, { label: 'User agent', key: 'user_agent' }], x.http, { empty: 'No cleartext HTTP.' })),
      section('TLS sessions', dataTable([{ label: 'Server name', cls: 'mono', render: r => r.sni || '(no SNI)' },
        { label: 'Destination', render: r => `${r.dst}:${r.dport}` }, { label: 'Version', key: 'version' },
        { label: 'Count', cls: 'r', key: 'count' }, { label: 'JA3', cls: 'mono', render: r => (r.ja3 || '').slice(0, 12) }], x.tls, { empty: 'No TLS handshakes.' }))));
  activityChart(act, x.timeline);
}

// ------------------------------------------------------------- connections ---
function flowTable(id, rows, opts = {}) {
  const cols = [
    { label: '#', cls: 'r', sort: 'id', key: 'id' },
    { label: 'Start', sort: 'first_ts', render: r => utcMs(r.first_ts) },
    { label: 'Source', sort: 'src', render: r => h('span', { class: 'mono' }, `${r.src}${r.sport ? ':' + r.sport : ''}`) },
    { label: 'Destination', sort: 'dst', render: r => h('span', { class: 'mono' }, `${r.dst}${r.dport ? ':' + r.dport : ''}`) },
    { label: 'Proto', render: r => r.proto },
    { label: 'App', sort: 'app', render: r => appTag(r.app, r.app_by) },
    { label: 'Name', render: r => r.sni || r.http_host || '' },
    { label: 'State', sort: 'state', render: r => r.state },
    { label: 'Duration', cls: 'r', sort: 'duration', render: r => duration(r.duration) },
    { label: 'Sent', cls: 'r', sort: 'bytes_fwd', render: r => bytes(r.bytes_fwd) },
    { label: 'Received', cls: 'r', sort: 'bytes_rev', render: r => bytes(r.bytes_rev) },
    { label: 'Pkts', cls: 'r', sort: 'packets', render: r => num(r.pkts_fwd + r.pkts_rev) }];
  return dataTable(opts.compact ? cols.filter(c => !['#', 'Name', 'Pkts', 'State'].includes(c.label)).map(c => ({ ...c, sort: null })) : cols, rows, opts);
}

async function flows({ page, id, route, go }) {
  const st = { q: route.params.get('q') || '', sort: 'first_ts', order: 'asc', offset: 0, limit: 100,
    t0: route.params.get('t0'), t1: route.params.get('t1') };
  const ov = await api.get(id, 'overview');
  const box = h('div'), drawer = h('div', { class: 'card drawer' }), split = h('div', { class: 'split closed' }, box);
  let selected = null;
  async function openFlow(fid) {
    selected = fid; split.classList.remove('closed'); if (!drawer.isConnected) split.append(drawer);
    fill(drawer, h('span', { class: 'spinner' }));
    let f;
    try { f = await api.get(id, `flows/${fid}`); } catch (err) { fill(drawer, errorBox(err)); return; }
    fill(drawer, 
      h('div', { class: 'drawer-head' }, h('h2', { style: { margin: 0 } }, `Connection #${f.id}`),
        h('button', { class: 'btn small', onclick: () => { drawer.remove(); split.classList.add('closed'); selected = null; } }, 'Close')),
      kv([
        ['Originator', h('span', null, hostLink(id, f.src), f.sport ? `:${f.sport}` : '', ' ', scopeTag(f.src_scope))],
        ['Responder', h('span', null, hostLink(id, f.dst), f.dport ? `:${f.dport}` : '', ' ', scopeTag(f.dst_scope))],
        ['Protocol', h('span', null, f.proto, ' ', appTag(f.app, f.app_by))],
        ['State', `${f.state}${ov.state_descriptions[f.state] ? ' - ' + ov.state_descriptions[f.state] : ''}`],
        ['Started', utc(f.first_ts)], ['Duration', duration(f.duration)],
        ['Sent', `${bytes(f.bytes_fwd)} in ${num(f.pkts_fwd)} packets (${bytes(f.payload_fwd)} payload)`],
        ['Received', `${bytes(f.bytes_rev)} in ${num(f.pkts_rev)} packets (${bytes(f.payload_rev)} payload)`],
        ['Retransmissions', f.proto === 'TCP' ? `${f.retrans} · ${f.ooo} sequence gap(s)` : null],
        ['Server name', f.sni || f.http_host], ['Detail', f.detail]]),
      f.tls.length ? [h('h3', null, 'TLS handshake'), kv([['SNI', f.tls[0].sni || '(none)'], ['Version', f.tls[0].version || '(server hello not seen)'],
        ['Client offered', f.tls[0].client_version], ['Cipher', f.tls[0].cipher], ['ALPN', f.tls[0].alpn],
        ['JA3', h('span', { class: 'mono' }, f.tls[0].ja3)], ['JA3S', h('span', { class: 'mono' }, f.tls[0].ja3s)]])] : null,
      f.http.length ? [h('h3', null, `HTTP (${f.http.length})`), f.http.slice(0, 20).map(t => h('div', { class: 'mono', style: { wordBreak: 'break-all', marginBottom: '4px' } },
        `${t.method || '(response only)'} ${t.host}${t.uri} → ${t.status || '?'}`, t.user_agent ? h('div', { class: 'muted' }, t.user_agent) : null))] : null,
      f.dns.length ? [h('h3', null, `DNS (${f.dns.length})`), f.dns.slice(0, 20).map(d => h('div', { class: 'mono', style: { wordBreak: 'break-all' } },
        `${d.qtype} ${d.qname} → ${d.rcode || 'no answer'}${d.answers && d.answers.length ? ' ' + d.answers.join(', ') : ''}`))] : null,
      h('h3', null, `Packets (first ${f.packets.length})`),
      h('div', { style: { maxHeight: '300px', overflow: 'auto' } }, f.packets.map(p => h('div', { class: 'mono', style: { whiteSpace: 'nowrap', fontSize: '11px' } },
        h('a', { href: `#/c/${id}/packets?q=${enc('flow:' + f.id)}&sel=${p.no}` }, `#${p.no}`), ' ',
        h('span', { class: 'muted' }, rel(p.ts, f.first_ts)), ' ', p.src === f.src ? '→' : '←', ' ', p.info))),
      h('div', { style: { marginTop: '10px' } }, h('a', { class: 'btn small', href: `#/c/${id}/packets?q=${enc('flow:' + f.id)}` }, 'All packets of this connection')));
    load(false);
  }
  async function load(reset = true) {
    let res;
    try { res = await api.get(id, 'flows', st); } catch (err) { fill(box, errorBox(err)); return; }
    fill(box, flowTable(id, res.items, { sort: st.sort, order: st.order, onRow: r => openFlow(r.id), isSelected: r => r.id === selected,
      onSort: k => { if (st.sort === k) st.order = st.order === 'asc' ? 'desc' : 'asc'; else { st.sort = k; st.order = 'desc'; } st.offset = 0; load(); },
      empty: 'No connections match this filter.' }),
      pager(res.total, st.limit, st.offset, o => { st.offset = o; load(); }));
    if (reset && res.total === 1) openFlow(res.items[0].id);
  }
  fill(page, head('Connections', 'Reconstructed TCP sessions and UDP/ICMP exchanges. Source is always the originator.'),
    filterBar(st.q, ['app:tls', 'state:S0', 'ip:10.0.5.77 dport:445', 'bytes>100000', 'scope:external -dport:443', 'name:example'],
      q => go(`c/${id}/flows`, { q, t0: st.t0, t1: st.t1 }), 'Filter connections, e.g. ip:10.0.0.5 dport:443 state:SF'),
    st.t0 ? h('div', { class: 'notice' }, `Limited to ${utc(Number(st.t0))} → ${utc(Number(st.t1), false)}. `,
      h('a', { href: `#/c/${id}/flows${st.q ? '?q=' + enc(st.q) : ''}` }, 'Remove time filter')) : null,
    split);
  await load();
}

// ----------------------------------------------------------------- packets ---
async function packets({ page, id, route, summary: s, go }) {
  const st = { q: route.params.get('q') || '', offset: Number(route.params.get('offset')) || 0, limit: 200,
    t0: route.params.get('t0'), t1: route.params.get('t1') };
  let selected = Number(route.params.get('sel')) || null;
  const box = h('div'), drawer = h('div', { class: 'card drawer' }), split = h('div', { class: 'split closed' }, box);
  async function openPacket(no) {
    selected = no; split.classList.remove('closed'); if (!drawer.isConnected) split.append(drawer);
    box.querySelectorAll('tr.sel').forEach(tr => tr.classList.remove('sel'));
    const tr = box.querySelector(`tr[data-no="${no}"]`); if (tr) tr.classList.add('sel');
    fill(drawer, h('span', { class: 'spinner' }));
    let p;
    try { p = await api.get(id, `packets/${no}`); } catch (err) { fill(drawer, errorBox(err)); return; }
    fill(drawer, 
      h('div', { class: 'drawer-head' }, h('h2', { style: { margin: 0 } }, `Packet #${p.no}`),
        h('button', { class: 'btn small', onclick: () => { drawer.remove(); split.classList.add('closed'); selected = null; } }, 'Close')),
      kv([['Time', `${utc(p.ts)} (+${rel(p.ts, s.start_ts)} s)`], ['Length', `${p.len} bytes on wire, ${p.caplen} captured`],
        ['Connection', p.flow_id ? h('a', { href: `#/c/${id}/flows?q=${enc('id:' + p.flow_id)}` }, `#${p.flow_id}`) : null], ['Summary', p.info]]),
      h('h3', null, 'Layers'),
      p.layers.map((l, i) => h('details', { class: 'layer', open: i === p.layers.length - 1 || null },
        h('summary', null, l.name, h('span', null, l.summary)), kv(l.fields.map(f => [f.name, h('span', { class: 'mono' }, f.value)])))),
      h('h3', null, `Bytes (${p.hex.bytes}${p.hex.truncated ? ', truncated view' : ''})`),
      h('div', { class: 'hex' }, p.hex.rows.map(r => [h('span', { class: 'o' }, r.offset), `  ${r.hex.padEnd(47)}  ${r.ascii}\n`])));
  }
  async function load() {
    let res;
    try { res = await api.get(id, 'packets', st); } catch (err) { fill(box, errorBox(err)); return; }
    const table = dataTable([
      { label: 'No.', cls: 'r', key: 'no' },
      { label: 'Time', cls: 'r mono', render: r => rel(r.ts, s.start_ts) },
      { label: 'Source', cls: 'mono', render: r => r.src || '' }, { label: 'Destination', cls: 'mono', render: r => r.dst || '' },
      { label: 'Protocol', render: r => h('span', { class: 'tag', style: { borderLeft: `3px solid ${protoColor(r.app || r.proto)}`, borderRadius: '2px' } }, r.app || r.proto) },
      { label: 'Length', cls: 'r', key: 'len' },
      { label: 'Info', render: r => r.info }], res.items,
      { onRow: r => openPacket(r.no), isSelected: r => r.no === selected, empty: 'No packets match this filter.' });
    [...table.querySelectorAll('tbody tr')].forEach((tr, i) => { if (res.items[i]) tr.dataset.no = res.items[i].no; });
    fill(box, table, pager(res.total, st.limit, st.offset, o => { st.offset = o; load(); box.scrollIntoView(); }));
  }
  fill(page, head('Packets', `${num(s.packets)} packets. Time is seconds since the first packet. Click a packet to dissect it.`),
    filterBar(st.q, ['proto:tcp flag:syn -flag:ack', 'app:dns', 'ip:10.0.5.23 port:443', 'len>1400', '"Client Hello"', '-proto:arp'],
      q => go(`c/${id}/packets`, { q, t0: st.t0, t1: st.t1 }), 'Filter packets, e.g. ip:10.0.0.5 port:53 or free text'),
    st.t0 ? h('div', { class: 'notice' }, `Limited to ${utc(Number(st.t0))} → ${utc(Number(st.t1), false)}. `,
      h('a', { href: `#/c/${id}/packets${st.q ? '?q=' + enc(st.q) : ''}` }, 'Remove time filter')) : null,
    split);
  await load();
  if (selected) openPacket(selected);
}

// ------------------------------------------------------------------ report ---
async function report({ page, id }) {
  fill(page, 
    head('Investigation report', 'Executive summary, hosts, communication patterns, findings with evidence and recommendations.',
      h('a', { class: 'btn primary', href: api.reportUrl(id, 'html', true) }, 'Download HTML'),
      h('a', { class: 'btn', href: api.reportUrl(id, 'md', true) }, 'Markdown'),
      h('a', { class: 'btn', href: api.reportUrl(id, 'json', true) }, 'JSON')),
    h('div', { class: 'hint' }, 'The HTML report is self-contained and prints cleanly to PDF from the browser.'),
    h('iframe', { class: 'report-frame', src: api.reportUrl(id, 'html'), title: 'Report preview',
      // scripts stay disabled in the frame; the report itself is served with default-src 'none'
      sandbox: 'allow-same-origin' }));
}

export const VIEWS = { overview, alerts, topology, timeline, hosts, flows, packets, report };
