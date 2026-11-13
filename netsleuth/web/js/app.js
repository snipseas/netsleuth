// Application shell: hash router, sidebar, capture library (upload / samples).
import { api } from './api.js';
import { h, clear, fill, bytes, num, duration, utc, hideTip } from './util.js';
import { errorBox, loading } from './components.js';
import { VIEWS } from './views.js';

const app = document.getElementById('app');
const NAV = [
  ['overview', 'Overview'], ['alerts', 'Detections'], ['topology', 'Topology'], ['timeline', 'Timeline'],
  ['hosts', 'Hosts'], ['flows', 'Connections'], ['packets', 'Packets'], ['report', 'Report'],
];
let cleanup = null;          // teardown hook of the current view
let current = null;          // { id, row } of the open capture
let version = '';

function parseRoute() {
  const raw = location.hash.replace(/^#\/?/, '');
  const [path, query] = raw.split('?');
  const parts = path.split('/').filter(Boolean).map(decodeURIComponent);
  return { parts, params: new URLSearchParams(query || '') };
}
export function go(path, params) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params || {})) if (v != null && v !== '') p.set(k, v);
  const qs = p.toString();
  location.hash = `#/${path}${qs ? `?${qs}` : ''}`;
}

const LOGO = () => {
  const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  s.setAttribute('viewBox', '0 0 32 32'); s.setAttribute('width', '22'); s.setAttribute('height', '22');
  s.innerHTML = '<circle cx="14" cy="14" r="8" fill="none" stroke="var(--accent)" stroke-width="3"/>'
    + '<path d="M20 20 27 27" stroke="var(--accent)" stroke-width="3" stroke-linecap="round"/>'
    + '<circle cx="14" cy="14" r="2.5" fill="var(--accent)"/>';   // static markup, no data
  return s;
};

function shell(route) {
  const page = route.parts[2] || 'overview';
  const side = h('aside', { class: 'sidebar' },
    h('a', { class: 'brand', href: '#/' }, LOGO(), 'NetSleuth'));
  if (current) {
    const s = current.row.summary || {};
    const sev = s.findings_by_severity || {};
    const urgent = (sev.high || 0) + (sev.medium || 0);
    side.append(
      h('div', { class: 'capture-chip' },
        h('div', { class: 'name', title: current.row.filename }, current.row.filename),
        h('div', { class: 'meta' }, `${num(s.packets)} packets · ${bytes(s.bytes)} · ${duration(s.duration)}`)),
      h('nav', { class: 'nav', 'aria-label': 'Capture views' }, NAV.map(([key, label]) =>
        h('a', { href: `#/c/${current.id}/${key}`, class: key === page ? 'active' : null,
          'aria-current': key === page ? 'page' : null }, label,
          key === 'alerts' && s.findings ? h('span', { class: 'count' + (urgent ? ' alert' : '') }, urgent || s.findings) :
          key === 'hosts' ? h('span', { class: 'count' }, num(s.hosts)) :
          key === 'flows' ? h('span', { class: 'count' }, num(s.flows)) :
          key === 'packets' ? h('span', { class: 'count' }, num(s.packets)) : null))),
      h('div', { class: 'nav-label' }, 'Library'),
      h('nav', { class: 'nav' }, h('a', { href: '#/' }, '← All captures')));
  }
  side.append(h('div', { class: 'sidebar-foot' }, `NetSleuth ${version}`, h('br'), 'Heuristic findings are leads, not verdicts.'));
  const main = h('main', { class: 'main' }, h('div', { class: 'page', id: 'page' }));
  fill(app, h('div', { class: 'shell' }, side, main));
  return main.firstChild;
}

async function render() {
  if (cleanup) { try { cleanup(); } catch { /* ignore */ } cleanup = null; }
  hideTip();
  const route = parseRoute();
  if (route.parts[0] === 'c' && route.parts[1]) {
    const id = route.parts[1];
    if (!current || current.id !== id) {
      try {
        const row = await api.capture(id);
        if (row.status !== 'done') { location.hash = '#/'; return; }
        current = { id, row };
      } catch (err) {
        current = null;
        shell(route).append(errorBox(err), h('a', { class: 'btn', href: '#/' }, 'Back to captures'));
        return;
      }
    }
    const page = shell(route);
    const view = VIEWS[route.parts[2] || 'overview'];
    if (!view) { page.append(h('div', { class: 'empty' }, 'Unknown page.')); return; }
    loading(page);
    try {
      cleanup = await view({ page, id, row: current.row, summary: current.row.summary || {}, route, go }) || null;
    } catch (err) {
      console.error(err);
      fill(page, errorBox(err));
    }
    return;
  }
  current = null;
  cleanup = await library(shell(route));
}

// ------------------------------------------------------------- library ---
async function library(page) {
  let timer = null, stopped = false;
  const listBox = h('div');
  const errBox = h('div');
  const fileInput = h('input', { type: 'file', accept: '.pcap,.pcapng,.cap,.dmp', hidden: true,
    onchange: () => { if (fileInput.files[0]) startUpload(fileInput.files[0]); fileInput.value = ''; } });
  const dropStatus = h('div', { class: 'muted', style: { marginTop: '10px', minHeight: '18px' } });
  const drop = h('div', { class: 'drop' },
    h('div', { class: 'big' }, 'Drop a PCAP or PCAPNG file to analyse'),
    h('div', { class: 'muted' }, 'Analysis runs in the background; large captures show progress below.'),
    h('div', { style: { marginTop: '14px' } },
      h('button', { class: 'btn primary', onclick: () => fileInput.click() }, 'Choose file…')),
    dropStatus, fileInput);
  ['dragenter', 'dragover'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove('over'); }));
  drop.addEventListener('drop', e => { const f = e.dataTransfer.files[0]; if (f) startUpload(f); });

  async function startUpload(file) {
    clear(errBox);
    dropStatus.textContent = `Uploading ${file.name}…`;
    try {
      await api.upload(file, f => { dropStatus.textContent = `Uploading ${file.name}… ${Math.round(f * 100)}%`; });
      dropStatus.textContent = '';
      refresh();
    } catch (err) { dropStatus.textContent = ''; errBox.append(errorBox(err)); }
  }

  const samplesBox = h('div', { class: 'card' }, h('h2', null, 'Sample captures'),
    h('div', { class: 'muted', style: { marginBottom: '6px' } }, 'Synthetic traffic bundled with NetSleuth, for trying the interface.'));
  api.samples().then(list => {
    for (const s of list) {
      samplesBox.append(h('div', { class: 'sample' },
        h('div', null, h('div', { class: 'mono' }, s.name), h('div', { class: 'muted' }, `${s.description} (${bytes(s.size)})`)),
        h('button', { class: 'btn', onclick: async e => {
          e.target.disabled = true;
          try { await api.loadSample(s.name); refresh(); } catch (err) { errBox.append(errorBox(err)); }
          e.target.disabled = false;
        } }, 'Load')));
    }
  }).catch(() => {});

  function captureRow(c) {
    const s = c.summary || {};
    const sev = s.findings_by_severity || {};
    let status;
    if (c.status === 'done') {
      status = h('div', null, ['high', 'medium', 'low', 'info'].filter(k => sev[k]).map(k =>
        h('span', { class: `sev ${k}`, style: { marginRight: '10px' } }, `${sev[k]} ${k}`)),
        !s.findings ? h('span', { class: 'muted' }, 'no findings') : null);
    } else if (c.status === 'failed') {
      status = h('span', { style: { color: 'var(--sev-high)' }, title: c.error }, `Failed: ${c.error}`);
    } else {
      status = h('div', { style: { display: 'flex', gap: '10px', alignItems: 'center' } },
        h('div', { class: 'progress', role: 'progressbar', 'aria-valuenow': Math.round(c.progress * 100) },
          h('i', { style: { width: `${Math.round(c.progress * 100)}%` } })),
        h('span', { class: 'muted' }, c.status === 'queued' ? 'queued' : `${c.stage || 'starting'} ${Math.round(c.progress * 100)}%`));
    }
    return h('tr', { class: c.status === 'done' ? 'click' : null,
      onclick: e => { if (c.status === 'done' && !e.target.closest('button')) go(`c/${c.id}/overview`); } },
      h('td', null, c.status === 'done' ? h('a', { href: `#/c/${c.id}/overview` }, c.filename) : c.filename),
      h('td', { class: 'r' }, bytes(c.size)),
      h('td', { class: 'r' }, s.packets != null ? num(s.packets) : ''),
      h('td', { class: 'r' }, s.duration != null ? duration(s.duration) : ''),
      h('td', { class: 'wrap' }, status),
      h('td', { class: 'muted' }, utc(c.created_at)),
      h('td', { class: 'r' }, h('button', { class: 'btn small danger', 'aria-label': `Delete ${c.filename}`,
        onclick: async () => {
          if (!confirm(`Delete "${c.filename}" and its analysis? This cannot be undone.`)) return;
          try { await api.remove(c.id); } catch (err) { errBox.append(errorBox(err)); }
          refresh();
        } }, 'Delete')));
  }

  async function refresh() {
    clearTimeout(timer);
    if (stopped) return;
    let list;
    try { list = await api.captures(); }
    catch (err) { fill(listBox, errorBox(err)); timer = setTimeout(refresh, 3000); return; }
    clear(listBox);
    if (!list.length) listBox.append(h('div', { class: 'card empty' }, 'No captures yet. Upload one or load a sample.'));
    else listBox.append(h('div', { class: 'table-wrap' }, h('table', { class: 'data' },
      h('thead', null, h('tr', null, ['Capture', 'Size', 'Packets', 'Duration', 'Status / findings', 'Added', ''].map((t, i) =>
        h('th', { class: [1, 2, 3, 6].includes(i) ? 'r' : null }, t)))),
      h('tbody', null, list.map(captureRow)))));
    if (list.some(c => c.status === 'queued' || c.status === 'processing')) timer = setTimeout(refresh, 700);
  }

  fill(page, 
    h('div', { class: 'page-head' }, h('div', null, h('h1', null, 'Captures'),
      h('p', null, 'Upload a packet capture to reconstruct its network activity and review suspicious behaviour.'))),
    errBox,
    h('div', { class: 'grid wide-left', style: { marginBottom: '16px' } }, drop, samplesBox),
    listBox);
  refresh();
  return () => { stopped = true; clearTimeout(timer); };
}

window.addEventListener('hashchange', render);
api.config().then(c => { version = c.version; }).catch(() => {}).finally(render);
