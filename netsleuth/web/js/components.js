// Reusable interface pieces: data table, pager, filter bar, key/value list.
import { h, clear, fill } from './util.js';

/**
 * columns: [{ key, label, render(row), cls, sort (sort key) }]
 * opts: { onRow(row), sort, order, onSort(key), isSelected(row), empty }
 */
export function dataTable(columns, rows, opts = {}) {
  const head = h('tr', null, columns.map(c => {
    const sortable = c.sort && opts.onSort;
    const active = sortable && opts.sort === c.sort;
    return h('th', { class: [c.cls, sortable ? 'sortable' : ''].filter(Boolean).join(' ') || null,
      onclick: sortable ? () => opts.onSort(c.sort) : null,
      'aria-sort': active ? (opts.order === 'asc' ? 'ascending' : 'descending') : null },
      c.label, active ? (opts.order === 'asc' ? ' ▲' : ' ▼') : '');
  }));
  const body = h('tbody');
  for (const row of rows) {
    const tr = h('tr', { class: [opts.onRow ? 'click' : '', opts.isSelected && opts.isSelected(row) ? 'sel' : ''].filter(Boolean).join(' ') || null },
      columns.map(c => {
        const v = c.render ? c.render(row) : row[c.key];
        const td = h('td', { class: c.cls || null }, v == null ? '' : v);
        if (typeof v === 'string' && v.length > 40) td.title = v;
        return td;
      }));
    if (opts.onRow) tr.addEventListener('click', e => { if (!e.target.closest('a')) opts.onRow(row, tr); });
    body.append(tr);
  }
  if (!rows.length) body.append(h('tr', null, h('td', { colspan: columns.length, class: 'empty' }, opts.empty || 'No results.')));
  return h('div', { class: 'table-wrap' }, h('table', { class: 'data' }, h('thead', null, head), body));
}

export function pager(total, limit, offset, onPage) {
  const from = total ? offset + 1 : 0, to = Math.min(offset + limit, total);
  return h('div', { class: 'pager' },
    h('button', { class: 'btn small', disabled: offset <= 0, onclick: () => onPage(Math.max(0, offset - limit)) }, '← Prev'),
    h('button', { class: 'btn small', disabled: to >= total, onclick: () => onPage(offset + limit) }, 'Next →'),
    h('span', { class: 'num' }, `${from.toLocaleString('en-US')}–${to.toLocaleString('en-US')} of ${Number(total).toLocaleString('en-US')}`));
}

export function kv(pairs) {
  const dl = h('dl', { class: 'kv' });
  for (const [k, v] of pairs) {
    if (v == null || v === '') continue;
    dl.append(h('dt', null, k), h('dd', null, v));
  }
  return dl;
}

/** Filter input with examples; calls onApply(text) on Enter / button. */
export function filterBar(value, examples, onApply, placeholder) {
  const input = h('input', { class: 'input grow', type: 'search', value, placeholder, spellcheck: 'false',
    'aria-label': 'Filter expression', onkeydown: e => { if (e.key === 'Enter') onApply(input.value.trim()); } });
  const bar = h('div', null,
    h('div', { class: 'toolbar' }, input,
      h('button', { class: 'btn primary', onclick: () => onApply(input.value.trim()) }, 'Apply'),
      value ? h('button', { class: 'btn', onclick: () => onApply('') }, 'Clear') : null),
    h('div', { class: 'hint' }, 'Examples: ', examples.map((ex, i) => [i ? '  ' : '',
      h('code', { onclick: () => onApply(ex) }, ex)])));
  return bar;
}

export function section(title, ...children) {
  return h('div', { class: 'card' }, title ? h('h2', null, title) : null, ...children);
}
export function loading(target) { fill(target, h('div', { class: 'empty' }, h('span', { class: 'spinner' }), ' Loading…')); }
export function errorBox(err) { return h('div', { class: 'error', role: 'alert' }, err && err.message ? err.message : String(err)); }
