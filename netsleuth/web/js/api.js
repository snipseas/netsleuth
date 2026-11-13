// Thin fetch wrapper around the NetSleuth HTTP API.
export class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
async function request(path, opts) {
  let res;
  try { res = await fetch(path, opts); }
  catch { throw new ApiError(0, 'Cannot reach the NetSleuth server.'); }
  if (res.status === 204) return null;
  let body = null;
  try { body = await res.json(); } catch { /* non-JSON error body */ }
  if (!res.ok) {
    let msg = body && body.detail;
    if (Array.isArray(msg)) msg = msg.map(m => m.msg).join('; ');
    throw new ApiError(res.status, msg || `Request failed (${res.status})`);
  }
  return body;
}
function qs(params) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params || {})) if (v != null && v !== '') p.set(k, v);
  const s = p.toString();
  return s ? `?${s}` : '';
}
export const api = {
  config: () => request('/api/config'),
  captures: () => request('/api/captures'),
  capture: id => request(`/api/captures/${id}`),
  remove: id => request(`/api/captures/${id}`, { method: 'DELETE' }),
  samples: () => request('/api/samples'),
  loadSample: name => request(`/api/samples/${encodeURIComponent(name)}`, { method: 'POST' }),
  get: (id, what, params) => request(`/api/captures/${id}/${what}${qs(params)}`),
  reportUrl: (id, format, download) => `/api/captures/${id}/report${qs({ format, download: download ? 'true' : null })}`,
  upload(file, onProgress) {
    // XMLHttpRequest because fetch cannot report upload progress
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', `/api/captures${qs({ filename: file.name })}`);
      xhr.setRequestHeader('Content-Type', 'application/octet-stream');
      xhr.upload.onprogress = e => { if (e.lengthComputable && onProgress) onProgress(e.loaded / e.total); };
      xhr.onload = () => {
        let body = null;
        try { body = JSON.parse(xhr.responseText); } catch { /* ignore */ }
        if (xhr.status >= 200 && xhr.status < 300) resolve(body);
        else reject(new ApiError(xhr.status, (body && body.detail) || `Upload failed (${xhr.status})`));
      };
      xhr.onerror = () => reject(new ApiError(0, 'Upload failed: connection lost.'));
      xhr.send(file);
    });
  },
};
