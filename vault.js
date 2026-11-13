// Shared client-side crypto + GitHub storage. Your code never leaves the browser.
const enc = new TextEncoder();
const dec = new TextDecoder();
const CFG = window.VAULT_CONFIG;
const ITER = 1000000;
const MIN_CODE = 10;
const toB64 = (u8) => { let s = ''; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); };
const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const toHex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');

async function deriveKey(code, salt) {
  const base = await crypto.subtle.importKey('raw', enc.encode(code), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITER }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function aesEncrypt(key, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  return { iv, ct: new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes)) };
}
const aesDecrypt = async (key, iv, ct) => new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));

// ---- public store (served by Pages, relative URLs) ----
async function fetchJson(path) {
  const r = await fetch(path + '?t=' + Date.now(), { cache: 'no-store' });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error('Could not load ' + path + ' (' + r.status + ')');
  return r.json();
}
const loadMeta = () => fetchJson('store/vault.json');
const loadIndex = async () => (await fetchJson('store/index.json')) || [];

// vault.json holds a public random salt and a tiny encrypted check value, so a wrong code is detected client-side.
async function unlock(code, meta) {
  const key = await deriveKey(code, fromB64(meta.salt));
  try {
    const ok = dec.decode(await aesDecrypt(key, fromB64(meta.check.iv), fromB64(meta.check.ct)));
    if (ok !== 'pdf-vault-ok') throw 0;
  } catch { throw new Error('Wrong code.'); }
  return key;
}
async function createVault(code) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(code, salt);
  const c = await aesEncrypt(key, enc.encode('pdf-vault-ok'));
  return { key, meta: { salt: toB64(salt), check: { iv: toB64(c.iv), ct: toB64(c.ct) } } };
}

// ---- GitHub contents API (needs a token; only used to write/delete) ----
function github(token) {
  const base = `https://api.github.com/repos/${CFG.owner}/${CFG.repo}/contents/`;
  const headers = { Authorization: 'Bearer ' + token, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' };
  async function call(method, path, body) {
    const url = base + path + (method === 'GET' ? '?ref=' + encodeURIComponent(CFG.branch) + '&t=' + Date.now() : '');
    const r = await fetch(url, { method, headers, body: body && JSON.stringify({ ...body, branch: CFG.branch }), cache: 'no-store' });
    if (r.status === 404 && method === 'GET') return null;
    if (r.status === 401) throw new Error('GitHub rejected the token.');
    if (r.status === 403 || r.status === 404) throw new Error('GitHub denied access (' + r.status + '). The token needs Contents: read & write on this repo.');
    if (r.status === 409 || r.status === 422) throw new Error('GitHub conflict (' + r.status + '). Try again.');
    if (!r.ok) throw new Error('GitHub error (' + r.status + ').');
    return r.json();
  }
  return {
    get: (path) => call('GET', path),
    put: async (path, bytes, message, sha) => call('PUT', path, { message, content: toB64(bytes), ...(sha ? { sha } : {}) }),
    del: (path, sha, message) => call('DELETE', path, { message, sha }),
    async readJson(path) { const f = await call('GET', path); return f ? { sha: f.sha, data: JSON.parse(dec.decode(fromB64(f.content.replace(/\n/g, '')))) } : null; },
  };
}

function status(el, msg, kind) { el.textContent = msg; el.className = 'status ' + (kind || ''); }
