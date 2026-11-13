// Shared client-side crypto. Nothing here ever sends your code anywhere.
const enc = new TextEncoder();
const dec = new TextDecoder();
const toB64 = (u8) => { let s = ''; for (const b of u8) s += String.fromCharCode(b); return btoa(s); };
const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const toHex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');
const MIN_CODE = 8;

async function pbkdf2Bits(code, salt, iterations) {
  const base = await crypto.subtle.importKey('raw', enc.encode(code), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base, 256));
}

const api = {
  params: () => fetch('/api/params').then((r) => r.json()),
  async call(token, path, opts = {}) {
    const r = await fetch(path, { ...opts, headers: { ...(opts.headers || {}), Authorization: 'Bearer ' + token } });
    if (r.status === 401) throw new Error('Wrong code.');
    if (r.status === 429) throw new Error('Too many attempts. Try again later.');
    if (!r.ok) throw new Error('Server error (' + r.status + ').');
    return r;
  },
};

// Derive the login token (sent to server) and the AES key (never leaves the browser) from the code.
async function unlock(code, { allowSetup = false } = {}) {
  let p = await api.params();
  const authBits = await pbkdf2Bits(code, enc.encode('pdf-vault/auth/v1'), p.iterations);
  const token = toHex(authBits);
  if (!p.setup) {
    if (!allowSetup) throw new Error('Vault not set up yet. Open the upload page first.');
    const r = await fetch('/api/setup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
    if (!r.ok) throw new Error('Setup failed.');
    p = { ...p, encSalt: (await r.json()).encSalt };
  } else {
    await api.call(token, '/api/check'); // throws "Wrong code." if invalid
  }
  const keyBits = await pbkdf2Bits(code, fromB64(p.encSalt), p.iterations);
  const key = await crypto.subtle.importKey('raw', keyBits, 'AES-GCM', false, ['encrypt', 'decrypt']);
  return { token, key };
}

async function aesEncrypt(key, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes));
  return { iv, ct };
}
const aesDecrypt = async (key, iv, ct) => new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));

function status(el, msg, kind) { el.textContent = msg; el.className = 'status ' + (kind || ''); }
