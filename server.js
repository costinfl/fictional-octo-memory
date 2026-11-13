'use strict';
// Minimal PDF vault server. It only ever sees ciphertext: the browser encrypts
// the file (and the file name) before upload, and derives everything from your
// code. The code itself is never sent; only a derived token is.
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const VAULT_PATH = process.env.VAULT_PATH || '/vault'; // make this unguessable if you like
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const FILES = path.join(DATA, 'files');
const CONFIG = path.join(DATA, 'config.json');
const MAX_BYTES = 50 * 1024 * 1024;
const ITERATIONS = 600000;
fs.mkdirSync(FILES, { recursive: true });

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const readConfig = () => { try { return JSON.parse(fs.readFileSync(CONFIG, 'utf8')); } catch { return null; } };

// --- tiny in-memory brute-force limiter (per IP) ---
const fails = new Map();
function limited(ip) {
  const f = fails.get(ip);
  return f && f.count >= 10 && Date.now() - f.first < 15 * 60 * 1000;
}
function noteFail(ip) {
  const f = fails.get(ip);
  if (!f || Date.now() - f.first > 15 * 60 * 1000) fails.set(ip, { count: 1, first: Date.now() });
  else f.count++;
}

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use((req, res, next) => {
  res.set({
    'Cache-Control': 'no-store',
    'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Robots-Tag': 'noindex, nofollow',
  });
  next();
});

function auth(req, res, next) {
  const cfg = readConfig();
  if (!cfg) return res.status(409).json({ error: 'not set up' });
  if (limited(req.ip)) return res.status(429).json({ error: 'too many attempts, try later' });
  const token = (req.get('authorization') || '').replace(/^Bearer /, '');
  const a = Buffer.from(sha256(token));
  const b = Buffer.from(cfg.verifier);
  if (!/^[0-9a-f]{64}$/.test(token) || !crypto.timingSafeEqual(a, b)) {
    noteFail(req.ip);
    return res.status(401).json({ error: 'wrong code' });
  }
  next();
}

app.get('/api/params', (req, res) => {
  const cfg = readConfig();
  res.json({ setup: !!cfg, encSalt: cfg ? cfg.encSalt : null, iterations: ITERATIONS });
});

// First visit only: the first code chosen becomes the vault code.
app.post('/api/setup', express.json(), (req, res) => {
  if (readConfig()) return res.status(409).json({ error: 'already set up' });
  const token = req.body && req.body.token;
  if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token)) return res.status(400).json({ error: 'bad token' });
  const cfg = { verifier: sha256(token), encSalt: crypto.randomBytes(16).toString('base64') };
  fs.writeFileSync(CONFIG, JSON.stringify(cfg), { mode: 0o600 });
  res.json({ encSalt: cfg.encSalt });
});

app.get('/api/check', auth, (req, res) => res.json({ ok: true }));

app.post('/api/files', auth, express.raw({ type: 'application/octet-stream', limit: MAX_BYTES }), (req, res) => {
  if (!Buffer.isBuffer(req.body) || !req.body.length) return res.status(400).json({ error: 'empty body' });
  let name;
  try {
    name = JSON.parse(Buffer.from(req.get('x-meta') || '', 'base64').toString('utf8'));
    if (typeof name.iv !== 'string' || typeof name.ct !== 'string' || name.iv.length > 64 || name.ct.length > 2048) throw 0;
  } catch { return res.status(400).json({ error: 'bad meta' }); }
  const id = crypto.randomBytes(16).toString('hex');
  fs.writeFileSync(path.join(FILES, id + '.bin'), req.body);
  fs.writeFileSync(path.join(FILES, id + '.json'), JSON.stringify({ id, size: req.body.length, created: Date.now(), name: { iv: name.iv, ct: name.ct } }));
  res.json({ id });
});

app.get('/api/files', auth, (req, res) => {
  const items = fs.readdirSync(FILES).filter((f) => f.endsWith('.json'))
    .map((f) => JSON.parse(fs.readFileSync(path.join(FILES, f), 'utf8')))
    .sort((a, b) => b.created - a.created);
  res.json(items);
});

app.get('/api/files/:id', auth, (req, res) => {
  if (!/^[0-9a-f]{32}$/.test(req.params.id)) return res.status(400).end();
  const p = path.join(FILES, req.params.id + '.bin');
  if (!fs.existsSync(p)) return res.status(404).end();
  res.type('application/octet-stream').send(fs.readFileSync(p));
});

app.delete('/api/files/:id', auth, (req, res) => {
  if (!/^[0-9a-f]{32}$/.test(req.params.id)) return res.status(400).end();
  for (const ext of ['.bin', '.json']) fs.rmSync(path.join(FILES, req.params.id + ext), { force: true });
  res.json({ ok: true });
});

app.use('/vendor', express.static(path.join(__dirname, 'node_modules/pdf-lib-plus-encrypt/dist')));
app.use(express.static(path.join(__dirname, 'public'), { index: false, extensions: [] }));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public/upload.html')));
app.get(VAULT_PATH, (req, res) => res.sendFile(path.join(__dirname, 'public/vault.html')));

app.listen(PORT, () => console.log(`PDF vault on http://localhost:${PORT}  (secret page: ${VAULT_PATH})`));
