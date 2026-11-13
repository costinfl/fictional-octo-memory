const $ = (id) => document.getElementById(id);
let meta = null;
loadMeta().then((m) => {
  meta = m;
  if (!m) { $('first').hidden = false; $('confirmRow').hidden = false; }
}).catch(() => {});

$('form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const code = $('code').value, token = $('token').value.trim(), file = $('file').files[0], out = $('status');
  $('result').hidden = true;
  try {
    if (!file) throw new Error('Choose a PDF first.');
    if (!token) throw new Error('Paste your GitHub token.');
    if (code.length < MIN_CODE) throw new Error('Code must be at least ' + MIN_CODE + ' characters.');
    if (file.size > 40 * 1024 * 1024) throw new Error('File too large (40 MB max).');
    $('go').disabled = true;
    const gh = github(token);

    status(out, 'Checking code…');
    meta = meta || (await loadMeta());
    let key;
    if (meta) key = await unlock(code, meta);
    else {
      if (code !== $('code2').value) throw new Error('The two codes do not match.');
      const v = await createVault(code); key = v.key;
      status(out, 'Creating vault…');
      await gh.put('store/vault.json', enc.encode(JSON.stringify(v.meta)), 'Create vault');
      meta = v.meta;
    }

    status(out, 'Protecting PDF with your code…');
    const raw = new Uint8Array(await file.arrayBuffer());
    if (dec.decode(raw.slice(0, 5)) !== '%PDF-') throw new Error('That does not look like a PDF.');
    const pdf = await PDFLib.PDFDocument.load(raw);
    await pdf.encrypt({ userPassword: code, ownerPassword: code, permissions: { printing: 'highResolution', copying: true } });
    const protectedPdf = await pdf.save();

    status(out, 'Encrypting before upload…');
    const body = await aesEncrypt(key, protectedPdf);
    const name = await aesEncrypt(key, enc.encode(file.name));
    const blob = new Uint8Array(12 + body.ct.length);
    blob.set(body.iv, 0); blob.set(body.ct, 12);
    const id = toHex(crypto.getRandomValues(new Uint8Array(16)));

    status(out, 'Uploading to the store…');
    await gh.put('store/' + id + '.bin', blob, 'Add encrypted file');
    const idx = (await gh.readJson('store/index.json')) || { sha: undefined, data: [] };
    idx.data.unshift({ id, size: blob.length, created: Date.now(), name: { iv: toB64(name.iv), ct: toB64(name.ct) } });
    await gh.put('store/index.json', enc.encode(JSON.stringify(idx.data)), 'Update index', idx.sha);

    status(out, 'Done. Only encrypted data was committed.', 'ok');
    $('result').hidden = false;
    $('form').reset(); $('first').hidden = true; $('confirmRow').hidden = true;
  } catch (err) {
    status(out, err.message || String(err), 'err');
  } finally { $('go').disabled = false; }
});
