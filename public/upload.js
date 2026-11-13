const $ = (id) => document.getElementById(id);
let isSetup = true;
api.params().then((p) => {
  isSetup = p.setup;
  if (!p.setup) {
    $('first').hidden = false;
    $('confirmRow').hidden = false;
  }
});

$('form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const code = $('code').value;
  const file = $('file').files[0];
  const out = $('status');
  $('result').hidden = true;
  try {
    if (!file) throw new Error('Choose a PDF first.');
    if (code.length < MIN_CODE) throw new Error('Code must be at least ' + MIN_CODE + ' characters.');
    if (!isSetup && code !== $('code2').value) throw new Error('The two codes do not match.');
    $('go').disabled = true;

    status(out, 'Checking code…');
    const { token, key } = await unlock(code, { allowSetup: !isSetup });

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
    const meta = toB64(enc.encode(JSON.stringify({ iv: toB64(name.iv), ct: toB64(name.ct) })));

    status(out, 'Uploading…');
    await api.call(token, '/api/files', { method: 'POST', headers: { 'Content-Type': 'application/octet-stream', 'X-Meta': meta }, body: blob });
    status(out, 'Done. Only encrypted data was uploaded.', 'ok');
    $('result').hidden = false;
    $('form').reset();
    isSetup = true;
    $('first').hidden = true; $('confirmRow').hidden = true;
  } catch (err) {
    status(out, err.message || String(err), 'err');
  } finally {
    $('go').disabled = false;
  }
});
