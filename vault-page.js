const $ = (id) => document.getElementById(id);
const fmt = (n) => (n > 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.ceil(n / 1024) + ' KB');

$('form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const out = $('status');
  try {
    $('go').disabled = true;
    status(out, 'Unlocking…');
    const meta = await loadMeta();
    if (!meta) throw new Error('Nothing stored yet. Upload a PDF first.');
    const key = await unlock($('code').value, meta);
    const items = await loadIndex();
    $('form').hidden = true; $('delrow').hidden = false;
    out.textContent = ''; out.className = 'status';
    render(items, key);
  } catch (err) { status(out, err.message || String(err), 'err'); }
  finally { $('go').disabled = false; }
});

async function render(items, key) {
  const list = $('list'); list.hidden = false; list.textContent = '';
  if (!items.length) { list.textContent = 'No files yet.'; return; }
  for (const it of items) {
    let name = 'file.pdf';
    try { name = dec.decode(await aesDecrypt(key, fromB64(it.name.iv), fromB64(it.name.ct))); } catch {}
    const row = document.createElement('div'); row.className = 'row';
    const a = document.createElement('a'); a.href = '#'; a.textContent = name; a.className = 'dl';
    const meta = document.createElement('span'); meta.className = 'meta';
    meta.textContent = fmt(it.size) + ' · ' + new Date(it.created).toLocaleString();
    const del = document.createElement('button'); del.textContent = 'Delete'; del.className = 'danger';
    a.addEventListener('click', async (ev) => {
      ev.preventDefault();
      try {
        status($('msg'), 'Decrypting ' + name + '…');
        const r = await fetch('store/' + it.id + '.bin', { cache: 'no-store' });
        if (!r.ok) throw new Error('File not published yet (' + r.status + '). GitHub Pages can take a minute or two; try again.');
        const buf = new Uint8Array(await r.arrayBuffer());
        const pdf = await aesDecrypt(key, buf.slice(0, 12), buf.slice(12));
        const url = URL.createObjectURL(new Blob([pdf], { type: 'application/pdf' }));
        const d = document.createElement('a'); d.href = url; d.download = name; d.click();
        setTimeout(() => URL.revokeObjectURL(url), 10000);
        status($('msg'), 'Downloaded. Open it and enter your code.', 'ok');
      } catch (err) { status($('msg'), err.message || String(err), 'err'); }
    });
    del.addEventListener('click', async () => {
      const token = $('token').value.trim();
      if (!token) return status($('msg'), 'Paste a GitHub token below to delete.', 'err');
      if (!confirm('Delete ' + name + '?')) return;
      try {
        const gh = github(token);
        const idx = await gh.readJson('store/index.json');
        if (idx) await gh.put('store/index.json', enc.encode(JSON.stringify(idx.data.filter((x) => x.id !== it.id))), 'Update index', idx.sha);
        const f = await gh.get('store/' + it.id + '.bin');
        if (f) await gh.del('store/' + it.id + '.bin', f.sha, 'Delete encrypted file');
        row.remove(); status($('msg'), 'Deleted.', 'ok');
      } catch (err) { status($('msg'), err.message, 'err'); }
    });
    row.append(a, meta, del); list.append(row);
  }
}
