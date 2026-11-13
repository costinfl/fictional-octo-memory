const $ = (id) => document.getElementById(id);
const fmt = (n) => (n > 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.ceil(n / 1024) + ' KB');

$('form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const out = $('status');
  try {
    $('go').disabled = true;
    status(out, 'Unlocking…');
    const { token, key } = await unlock($('code').value);
    const items = await (await api.call(token, '/api/files')).json();
    $('form').hidden = true;
    out.textContent = ''; out.className = 'status';
    render(items, token, key);
  } catch (err) {
    status(out, err.message || String(err), 'err');
  } finally { $('go').disabled = false; }
});

async function render(items, token, key) {
  const list = $('list');
  list.hidden = false;
  list.textContent = '';
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
        const buf = new Uint8Array(await (await api.call(token, '/api/files/' + it.id)).arrayBuffer());
        const pdf = await aesDecrypt(key, buf.slice(0, 12), buf.slice(12));
        const url = URL.createObjectURL(new Blob([pdf], { type: 'application/pdf' }));
        const d = document.createElement('a'); d.href = url; d.download = name; d.click();
        setTimeout(() => URL.revokeObjectURL(url), 10000);
        status($('msg'), 'Downloaded. Open it and enter your code.', 'ok');
      } catch (err) { status($('msg'), err.message || String(err), 'err'); }
    });
    del.addEventListener('click', async () => {
      if (!confirm('Delete ' + name + '?')) return;
      try { await api.call(token, '/api/files/' + it.id, { method: 'DELETE' }); row.remove(); } catch (err) { status($('msg'), err.message, 'err'); }
    });
    row.append(a, meta, del);
    list.append(row);
  }
}
