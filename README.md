# PDF vault (GitHub Pages)

A static site to stash a PDF and fetch it from another browser. Encrypted files live in `store/`.

- `index.html`: pick a PDF, enter your code and a GitHub token. In the browser the PDF is
  password-protected with your code, then AES-256-GCM encrypted (key = PBKDF2 of your code),
  then committed to `store/` via the GitHub API. The file name is encrypted too.
- `vault.html`: enter your code to list files. Clicking one fetches `store/<id>.bin`, decrypts it
  in the browser and saves a normal PDF that **asks for your code when opened**.

Your code and token never leave the browser (the token only goes to api.github.com).

## Setup

1. Repo must be public (Pages on private repos needs a paid plan).
2. Settings > Pages > Deploy from a branch > branch `claude/push-file-to-repo-ch4ik8` (or whichever
   branch you use), folder `/ (root)`. Keep `config.js` `branch` equal to that branch.
3. Create a fine-grained token: only this repo, Contents: Read and write. Paste it on the upload
   page each time (it is not stored). Use a short expiry.
4. First upload creates `store/vault.json`; the code you use then becomes the vault code.

## Limits

- The store is public. Anyone can download the ciphertext and try codes offline, so use a long
  passphrase (the page enforces 10+ chars, 1M PBKDF2 iterations). No code recovery.
- New uploads show up after Pages rebuilds (1-2 min). Max 40 MB per file.
- Anyone who knows `vault.html` can see it exists; rename it for obscurity. File sizes and
  upload times are visible in `store/`.
