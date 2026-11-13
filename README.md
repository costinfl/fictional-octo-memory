# PDF vault

A tiny private site to stash a PDF and fetch it from another browser.

- `/` : pick a PDF + enter your code. In the browser the PDF is password-protected
  with your code, then AES-256-GCM encrypted, then uploaded. The file name is encrypted too.
- `/vault` (change with `VAULT_PATH`): enter your code to list your files. Clicking a file
  decrypts the transport layer in the browser and saves a normal PDF that **asks for your code when opened**.

The server stores ciphertext only. Your code never leaves the browser; a PBKDF2-derived
token is sent for login and a separate PBKDF2-derived key does the encryption.

## Run

    npm install
    npm start            # http://localhost:3000

The first code entered on the upload page becomes the vault code (set it right after deploying).
Serve it over HTTPS if it is public. Env: `PORT`, `VAULT_PATH`, `DATA_DIR`. Max file size 50 MB.

## Limits

No code recovery: lose the code, lose the files. Use a long passphrase; weak codes can be
brute-forced offline from the stored ciphertext. Login attempts are rate-limited per IP (in memory).
