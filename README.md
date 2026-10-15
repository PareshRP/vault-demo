# Vault Change Portal

A local-only Flask portal to review and apply HashiCorp Vault KV v2 secret changes from uploaded `.txt` instruction files.

## Workflow

1. Select Sandbox, Pilot, or Prod.
2. Upload a folder (browser-supported folder picker) or one or more `.txt` files. The selected names are shown before you build the preview.
3. Review the final before/after diff, current KV v2 version, and operation list for every file.
4. Apply one file with **Make change**, or apply remaining pending files with **Make all changes**.
5. Check each file's status. Stale, failed, and outcome-unknown entries are not silently retried.

The app defaults to **DEMO mode**. The single switch is `DRY_RUN = True` near the top of `app.py`. True uses synthetic in-memory data and never sends HTTP requests to Vault. Set it to `False` only when deliberately enabling real Vault operations. No `VAULT_MODE` or `VAULT_ALLOWED_HOSTS` environment variables are needed.

## Security boundary

- This version has **no login** and is intended for one operator on a trusted computer.
- The server binds to `127.0.0.1` only. Do not expose it on `0.0.0.0`, a LAN, a shared host, or the public internet.
- A browser preview displays sensitive old/new values. Use only on a trusted machine and close the browser when finished.
- Uploaded file contents and preview data are held in server memory, not written to a public upload directory. Preview state expires after 15 minutes and is bound to the browser session.
- POST actions use a per-session CSRF token. Pages containing values use `Cache-Control: no-store` and security headers.
- Never put Vault tokens or real secret values in source control, examples, screenshots, or logs.
- Behind HTTPS, set `SESSION_COOKIE_SECURE=True`, use a valid TLS configuration, add authentication/authorization, and reassess CSRF, host validation, secret storage, audit logging, and deployment hardening before allowing remote access.

## Requirements

- Python 3.11+
- pip
- Access to the configured Vault endpoints only if you later enable REAL mode

## Run on macOS / Linux

```bash
cd vault-change-portal
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5001. No `.env` file is needed. The terminal should announce DEMO mode.

## Run on Windows PowerShell

```powershell
cd vault-change-portal
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

If script activation is blocked by policy, run `.\.venv\Scripts\python.exe -m pip install -r requirements.txt` and `.\.venv\Scripts\python.exe app.py` without activating the environment.

Open http://127.0.0.1:5001.

## Run tests

```bash
pytest -q
```

## Instruction format

Each file targets exactly one secret. The first meaningful line must be `SECRET: <relative/path>`. Blank lines and lines starting with `#` are comments.

```text
SECRET: TEST_gcp
SET gcp_id = 1234452
SET gcp_name = demo-project
```

To copy a value from another secret, use `Key: <secret_name.key_name>` as the value. The app reads the source key during preview and resolves it into the target value. The source secret version and value are checked again before apply; if the source changes, the preview is marked stale.

```text
SECRET: team/service-config
SET gcp_id = Key: <TEST_gcp.gcp_id>
SET_NESTED config : region = Key: <shared/config.region>
```

The secret path is everything before the final dot; the part after the final dot is the source key. Referenced values must be strings.

For one sub-value inside a multiline string:

```text
SECRET: TEST_token
SET_NESTED token_gcp : gcp_token = NEW_DEMO_TOKEN_456
```

Rules:
- `SET key = value` creates or updates a top-level key.
- `SET_NESTED outer_key : sub_key = value` updates a `sub_key=value` line inside a string. If absent, the subkey is appended; if the outer key is missing, it is created. The outer key must be a string.
- Values may contain `=` and `#`. Parsing splits only at the operation's first `=`.
- Empty values are allowed: `SET key =` sets the key to an empty string.
- Other keys and unrelated multiline lines are preserved.
- Unsupported/malformed operations and unsafe paths are rejected.
- Multiple files targeting the same secret path are rejected.
- Maximum 50 files per preview, maximum 256 KiB per file. UTF-8 text only.
- Folder uploads rely on browser support for `webkitdirectory`/directory selection. If unavailable, use multi-file upload.

## Connections tab

In REAL mode, open **Connections** to add or replace the Sandbox, Pilot, and Prod Vault endpoints. Enter the HTTPS address and token, then choose **Verify & save connection**. The app checks the token with Vault's `auth/token/lookup-self` endpoint. This endpoint must be permitted by the token policy. A verified connection is held in server process memory only and is removed when the app restarts; tokens are not written to disk or browser sessions. Existing `VAULT_TOKEN_*` environment variables remain supported as a fallback.

The exact-host allowlist is configured in the code-level `ALLOWED_VAULT_HOSTS` set in `app.py`. Only HTTPS URLs on these exact hosts are accepted, helping prevent server-side request forgery through arbitrary connection URLs.

## Switching to REAL mode later

**Do not enable REAL mode until the target URLs, policies, and KV mount are verified with your Vault administrator.** The default endpoints and mount follow the supplied project brief. Connections added in the Connections tab can override the endpoint for the selected environment in memory.

1. Change `DRY_RUN = True` to `DRY_RUN = False` in `app.py`. REAL mode is opt-in; a Vault error never falls back to demo.
2. Set the appropriate token in the server environment only:
   - `VAULT_TOKEN_SANDBOX`
   - `VAULT_TOKEN_PILOT`
   - `VAULT_TOKEN_PROD`
3. Restart the server. Tokens are never requested in the browser and are never displayed or logged.
4. Verify the environment selection and exact diff before applying. Prod requires typing `Prod` for each apply action.
5. Grant least-privilege KV v2 read/write access only to the required paths. Keep tokens out of shell history where possible and use your organization's secret-management method.

For Windows, double-click `Start-VaultPortal.bat` to start the updated build at `http://127.0.0.1:5001`. It deliberately uses port 5001 so an older version already running on port 5000 cannot make the browser show the old UI. It invokes `Start-VaultPortal.ps1`, creates `.venv` if needed, installs requirements, starts Flask, and opens the browser. To configure a real connection, set `DRY_RUN = False`, restart the app, and enter the Vault address and token in the Connections tab. Never commit tokens.

## Apply semantics and limitations

- The app checks the version and data again before each write, then uses KV v2 CAS on the write.
- “Make all changes” checks all pending versions before starting writes, then writes one secret at a time.
- Vault does not provide an atomic transaction across multiple secrets. Earlier writes are not rolled back if a later write fails.
- A write timeout or lost response is shown as **OUTCOME UNKNOWN**. The app does not retry automatically. Inspect Vault and create a fresh preview before taking further action.
- No-op changes do not create a new secret version.
- Missing secrets are written with CAS `0` to prevent overwriting a secret that was created after the preview.

## Project structure

```text
vault-change-portal/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── vault_portal/
│   ├── __init__.py
│   ├── core.py
│   └── vault.py
├── templates/
│   ├── base.html
│   ├── index.html
│   └── error.html
├── static/
│   └── style.css
├── examples/
│   ├── update-gcp.txt
│   └── update-nested-token.txt
└── tests/
    ├── test_core.py
    └── test_app.py
```
