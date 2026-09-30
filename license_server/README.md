# License Server

Free-version license server for the WHUT campus auto-login tool.

The tool is permanently free: there is no trial, no purchase, no activation
code, and no order flow anywhere in the server. The server only:

- registers devices (device fingerprint hash only) and issues a permanent
  free license on first registration;
- refreshes the signed license token for known devices;
- serves a minimal internal read-only admin console for usage statistics;
- optionally provides runtime attestation for privileged local processes.

It implements:

- `GET /healthz`
- `GET /health`
- `POST /device/register`
- `POST /license/refresh`

`POST /device/register` accepts `product_id` and `device_fingerprint_hash`
only. Legacy clients may still send `device_name`, `os`, and `app_version`;
these fields are ignored and never stored. Any campus account fields are
rejected with 422.

A new device immediately receives a permanent free license:

- `license_type="free"`, `source="free"`;
- `expires_at="9999-12-31T00:00:00Z"`;
- the historical `order_id` column stays in the schema but is always NULL and
  never read.

Responses include `status` (`free_active`, `free_expired`, or `revoked`), the
license fields, and a server-signed `signed_license_token` that clients verify
with the embedded public key. `POST /license/refresh` returns 404
`device_not_found` for unknown devices.

## Admin Console

With `ADMIN_ENABLED=true` the server mounts a read-only admin console at
`/internal/admin/` (page plus `/internal/admin/assets/admin.js`). The page
itself contains no business data; the admin token lives only in the browser
session. Data endpoints under `/internal/admin/api/`:

- `GET /api/summary` — device totals, 24h/7d/30d active devices, license type
  and status distribution;
- `GET /api/devices` and `GET /api/devices/{device_fingerprint_hash}`;
- `GET /api/licenses`;
- `GET /api/audit-logs` and `GET /api/audit-logs/{audit_id}`;
- `POST /api/devices/{device_fingerprint_hash}/notes` and
  `POST /api/licenses/{license_id}/notes` — the only write endpoints; they
  append an audited note.

The console cannot issue, freeze, or modify licenses. Access uses a Bearer
token compared by SHA-256 digest (`ADMIN_ACCESS_TOKEN_SHA256`); the raw token
must never enter the repository, logs, or Nginx config. Responses always carry
security headers, and sensitive note text is redacted in audit views.

## Database

Schema version 6 (`license_server/db.py`) keeps only the core tables
`devices`, `licenses`, `admin_audit_logs`, and `schema_meta`. Payment-era
legacy tables (`db.LEGACY_PAYMENT_TABLES`) are not created in new databases;
if they still exist in an old database they are preserved as-is and are never
validated, read, or written.

## Runtime Attestation

Optional and production-only. With `LICENSE_RUNTIME_ATTESTATION_ENABLED=true`
(and a valid `LICENSE_RUNTIME_SOURCE_COMMIT`), the app starts a local runtime
attestation server that answers signed proofs over a locked Unix socket for
privileged local processes only. Public traffic must never reach it; the
Nginx example blocks `/internal/runtime-attestation`. Deployment details live
in `docs/deploy/LICENSE_SERVER_PRODUCTION_CONFIG.md`.

## Local Setup

Generate an Ed25519 key pair:

```powershell
python scripts/dev/generate_license_keys.py
```

Set environment variables:

```powershell
$env:LICENSE_SERVER_ENV = "development"
$env:LICENSE_PRIVATE_KEY = "<private key from script>"
$env:LICENSE_PUBLIC_KEY = "<public key from script>"
$env:DATABASE_URL = "sqlite:///./license_server_dev.sqlite3"
```

Run:

```powershell
uvicorn license_server.app:app --host 127.0.0.1 --port 8787
```

The private key must not be committed. The client only needs the public key.

Production must set `LICENSE_SERVER_ENV=production`, an explicit absolute
SQLite path, and a valid Ed25519 private key.
See `docs/deploy/LICENSE_SERVER_PRODUCTION_CONFIG.md`.
