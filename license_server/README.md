# License Server

Development-only authorization server for the WHUT campus auto-login tool.

It implements:

- `GET /healthz`
- `GET /health`
- `POST /device/register`
- `POST /license/refresh`
- `POST /payment/create`
- `GET /payment/status`

Payment support is only an order skeleton:

- it creates and stores unpaid local payment orders;
- it does not integrate real WeChat Pay;
- it does not integrate real Alipay;
- it does not generate real or fake QR codes;
- it does not generate real or fake payment links;
- it does not simulate payment success;
- it does not issue paid licenses from payment orders.

The current `/payment/create` and `/payment/status` routes are skeleton or
compatibility routes. Payment V1 target contracts, states, schema, amount rules,
and WeChat Native-only scope are defined in
`docs/design/PAYMENT_V1_IMPLEMENTATION.md`.

Orders can only become `paid` after a future real payment callback verifies the
provider signature, amount, order status, and idempotency rules.

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
