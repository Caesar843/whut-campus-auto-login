# License Server

Development-only authorization server for the WHUT campus auto-login tool.

It implements:

- `GET /health`
- `POST /device/register`
- `POST /license/refresh`
- `POST /admin/grant`
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

Orders can only become `paid` after a future real payment callback verifies the
provider signature, amount, order status, and idempotency rules.

## Local Setup

Generate an Ed25519 key pair:

```powershell
python scripts/dev/generate_license_keys.py
```

Set environment variables:

```powershell
$env:LICENSE_PRIVATE_KEY = "<private key from script>"
$env:LICENSE_PUBLIC_KEY = "<public key from script>"
$env:LICENSE_ADMIN_TOKEN = "change-me"
$env:DATABASE_URL = "sqlite:///./license_server_dev.sqlite3"
```

Run:

```powershell
uvicorn license_server.app:app --host 127.0.0.1 --port 8787
```

The private key must not be committed. The client only needs the public key.

Production deployments can set `DATABASE_URL=sqlite:////var/lib/whut-campus-auto-login/license.sqlite3`.
`LICENSE_DB_PATH` is still accepted for local compatibility, but `DATABASE_URL` is preferred.
