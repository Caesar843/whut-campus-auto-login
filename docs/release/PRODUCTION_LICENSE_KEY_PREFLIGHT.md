# Production license key preflight SOP

## Purpose

This read-only preflight proves only that the configured production environment
file contains a valid matching Ed25519 private key and public key, and that the
configured public key verifies a challenge signed by the configured private key.
The private key may come from non-empty `LICENSE_PRIVATE_KEY` or, only when that
value is empty, from `LICENSE_PRIVATE_KEY_FILE`. This matches the license
server's source priority. The private key must remain on the server.

## Preconditions

- Sync the approved commit to `/opt/whut-campus-auto-login`.
- Confirm the checkout is clean and do not change the production environment
  file during this procedure.
- Confirm the server Python virtual environment is available.
- Use `sudo` only to obtain read access to the environment file.
- When `LICENSE_PRIVATE_KEY_FILE` is used, keep its path absolute, its file mode
  owner-only on POSIX, and the file itself a regular non-symlink UTF-8 file
  containing only the Base64 Ed25519 private-key value.
- Do not restart services, rotate keys, edit configuration, deploy, or build an
  executable during this preflight.

### Supported environment-file syntax

This preflight intentionally parses a restricted literal `KEY=value` subset
rather than emulating the full `systemd EnvironmentFile=` grammar. Blank lines
and whole-line comments are allowed. Every other line must contain a `=` and a
valid key name matching `[A-Za-z_][A-Za-z0-9_]*`; leading or trailing
whitespace around the key name is rejected. The `export` prefix is not
supported.

For the four consumed keys — `LICENSE_SERVER_ENV`, `LICENSE_PRIVATE_KEY`,
`LICENSE_PRIVATE_KEY_FILE`, and `LICENSE_PUBLIC_KEY` — values must be literal.
They must not contain single quotes (`'`), double quotes (`"`), dollar signs
(`$`), backticks (`` ` ``), here-doc markers (`<<`), or trailing-backslash
line continuation. Duplicate definitions of these keys are rejected.

Other structurally valid environment keys are silently ignored: their values
are not interpreted, validated, stored, or output by the preflight.

This parser is intentionally narrow. Do not rely on it as a general-purpose
environment-file parser.

## Run the preflight

```bash
cd /opt/whut-campus-auto-login
sudo /opt/whut-campus-auto-login/.venv/bin/python \
  scripts/ops/verify_production_license_keypair.py \
  --env-file /etc/whut-campus-auto-login/license-server.env
```

Successful default output has exactly these fields:

```text
environment_file=pass
environment=production
configured_private_key=pass
configured_public_key=pass
configured_keypair_match=pass
configured_sign_verify=pass
public_key_sha256=<64 lowercase hexadecimal characters>
running_service_keypair=not_verified
result=PASS
```

Stop immediately if the command returns a non-zero exit code.

## Optional public-key output

Use this only when the public key is needed for the later controlled Windows
release-build session:

```bash
cd /opt/whut-campus-auto-login
sudo /opt/whut-campus-auto-login/.venv/bin/python \
  scripts/ops/verify_production_license_keypair.py \
  --env-file /etc/whut-campus-auto-login/license-server.env \
  --show-public-key
```

This adds one line:

```text
public_key_base64=<configured public key>
```

The private key remains on the server and must never be copied into a build
command, transcript, PR, issue, CI variable, or repository.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | All configured-key checks passed. |
| `1` | Unexpected but controlled failure. |
| `2` | Environment-file path, syntax, permission, or production-environment failure. |
| `3` | Configured private-key source or private-key/public-key format failure. |
| `4` | Configured public key does not match the private-key-derived public key. |
| `5` | Challenge signing or verification failed. |

## Stop conditions

Stop without attempting an in-session correction if any of these occurs:

- any non-zero exit code;
- unexpected output or a traceback;
- any appearance of the private key;
- an environment-file content, size, permission, or modification-time change;
- a private-key-file content, size, permission, or modification-time change;
- a configured key-pair mismatch.

Do not replace keys, edit the environment file, restart the service, or deploy
from the failed preflight session.

## Evidence handling

Retain only:

- the approved commit SHA;
- the UTC execution time;
- the safe output shown above;
- the `public_key_sha256` fingerprint.

Never retain:

- the environment file or a dump of it;
- the private-key file, its path, or a dump of it;
- the private key or any private-key digest;
- the random challenge or signature;
- administrator secrets;
- database contents;
- unrelated environment values.

## Result interpretation

`result=PASS` proves only that the environment file contains a matching
configured key pair. It does not prove:

- that the currently running service process reloaded the environment file;
- that DNS, TLS, Nginx, or public HTTPS works;
- that the final Windows EXE embeds the correct public key;
- that the complete device register, refresh, or authorization flow works.

The explicit `running_service_keypair=not_verified` field records this boundary.
Python may retain sensitive material in process memory and cannot guarantee
complete memory zeroization; do not claim that the key was fully cleared from
memory.

## Next stage

After ICP filing and public HTTPS readiness, P6-A1c-1 must verify a token from
the running production service and compare all three public-key fingerprints:

1. this server preflight fingerprint;
2. the Windows build-input fingerprint;
3. the packaged client fingerprint.

This preflight does not replace those checks.
