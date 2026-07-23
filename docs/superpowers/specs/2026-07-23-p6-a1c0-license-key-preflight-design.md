# P6-A1c-0B Production License Key Preflight Design

## Status

Approved design for implementation planning. This document defines the non-network, non-build portion of P6-A1c.

## Context

The Windows production build embeds a release license-server URL and an Ed25519 public key. Existing build validation proves that the public key is valid Base64 and decodes to 32 bytes, but it does not prove that the candidate public key belongs to the private key configured on the production license server.

A mismatched key pair would cause production clients to reject server-issued license tokens. The failure would affect trial activation, license refresh, and paid-license activation until a corrected client is rebuilt and redistributed.

Public HTTPS availability is currently blocked pending ICP filing completion. This preflight is intentionally independent of DNS, TLS, Nginx, public health checks, payment credentials, databases, and executable construction.

## Goals

1. Add a repeatable, fail-closed server-side preflight that verifies the configured production Ed25519 key pair.
2. Keep the production private key on the server at all times.
3. Reuse the same production cryptographic parsing and signing behavior used by the license server where practical.
4. Produce a stable SHA-256 fingerprint for the approved production public key.
5. Provide deterministic exit codes and safe, machine-readable output suitable for release evidence.
6. Add automated tests using temporary keys only.
7. Document the exact operational procedure and interpretation of results.

## Non-goals

This stage does not:

- verify public HTTPS, DNS, TLS certificates, Nginx, or `/healthz`;
- prove that the currently running service process has reloaded the environment file;
- issue a real trial, paid license, or device registration;
- read or modify the production database;
- construct or inspect a production EXE;
- generate, rotate, replace, or deploy signing keys;
- inspect or handle WeChat Pay, administrator, campus-network, or other unrelated secrets;
- modify systemd units or restart services.

## Proposed files

- `scripts/ops/verify_production_license_keypair.py`
- `tests/ops/test_verify_production_license_keypair.py`
- `docs/release/PRODUCTION_LICENSE_KEY_PREFLIGHT.md`

The implementation may add a small focused helper module only when direct reuse of existing license-server cryptographic code would otherwise create an import side effect. Any helper must remain narrowly scoped to Ed25519 key parsing, derivation, signing, or verification.

## Execution model

The script runs only on the server that stores the production environment file.

Example interface:

```bash
sudo /opt/whut-campus-auto-login/.venv/bin/python \
  scripts/ops/verify_production_license_keypair.py \
  --env-file /etc/whut-campus-auto-login/license-server.env
```

Optional public-key disclosure:

```bash
sudo /opt/whut-campus-auto-login/.venv/bin/python \
  scripts/ops/verify_production_license_keypair.py \
  --env-file /etc/whut-campus-auto-login/license-server.env \
  --show-public-key
```

The default output must not print the Base64 public key. The optional flag may print the public key because it is not secret, but explicit opt-in reduces unnecessary propagation into logs and transcripts.

## Input contract

### Environment file path

The script requires an explicit absolute path supplied through `--env-file`.

It must fail closed when:

- the path is relative;
- the path does not exist;
- the path is not a regular file;
- the path itself is a symbolic link;
- the file is group-readable, group-writable, other-readable, or other-writable;
- the file cannot be read safely.

Owner identity may be reported for operator review, but the implementation must not hard-code a specific numeric UID unless the existing deployment contract already does so.

### Supported file syntax

The parser must support only the simple production format actually used by this project:

```text
KEY=value
```

Permitted behavior:

- blank lines;
- comment lines whose first non-whitespace character is `#`;
- one assignment per line;
- values treated as literal text after the first `=`;
- optional surrounding whitespace around the key name only when consistent with the current production file and documented tests.

Rejected behavior:

- duplicate keys;
- `export KEY=value`;
- shell command substitution;
- variable expansion;
- line continuation;
- heredocs;
- shell statements;
- malformed keys;
- unsupported quoting semantics;
- NUL bytes or non-text input.

The implementation must not attempt to emulate the complete systemd `EnvironmentFile=` grammar. The release SOP must state the supported subset clearly.

### Whitelisted keys

The script may consume only:

- `LICENSE_SERVER_ENV`
- `LICENSE_PRIVATE_KEY`
- `LICENSE_PUBLIC_KEY`

All other keys must be ignored without being printed. The script must not dump the parsed environment map.

`LICENSE_SERVER_ENV` must equal `production` exactly after the same normalization used by the production application, or through a stricter equivalent check if the application uses no normalization.

## Cryptographic verification flow

1. Parse the approved environment file using the restricted parser.
2. Confirm `LICENSE_SERVER_ENV=production`.
3. Confirm both signing-key fields are present and non-empty.
4. Parse the private key with the same code path or format rules used by the production license server.
5. Parse the configured public key with the same code path or format rules used by the production license server or client verifier.
6. Derive the raw 32-byte Ed25519 public key from the parsed private key.
7. Compare the derived raw public key with the configured raw public key using a constant-time byte comparison.
8. Sign a fixed-domain, process-local challenge containing fresh random bytes.
9. Verify the resulting signature with the configured public key.
10. Compute SHA-256 over the raw 32-byte public key and render it as 64 lowercase hexadecimal characters.
11. Emit the safe result fields and exit with the defined status.

The challenge, signature, private key, and private-key-derived intermediate values must never be printed.

## Reuse of production code

The implementation must first identify the current production functions responsible for:

- decoding the configured private key;
- decoding the configured public key;
- constructing Ed25519 key objects;
- signing license data.

The preflight should reuse those functions when they are side-effect free and do not initialize the application, database, network clients, or logging of sensitive configuration.

When direct reuse would import unrelated runtime state, the implementation may extract a focused cryptographic helper used by both the service and the preflight. It must not create a second independent interpretation of the production key format.

## Safe output

Successful default output:

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

With `--show-public-key`, one additional line is allowed:

```text
public_key_base64=<configured production public key>
```

Failure output must:

- identify the failure category without echoing the rejected value;
- avoid traceback output for expected validation failures;
- never print the private key, complete parsed environment, random challenge, or signature;
- use stderr for the error summary;
- end with `result=FAIL` when normal output has begun.

Unexpected failures may include a short exception class or controlled message, but must still pass through a final redaction boundary before output.

## Exit codes

- `0`: all configured-key checks passed;
- `1`: unexpected controlled failure;
- `2`: environment-file path, syntax, permission, or production-environment failure;
- `3`: private-key or public-key format failure;
- `4`: configured public key does not match the public key derived from the configured private key;
- `5`: sign/verify self-test failure.

Tests and documentation must treat these exit codes as part of the public operational contract.

## Security properties

The implementation must preserve all of the following:

- no network access;
- no database access;
- no writes to the environment file or adjacent paths;
- no service restart or deployment action;
- no key generation or key replacement;
- no private-key output on stdout, stderr, exception text, or test diagnostics;
- no temporary file containing the private key;
- no logging configuration that captures parsed secret values;
- no acceptance of non-production environments;
- fail-closed behavior for ambiguous input syntax and file permissions.

The script may hold key objects and decoded bytes in process memory for the duration of the check. Python cannot guarantee complete memory zeroization; the documentation must not claim otherwise.

## Testing strategy

All automated tests must use temporary, runtime-generated Ed25519 keys. Production values must never appear in fixtures, snapshots, CI variables, or repository history.

Required coverage:

1. valid production environment and matching key pair passes;
2. configured public key from a different private key returns exit code `4`;
3. invalid private-key Base64 returns exit code `3`;
4. invalid public-key Base64 returns exit code `3`;
5. wrong decoded key lengths return exit code `3`;
6. missing private or public key returns a controlled failure;
7. non-production environment returns exit code `2`;
8. duplicate whitelisted keys are rejected;
9. unsupported shell syntax is rejected;
10. relative paths are rejected;
11. symbolic-link environment files are rejected;
12. over-permissive POSIX modes are rejected;
13. successful output does not contain the private key or challenge;
14. all expected failure paths do not contain supplied secret values;
15. `--show-public-key` prints only the public key in addition to normal safe fields;
16. the script performs no network calls;
17. the script performs no database calls;
18. the script does not modify the environment file;
19. public-key fingerprint is SHA-256 of the raw 32-byte public key, not the Base64 text;
20. exit codes and stdout/stderr routing match the documented contract.

POSIX-specific permission and symlink tests may be skipped on Windows when the platform cannot enforce equivalent semantics. They must execute in Linux CI or on the production-like server test environment before merge or deployment acceptance.

## Operational procedure

The release SOP will instruct the operator to:

1. sync the approved commit to the server without changing the environment file;
2. verify repository state and script checksum or commit SHA;
3. run the script with the production environment-file path;
4. record only the safe output;
5. compare the public-key fingerprint with the release record;
6. optionally rerun with `--show-public-key` only when preparing the later Windows production build input;
7. stop immediately on any non-zero exit code;
8. avoid service restart, key replacement, or manual correction during the preflight session.

A passing result means only that the configured production environment file contains a valid matching Ed25519 key pair and that the configured public key can verify a signature produced by the configured private key.

It does not prove that the currently running service process has reloaded that file. That proof is deferred to P6-A1c-1 through an end-to-end token verification against the running production service after public HTTPS becomes available.

## Acceptance criteria

The design is implemented successfully when:

- the script and SOP exist on the feature branch;
- the implementation reuses or shares the production key-format code rather than duplicating an independent format;
- required automated tests pass with temporary keys only;
- secret-redaction tests pass;
- no production key material appears in the repository or test output;
- the script is read-only and network-free;
- exit codes and output match this specification;
- an independent review finds no unresolved high- or medium-severity issue;
- a production server execution returns `result=PASS` and a frozen public-key fingerprint without printing the private key.

## Stage completion statement

After implementation, review, and successful server execution, the project may state:

```text
Configured production Ed25519 key pair: READY
Configured public-key fingerprint: FROZEN
Production private key left the server: NO
Running service end-to-end signing: NOT VERIFIED
Public HTTPS: BLOCKED pending ICP filing
Production Windows executable: NOT BUILT
Production release: NOT APPROVED
```
