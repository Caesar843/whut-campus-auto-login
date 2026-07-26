# P6-A1c-2 Windows release artifact attestation design

## Scope

This phase adds offline tooling only.  It does not build, sign, publish, upload,
or deploy a release and it accepts no production value in this repository.

`scripts/release_artifact_attestation.py` is the single command-line entry
point.  It coordinates an existing `onedir` directory, writes all derived
evidence into a caller-selected staging directory, and prints only a redacted
summary.  `scripts/release_attestation.py` contains the deterministic,
side-effect-bounded helpers used by the CLI and tests.

## Inputs and safe evidence

The CLI receives the onedir directory, staging directory, source commit,
app version, local Python and PyInstaller versions, an approved release URL,
and an expected public-key SHA-256 fingerprint.  The URL is process-only: it
is compared and revalidated but never persisted or printed.  The full key is
read only from the frozen artifact, decoded as a 32-byte Ed25519 public key,
and never written or printed.  Evidence records only validation booleans and
the fingerprint.

The manifest is deterministic UTF-8 JSON with sorted file records.  A record
contains a normalized relative POSIX path, byte length, and SHA-256.  Relative
paths that escape the selected `onedir` directory are rejected.  The manifest
contains version, commit, build metadata, packaging mode, fingerprint, and
redacted verification status; it contains no absolute path, URL, key,
session ID, environment dump, token, or private material.

## Offline inspection and content policy

The implementation uses the PyInstaller 6.x archive reader behind a small
adapter.  It lists/extracts archive members without launching the executable;
an unavailable or incompatible reader fails with one controlled error.  The
adapter requires the generated embedded configuration module and checks
`BUILD_ENVIRONMENT == "production"`, the exact approved HTTPS non-loopback
URL after `validate_release_server_url`, a valid 32-byte Base64 public key,
and the expected fingerprint.

The attestor creates a ZIP from only the `onedir` tree in lexical path order.
It verifies extracted member hashes against the manifest and writes SHA256SUMS
for the EXE, ZIP, manifest, SBOM, and license archive.  The scanner examines
the onedir tree, ZIP members, and output evidence for sensitive markers,
disallowed paths, source/test/server material, exposed cache/bytecode, and
absolute-path or environment-dump evidence.  It reports category/count/path,
never matched content.  Internal PyInstaller archive bytecode is not treated
as an exposed dist file.

The SBOM is SPDX 2.3 JSON.  It records packages as `bundled`, `build-test`, or
`uncertain`: only archive/artifact evidence yields `bundled`; installed local
metadata alone is not a bundle claim.  License collection uses only local
`importlib.metadata` and conventional distribution files.  Missing licenses
are recorded as missing with `NOASSERTION`; no network lookup or guessed text
is permitted.

## Failure and release process

All output is produced in a temporary sibling directory and atomically moved
to the requested staging directory only after every critical check succeeds.
Failure returns nonzero, removes temporary evidence, leaves user input intact,
and never labels partial output accepted.

Stage 1 is this tooling review, tests, Draft PR, and merge.  Stage 2 is a
separate human-controlled clean-main build with approved process-only inputs,
attestation, manual acceptance, and only then a signing/release decision.
