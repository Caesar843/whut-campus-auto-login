# P6-A1c-2 Release Artifact Attestation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add offline, deterministic Windows `onedir` artifact-attestation tooling without performing a production build.

**Architecture:** One tested CLI orchestrates a focused standard-library helper module.  The helper creates and verifies release evidence, scans unsafe content, collects local metadata, and delegates frozen archive reading to a narrow PyInstaller adapter.

**Tech Stack:** Python 3.11 standard library; project-pinned PyInstaller 6.21.0 archive reader; pytest.

## Global Constraints

- Do not run a production build, start an EXE, make network requests, or use real production URL/key/private-key material.
- Do not modify service, database, payment, campus-login, UI, build-baseline, or business logic.
- Persist only redacted booleans and public-key SHA-256; never persist the approved URL, full key, session ID, token, environment values, or absolute paths.
- Support only `onedir`; use temporary sibling output and atomic final replacement.

---

### Task 1: Manifest, ZIP, and checksums

**Files:**
- Create: `scripts/release_attestation.py`
- Create: `tests/test_windows_release_artifact_attestation.py`

**Interfaces:**
- Produces `build_manifest()`, `create_release_zip()`, `verify_zip_against_manifest()`, and `write_sha256sums()`.

- [x] Write failing tests for deterministic manifest ordering, escaping path rejection, file hashes, ZIP member whitelist, ZIP/manifest equality, and checksum coverage.
- [x] Run the selected tests; expected failure is `ModuleNotFoundError` for `scripts.release_attestation`.
- [x] Implement the smallest standard-library functions using `hashlib`, `json`, `zipfile`, and `pathlib`.
- [x] Re-run selected tests; expected result is pass.

### Task 2: Redacted embedded-config validation, SBOM, licenses, and scanning

**Files:**
- Modify: `scripts/release_attestation.py`
- Modify: `tests/test_windows_release_artifact_attestation.py`

**Interfaces:**
- Produces `verify_embedded_build_config()`, `build_spdx_sbom()`, `collect_local_licenses()`, and `scan_forbidden_content()`.

- [x] Write failing tests for configuration absence, production environment, URL/key rejection and redaction, SPDX scopes, local license metadata/files/missing/collision, and forbidden-content pass/fail.
- [x] Run selected tests; expected failure is missing functions or wrong behavior.
- [x] Implement validation with the existing release URL validator and a PyInstaller-reader adapter that never executes an artifact.
- [x] Re-run selected tests; expected result is pass.

### Task 3: Atomic CLI and operator SOP

**Files:**
- Create: `scripts/release_artifact_attestation.py`
- Modify: `tests/test_windows_release_artifact_attestation.py`
- Modify: `docs/release/WINDOWS_RELEASE_BUILD.md`

**Interfaces:**
- CLI accepts `--onedir`, `--staging-dir`, `--source-commit`, `--app-version`, `--build-environment`, `--approved-license-server-url`, `--expected-public-key-sha256`, `--python-version`, and `--pyinstaller-version`.

- [x] Write failing CLI tests for successful redacted output, controlled error output, no secret echo, and temporary-output cleanup.
- [x] Run selected tests; expected failure is absent CLI.
- [x] Implement the orchestrator with temporary sibling staging, atomic replacement, nonzero critical-failure exit, and no accepted partial evidence.
- [x] Update the SOP to state Stage 1 tooling versus Stage 2 future human-controlled attestation.
- [x] Re-run selected tests; expected result is pass.

### Task 4: Verification and review

**Files:**
- Modify only files above if a verified defect requires it.

- [x] Run the targeted attestation tests, then the complete pytest suite, `git diff --check`, and a local forbidden-content scan of the diff.
- [x] Run CodeRabbit review if locally available; otherwise record its exact unavailability.
- [x] Create one commit, push the feature branch, and open a Draft PR; do not merge or run a production build.
