# Privileged Attestation Entrypoints Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ensure root never executes deployment-tree code before an external trusted gate verifies the deployment and runtime chain.

**Architecture:** Install a standard-library-only gate source outside the repository at `/usr/local/libexec/whut-license-startup-gate` and execute it with `/usr/bin/python3 -I`. The gate verifies fixed paths, ownership, ancestor chains, ACLs, symlinks, venv interpreter resolution, Git read-only state, and `whutlogin` effective write access before systemd or the root audit wrapper may execute the deployment venv.

**Tech Stack:** Python 3 standard library, systemd, POSIX filesystem metadata and ACL tooling, Git, pytest.

## Global Constraints

- Preserve the existing three commits and create only `fix(deploy): harden privileged attestation entrypoints`.
- No production access, deployment, migration, payment, token-wire, Worker, admin, client, or Windows-package changes.
- Gate source imports no deployment module and executes no deployment venv, Uvicorn, Git hook, or repository code before verification.
- Fixed app directory is `/opt/whut-campus-auto-login`; it cannot be overridden by an argument or environment variable.
- Windows remains import-safe; POSIX ACL/systemd tests explicitly skip outside Linux.

---

### Task 1: Freeze trusted-entrypoint deployment contracts

**Files:**
- Modify: `tests/ops/test_runtime_attestation_deploy_contract.py`
- Modify: `tests/ops/test_verify_running_license_server_attestation.py`

**Interfaces:**
- Consumes: fixed production paths and unit templates.
- Produces: failing checks for external gate location, `-I`, fixed `--app-dir`, no deployment imports before gate, ACL/path-chain validation, and wrapper ordering.

- [ ] **Step 1: Write failing deployment contract tests**

```python
assert "ExecStartPre=+/usr/bin/python3 -I /usr/local/libexec/whut-license-startup-gate" in unit
assert "--app-dir /opt/whut-campus-auto-login" in unit
assert "from license_server" not in gate_source
assert "/opt/whut-campus-auto-login/.venv" not in gate_source
```

- [ ] **Step 2: Run tests to verify RED**

Run: `python -m pytest -p no:cacheprovider -ra tests/ops/test_runtime_attestation_deploy_contract.py tests/ops/test_verify_running_license_server_attestation.py`

Expected: FAIL because the unit and wrapper still execute deployment venv code before a trusted external gate.

- [ ] **Step 3: Add helper-level RED tests**

```python
with pytest.raises(gate.GateError):
    gate.validate_path_chain(untrusted_parent)
with pytest.raises(gate.GateError):
    gate.validate_acl(writable_acl)
```

- [ ] **Step 4: Run helper tests to verify RED**

Run: `python -m pytest -p no:cacheprovider -ra tests/ops/test_privileged_startup_gate.py`

Expected: FAIL because the external gate module does not exist.

### Task 2: Implement the external trusted gate

**Files:**
- Create: `deploy/libexec/whut-license-startup-gate.py`
- Create: `tests/ops/test_privileged_startup_gate.py`

**Interfaces:**
- Consumes: no command-line arguments; fixed path constants only.
- Produces: exit zero only after read-only validation; nonzero stable error otherwise.

- [ ] **Step 1: Implement minimal standard-library gate**

```python
DEPLOY_ROOT = Path("/opt/whut-campus-auto-login")
APP_DIR = DEPLOY_ROOT
SYSTEM_PYTHON = Path("/usr/bin/python3")

def main() -> int:
    validate_fixed_root_owned_gate_context()
    validate_deployment_tree_and_acl()
    validate_venv_python_chain()
    validate_read_only_git_head_and_clean_tree()
    return 0
```

The implementation must parse `app_version.py` through `ast.parse`, use fixed sanitized Git arguments with hooks/fsmonitor disabled and optional locks disabled, never use `shell=True`, and never import a repository package.

- [ ] **Step 2: Run gate tests to verify GREEN**

Run: `python -m pytest -p no:cacheprovider -ra tests/ops/test_privileged_startup_gate.py`

Expected: PASS on portable tests; Linux-only ACL checks are explicitly skipped elsewhere.

### Task 3: Wire systemd and root live-audit through the external gate

**Files:**
- Modify: `deploy/systemd/whut-license-server.service.example`
- Modify: `deploy/bin/whut-license-runtime-attestation-audit`
- Modify: `deploy/sudoers/whut-license-runtime-attestation-audit.example`
- Modify: `docs/release/RUNNING_LICENSE_SERVER_ATTESTATION.md`
- Modify: `tests/ops/test_runtime_attestation_deploy_contract.py`

**Interfaces:**
- Consumes: `/usr/local/libexec/whut-license-startup-gate` and fixed production paths.
- Produces: an external root preflight followed by `python -I -m uvicorn --app-dir /opt/whut-campus-auto-login`; wrapper rejects args, clears environment, invokes gate first, and only then runs deployment live-audit.

- [ ] **Step 1: Implement only fixed commands**

```text
ExecStartPre=+/usr/bin/python3 -I /usr/local/libexec/whut-license-startup-gate
ExecStart=/opt/whut-campus-auto-login/.venv/bin/python -I -m uvicorn --app-dir /opt/whut-campus-auto-login license_server.app:app --host 127.0.0.1 --port 8787 --workers 1
```

- [ ] **Step 2: Verify deployment contracts**

Run: `python -m pytest -p no:cacheprovider -ra tests/ops/test_runtime_attestation_deploy_contract.py`

Expected: PASS.

### Task 4: Regression verification and one commit

**Files:**
- Modify only files created or changed above, plus any narrowly required tests/docs.

- [ ] **Step 1: Run focused regression suites**

Run: `python -m pytest -p no:cacheprovider -ra tests/ops/test_privileged_startup_gate.py tests/ops/test_runtime_attestation_deploy_contract.py tests/ops/test_verify_running_license_server_attestation.py tests/license_server/test_signer.py tests/license_server/test_device_proof.py tests/license_server/test_license_server.py tests/license_server/test_payment_api.py`

- [ ] **Step 2: Run full verification**

Run: `python -m pytest -p no:cacheprovider -ra; python -m compileall -q license_server scripts deploy; git diff --check`

- [ ] **Step 3: Review and commit once**

Run CodeRabbit if available; otherwise record its unavailability. Stage only this plan and hardening changes, then commit:

```bash
git commit -m "fix(deploy): harden privileged attestation entrypoints"
```
