from pathlib import Path


UNIT = Path("deploy/systemd/whut-license-server.service.example")
NGINX = Path("deploy/nginx/license.whutlogin.cn.conf.example")
ENV_EXAMPLE = Path("license_server/.env.example")
WRAPPER = Path("deploy/bin/whut-license-runtime-attestation-audit")
GATE = Path("deploy/libexec/whut-license-startup-gate.py")
SUDOERS = Path(
    "deploy/sudoers/whut-license-runtime-attestation-audit.example"
)
SOP = Path("docs/release/RUNNING_LICENSE_SERVER_ATTESTATION.md")
DEPLOYMENT_GUIDE = Path("docs/license_deploy_tencent_cloud.md")


def test_systemd_contract_uses_external_isolated_gate_and_fixed_app_dir():
    content = UNIT.read_text(encoding="utf-8")

    required = (
        "User=whutlogin",
        "Group=whutlogin",
        "RuntimeDirectory=whut-license-server",
        "RuntimeDirectoryMode=0750",
        "RuntimeDirectoryPreserve=no",
        "UMask=0077",
        "Environment=WEB_CONCURRENCY=1",
        "ExecStartPre=+/usr/bin/python3 -I "
        "/usr/local/libexec/whut-license-startup-gate",
        "ExecStart=/opt/whut-campus-auto-login/.venv/bin/python -I -m uvicorn "
        "--app-dir /opt/whut-campus-auto-login license_server.app:app "
        "--host 127.0.0.1 --port 8787 --workers 1",
    )
    for directive in required:
        assert directive in content
    assert "2c555007" not in content


def test_nginx_blocks_entire_runtime_attestation_prefix_in_both_servers():
    content = NGINX.read_text(encoding="utf-8")

    assert content.count(
        "location ^~ /internal/runtime-attestation {"
    ) == 2
    for server in content.split("server {")[1:]:
        assert server.index(
            "location ^~ /internal/runtime-attestation"
        ) < server.index("location /")


def test_environment_example_is_default_disabled_without_frozen_old_commit():
    content = ENV_EXAMPLE.read_text(encoding="utf-8")

    assert "LICENSE_RUNTIME_ATTESTATION_ENABLED=false" in content
    assert "LICENSE_RUNTIME_SOURCE_COMMIT=" in content
    assert "2c555007" not in content


def test_root_wrapper_is_no_argument_and_uses_only_fixed_targets():
    content = WRAPPER.read_text(encoding="utf-8")
    normalized = " ".join(content.replace("\\", "").split())

    assert 'if [ "$#" -ne 0 ]; then' in content
    assert "/usr/bin/env -i" in content
    assert (
        "/usr/bin/python3 -I "
        "/usr/local/libexec/whut-license-startup-gate"
    ) in normalized
    assert (
        "/opt/whut-campus-auto-login/.venv/bin/python -I "
        "/opt/whut-campus-auto-login/scripts/ops/"
        "verify_running_license_server_attestation.py --live-audit"
    ) in normalized
    for unsafe in ("$1", '"$@"', "--socket", "--service", "--public-key"):
        assert unsafe not in content
    assert normalized.index("/usr/local/libexec/whut-license-startup-gate") < (
        normalized.index("verify_running_license_server_attestation.py")
    )


def test_external_gate_source_is_outside_deployment_runtime_and_import_safe():
    content = GATE.read_text(encoding="utf-8")

    assert "from license_server" not in content
    assert "import license_server" not in content
    assert "from app_version" not in content
    assert "sys.path.insert" not in content
    assert "ast.parse" in content
    assert "/usr/bin/git" in content
    assert "shell=True" not in content


def test_deployment_guide_does_not_grant_service_user_write_access_to_code():
    content = DEPLOYMENT_GUIDE.read_text(encoding="utf-8")

    assert "sudo chown -R root:root /opt/whut-campus-auto-login" in content
    assert "sudo chown -R whutlogin:whutlogin /opt/whut-campus-auto-login" not in content
    assert "/usr/local/libexec/whut-license-startup-gate" in content


def test_sudoers_grants_only_the_installed_no_argument_wrapper():
    content = SUDOERS.read_text(encoding="utf-8")

    assert (
        "/usr/local/sbin/whut-license-runtime-attestation-audit"
        in content
    )
    assert "verify_running_license_server_attestation.py" not in content
    assert "/bin/sh" not in content
    assert "ALL=(ALL)" not in content


def test_sop_freezes_security_boundary_and_no_database_migration():
    content = SOP.read_text(encoding="utf-8")

    required = (
        "/run/whut-license-server/runtime-attestation.sock",
        "/usr/local/sbin/whut-license-runtime-attestation-audit",
        "LICENSE_RUNTIME_SOURCE_COMMIT",
        "public_key_sha256",
        "Windows",
        "404",
        "密钥轮换",
        "回滚",
        "不需要数据库迁移",
        "不证明真实支付",
    )
    for fragment in required:
        assert fragment in content
    assert "2c555007" not in content


def test_attestation_runtime_has_no_database_dependency_or_http_route():
    runtime = Path("license_server/runtime_attestation.py").read_text(
        encoding="utf-8"
    )
    app = Path("license_server/app.py").read_text(encoding="utf-8")

    assert "license_server.db" not in runtime
    assert "sqlite" not in runtime.lower()
    assert '@app.get("/internal/runtime-attestation' not in app
    assert '@app.post("/internal/runtime-attestation' not in app
