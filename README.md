# 武汉理工校园网自动登录小工具

一个只面向武汉理工大学校园网环境的 Windows 桌面小工具：保存一次校园网账号密码，之后电脑开机时在后台自动启动，并在已连接校园网环境的前提下自动完成认证登录。

**本项目永久免费**：无任何商业化能力，也不需要注册、激活或付费。软件开箱即用，全部功能对所有用户开放。

## 功能

- 输入并保存校园网账号密码（密码只存本机，见下文隐私边界）；
- 开机自动启动，托盘后台运行；
- 在已连接校园网环境时自动尝试武汉理工校园网认证登录；
- 手动测试登录、登出校园网、重新登录；
- 修改账号密码、清除本机配置；
- 基础状态展示与运行日志查看；
- 永久免费使用。软件启动时与校园网登录成功后各上报一次设备使用情况（仅设备指纹哈希与时间戳），用于服务端统计使用人数与活跃度；上报失败只记日志，不影响任何功能。

## 隐私与安全边界

- 校园网账号密码只保存在本机：密码存入 Windows Credential Manager（advapi32 CredWriteW/CredReadW），本地 `config.json` 只保存用户名、自启开关等非敏感字段；
- 不上传校园网账号密码，不在日志、错误信息中输出明文密码；
- 设备指纹在本机生成：多字段组合加固定盐后做 SHA-256，只上传哈希值（`device_fingerprint_hash`），不上传任何硬件明文信息；
- 服务端 devices 表只保存产品 ID、设备指纹哈希、首见/末见时间；
- 签名私钥与后台管理令牌永不入仓、不入日志、不入客户端。

## 项目结构

| 目录 | 说明 |
| --- | --- |
| `desktop_app/` | 桌面界面、托盘、开机自启、配置管理、使用状态展示 |
| `campus_login/` | 武汉理工校园网认证登录核心（不依赖 UI 与授权服务） |
| `license_client/` | 免费版放行判定、设备指纹、使用情况上报 |
| `license_server/` | 设备注册、免费授权签发（`license_type=free`）、只读后台、运行时证明 |
| `docs/` | 设计、部署、发布、测试文档 |
| `tests/` | 自动化测试 |
| `scripts/` | 构建、开发与运维辅助脚本 |
| `deploy/` | Nginx、systemd、sudoers 等部署示例 |
| `installer/` | Inno Setup 安装器脚本 |
| `shared/` | 预留的客户端/服务端共享常量目录 |

## 技术路线

- 客户端：Python 3.11 + PySide6，PyInstaller 打包（发布基线：Windows 10/11 x64、Python 3.11.9、PyInstaller 6.21.0、`onedir`）；
- 服务端：FastAPI + SQLite + Nginx + systemd（详见 `docs/license_deploy_tencent_cloud.md`）；
- 安装器：Inno Setup 6，当前用户安装、无需管理员权限（详见 `docs/release/WINDOWS_INSTALLER.md`）。

## 快速开始（开发）

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-client.txt
python desktop_app\tray_app.py
```

命令行测试登录（凭据来自环境变量 `WHUT_NET_USERNAME` / `WHUT_NET_PASSWORD`，或加 `--use-saved-config` 读取本机已保存配置）：

```powershell
python scripts\dev\test_login.py
python scripts\dev\test_login.py --use-saved-config
```

服务端本地启动：

```powershell
pip install -r requirements-server.txt
uvicorn license_server.app:app --host 127.0.0.1 --port 8787
curl http://127.0.0.1:8787/healthz
```

## 运行测试

Windows 发布基线（发布前必跑）：

```powershell
& 'C:\Users\lenovo\AppData\Local\Programs\Python\Python311\python.exe' -m pytest tests/test_windows_release_baseline.py tests/test_windows_installer_baseline.py -q -p no:cacheprovider
```

客户端子集（Windows 发布 SOP 固定命令）：

```powershell
python -m pytest -p no:cacheprovider tests\campus_login tests\client tests\license_client tests\test_windows_build_config_lifecycle.py tests\test_windows_build_environment.py tests\test_windows_release_baseline.py
```

完整测试套件需在另装 `requirements-server.txt` 的开发环境中执行 `python -m pytest -p no:cacheprovider`。

## 文档索引

- `docs/design/PROJECT_BRIEF.md` — 产品背景与免费版边界（开发前必读）；
- `docs/design/MVP_SCOPE.md` — 第一版范围与不做清单；
- `docs/design/ARCHITECTURE.md` — 模块分层与数据流；
- `docs/design/LICENSE_AND_FREE_VERSION.md` — 免费版授权与使用统计设计说明；
- `docs/license_deploy_tencent_cloud.md` — 授权服务腾讯云部署说明；
- `docs/deploy/LICENSE_SERVER_PRODUCTION_CONFIG.md` — 服务端生产配置；
- `docs/release/WINDOWS_RELEASE_BUILD.md`、`docs/release/WINDOWS_INSTALLER.md` — Windows 构建与安装器；
- `docs/release/PRODUCTION_LICENSE_KEY_PREFLIGHT.md` — 生产签名密钥预检 SOP。

## 授权服务说明（免费版）

服务端仅保留设备注册（`POST /device/register`）、授权刷新（`POST /license/refresh`）、内部只读后台（`/internal/admin/`）与运行时证明。新设备注册即签发永久免费授权（`license_type=free`、`expires_at=9999-12-31T00:00:00Z`）。授权服务不参与客户端功能开关：客户端本地一律放行，授权服务器不可用时所有功能照常使用。
