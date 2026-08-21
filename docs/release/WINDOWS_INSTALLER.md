# Windows Installer Guide

武汉理工校园网助手 — Inno Setup 6 Windows 安装器

---

## 概述

本文档说明如何使用 Inno Setup 6 构建 `WHUTCampusAutoLogin` Windows 安装器。

**前置条件**：必须先完成 PyInstaller 构建（`scripts\build_windows.ps1`），
再运行安装器构建脚本（`scripts\build_windows_installer.ps1`）。

## 发布 Channel

| Channel | Authenticode | 公开下载 | 文件标识 |
|------|------|------|------|
| `development` | No | No | `-development-setup.exe` |
| `public-beta` | No（明确且有意） | 仅 owner 批准后 | `-public-beta-setup.exe` |
| `production` | Yes，强制 | 仅完成全部验收后 | `-setup.exe` |

Public Beta is an explicitly unsigned release channel。
`Public Beta` 是独立的、明确标识的 unsigned release channel，不是 production
signing bypass。它仍要求 production-like
授权服务器 URL、正式 Ed25519 公钥、干净 Git、输入内容门禁、真实 SHA-256、
人工验收和 owner approval。构建成功不会自动设置 `PublicDownloadEnabled=Yes`。
Windows 可能显示 Unknown Publisher 或 SmartScreen/信誉提示；SHA-256 不是数字签名。

Signed Production Authenticode requirement remains unchanged。

---

## 前置：PyInstaller 构建

```powershell
# 在干净的 Python 3.11.9 构建虚拟环境中完成 Phase 1-B
powershell -ExecutionPolicy Bypass -File .\scripts\build_windows.ps1 `
    -Clean `
    -BuildEnvironment development `
    -LicensePublicKey "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
```

输出目录：`dist\WHUTCampusAutoLogin\`

---

## Inno Setup 版本

| 项目 | 要求 |
|------|------|
| Inno Setup | 6.x（6.2+ 推荐） |
| 下载地址 | https://jrsoftware.org/isdl.php |
| 脚本位置 | `installer\WHUTCampusAutoLogin.iss` |

> **注意**：禁止从不可信来源下载 Inno Setup。
> 禁止自动安装 Inno Setup 或下载未知二进制。

---

## 安装器构建命令

### Development 构建

```powershell
# 最简调用（自动检测 ISCC.exe 和 AppVersion）
powershell -ExecutionPolicy Bypass -File .\scripts\build_windows_installer.ps1 `
    -BuildEnvironment development

# 完整参数
powershell -ExecutionPolicy Bypass -File .\scripts\build_windows_installer.ps1 `
    -BuildEnvironment development `
    -InputDir "dist\WHUTCampusAutoLogin" `
    -OutputDir "installer\output" `
    -AppVersion "0.1.0" `
    -IsccPath "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
```

### Public Beta 构建

Public Beta 使用 production-like license inputs，但明确不执行 Authenticode：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_windows.ps1 `
    -Clean `
    -BuildEnvironment public-beta `
    -LicensePublicKey "<approved-production-ed25519-public-key>" `
    -LicenseServerUrl "https://<approved-production-license-server>"

powershell -ExecutionPolicy Bypass -File .\scripts\build_windows_installer.ps1 `
    -BuildEnvironment public-beta `
    -InputDir "dist\WHUTCampusAutoLogin" `
    -OutputDir "installer\output"
```

输出为 `WHUTCampusAutoLogin-<ver>-public-beta-setup.exe`，并生成同名
`-release-report.txt`。报告必须记录：

```text
ReleaseChannel: PublicBeta
Authenticode: NotSigned
CodeSigningStatus: IntentionallyUnsignedPublicBeta
ManualAcceptanceCompleted: No
OwnerApproval: No
PublicDownloadEnabled: No
```

安装器完成不代表可以公开下载；必须先完成隔离安装、升级、卸载、GUI 验收和 owner approval。

### Production 构建（尚未批准）

Production 构建目前不可用于正式发行。正式发布前必须满足：

- 正式 HTTPS 授权服务器 URL 已配置；
- 正式 Ed25519 公钥已嵌入；
- EXE 和安装器已通过代码签名证书签名；
- 完整的人工 GUI 验收已完成；
- 隔离安装/升级/卸载测试已完成；
- 项目所有者已明确批准发布。

---

## Development、Public Beta 与 Production 区分

| 项目 | Development | Public Beta | Production |
|------|-------------|------------|------------|
| 输出文件名 | `WHUTCampusAutoLogin-<ver>-development-setup.exe` | `WHUTCampusAutoLogin-<ver>-public-beta-setup.exe` | `WHUTCampusAutoLogin-<ver>-setup.exe` |
| 公钥 | 占位符（不可用于真实授权） | 正式 Ed25519 公钥 | 正式 Ed25519 公钥 |
| Git 状态要求 | 宽松 | 必须干净 | 必须干净 |
| 可向用户分发 | **否** | 仅 owner 批准后 | 仅满足全部发布前置条件后 |
| AppId | 相同固定 GUID | 相同固定 GUID | 相同固定 GUID |

> **警告**：Development 安装器禁止分发给最终用户。

---

## AppId 说明

```
{8A3F2B1C-4D7E-4F9A-B2C3-D1E4F5A6B7C8}
```

**此 GUID 首次生成后严禁修改。**

更换 AppId 的后果：
- Windows 会将新安装器识别为完全不同的产品；
- 旧版本无法自动升级，需要先卸载；
- "程序和功能"中会出现两条记录；
- 用户数据不会自动迁移。

Development、Public Beta 和 Production 使用同一个 AppId，以确保测试安装可以被后续版本升级覆盖。

---

## 安装模型

| 项目 | 配置 |
|------|------|
| 权限 | `PrivilegesRequired=lowest`（无 UAC 管理员提示） |
| 架构 | x64 兼容（Windows 10/11 x64） |
| 默认安装目录 | `%LOCALAPPDATA%\Programs\WHUTCampusAutoLogin` |
| 安装范围 | 当前用户 |

---

## 快捷方式

| 类型 | 行为 |
|------|------|
| 开始菜单 | 始终创建：「武汉理工校园网助手」 |
| 桌面 | 可选任务，**默认不勾选**（使用 `{autodesktop}`，当前用户桌面范畴，无需管理员权限） |
| 安装后启动 | 可选任务，默认勾选，以 `--startup-tray` 参数后台启动 |

> **不得**在安装过程中自动创建开机自启快捷方式。
> 开机自启由应用内「设置 → 开机自启」控制。

---

## 升级行为

| 场景 | 行为 |
|------|------|
| 高版本覆盖低版本 | 允许（标准升级） |
| 同版本再次安装 | 允许（维修性覆盖） |
| 低版本覆盖高版本 | **拒绝**（`[Code] InitializeSetup` 注册表版本比对弹窗拦截） |
| 用户 APPDATA 数据 | 保留不变 |
| 凭据（Credential Manager） | 保留不变 |
| 本地授权 token | 保留不变 |
| 已设置的开机自启 | 保留不变（由应用管理） |

升级时若应用正在运行，Inno Setup 会通过 Restart Manager 提示用户关闭应用，
**不会强制结束进程**，若应用无法关闭则安装中止。

### 降级策略

安装程序通过 Inno Setup `[Code]` 节中的 `InitializeSetup` 事件函数实现产品级降级保护：
1. 读取注册表中对应 AppId（`{8A3F2B1C-4D7E-4F9A-B2C3-D1E4F5A6B7C8}_is1`）已安装版本的 `DisplayVersion`；
2. 逐段对比版本号数值（Numeric Version Comparison）；
3. 若已安装版本高于当前安装包版本，弹出明确错误提示框并中断安装流程（Return False）；
4. 若相同版本（维修）或较高版本（升级），允许继续安装。

若需降级（如紧急回滚），必须：
1. 先手动卸载当前版本；
2. 再安装旧版本；
3. 用户 APPDATA 数据在卸载时保留，降级后仍可使用。

---

## 运行中应用处理

安装器通过 Inno Setup 官方 Restart Manager 机制处理正在运行的应用：

```ini
CloseApplications=yes
CloseApplicationsFilter=WHUTCampusAutoLogin.exe
RestartApplications=no
```

- 仅针对 `WHUTCampusAutoLogin.exe`，不影响其他进程；
- 提示用户关闭应用，不静默强杀；
- 若应用无法关闭，安装中止。

> **注意**：当前应用无 OS 级单实例互斥（未发现 QSharedMemory 或 Win32 named mutex）。
> Restart Manager 依赖文件锁定检测。若托盘应用关闭主窗口后仍在后台运行，
> Restart Manager 能正确检测到运行中的 EXE。

---

## 卸载行为

| 内容 | 卸载时行为 |
|------|-----------|
| 应用安装目录（`%LOCALAPPDATA%\Programs\WHUTCampusAutoLogin`） | **删除** |
| 开始菜单快捷方式 | **删除** |
| 桌面快捷方式（如已创建） | **删除** |
| Startup 文件夹快捷方式（`whut-campus-auto-login.lnk`） | **删除**（精确匹配，非通配符） |
| `%APPDATA%\WHUTCampusAutoLogin\`（用户日志、配置） | **保留** |
| Credential Manager 条目（校园网账号密码） | **保留** |
| DPAPI 加密数据 | **保留** |
| 本地授权 token | **保留** |
| Windows 卸载注册表条目 | 由 Inno Setup 自动删除 |

### 为什么默认保留用户数据

- 普通卸载与"彻底清除用户数据"是不同操作；
- 重装或升级必须保留正常用户状态；
- 删除凭据是不可逆的隐私操作，不应由安装器静默执行；
- 彻底清除配置应使用应用内的「清除配置」功能，该操作会通知用户并等待确认。

---

## 开机自启清理规则

卸载时精确删除：

```
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\whut-campus-auto-login.lnk
```

此文件名来自：

```python
# desktop_app/autostart/windows_startup.py
SHORTCUT_NAME = "whut-campus-auto-login.lnk"
```

规则：

- 仅删除此精确文件名；
- 不使用通配符；
- 不删除整个 Startup 目录；
- 不删除无法证明属于本应用的其他文件；
- 若快捷方式不存在（用户未启用自启），不报错。

---

## 安装器输出路径

输出目录（git-ignored）：

```
installer\output\
```

文件名格式：

```
WHUTCampusAutoLogin-<version>-development-setup.exe   # development
WHUTCampusAutoLogin-<version>-setup.exe               # production
```

---

## SHA-256

每次构建自动输出：

```
SHA-256: <64-char hex>
```

验证命令：

```powershell
Get-FileHash installer\output\WHUTCampusAutoLogin-<ver>-development-setup.exe -Algorithm SHA256
```

---

## Authenticode 代码签名

Production Authenticode 是强制发布门禁。签名实现集中在
`scripts/release/windows_signing.ps1`，不写入私钥、PFX 密码或任何其他秘密。

### Production 配置合同

Production 签名只接受 Windows Certificate Store 中由精确 SHA-1 thumbprint
选择的证书：

| 环境变量 | 要求 |
|------|------|
| `WINDOWS_SIGNING_ENABLED` | Production 必须为 `true`；Development 可为 `false` |
| `WINDOWS_SIGNING_CERT_SHA1` | 精确 40 位十六进制 thumbprint；忽略空格后规范化为大写 |
| `WINDOWS_SIGNING_STORE` | `CurrentUser` 或 `LocalMachine`，对应 `Cert:\...\My` |
| `WINDOWS_SIGNTOOL_PATH` | 可选的绝对 `signtool.exe` 路径；未提供时自动发现 Windows SDK x64 SignTool |
| `WINDOWS_SIGNING_TIMESTAMP_URL` | Production 必须配置 approved HTTPS RFC3161 timestamp URL |

证书必须：

- 包含 Code Signing EKU：`1.3.6.1.5.5.7.3.3`；
- 在当前时间有效；
- 暴露可用 private key；
- 不是 self-signed development certificate；
- 能完成 SignTool 签名和受信任验证。

不接受 subject-name 模糊匹配，也不接受 PFX/P12 密码参数、密码环境变量、
cloud signing 或硬件厂商专用流程。

### 签名顺序与验证

正式流程由现有脚本和共享 helper 强制执行：

1. PyInstaller 生成 `WHUTCampusAutoLogin.exe`；
2. Production preflight 发现 SignTool，并验证 thumbprint、证书有效期、EKU 和 private key；
3. 使用 `signtool sign /fd SHA256 /sha1 <thumbprint> /tr <RFC3161 URL> /td SHA256` 签名 app EXE；
4. 使用 `signtool verify` 和 `Get-AuthenticodeSignature` 验证 app EXE，状态必须为 `Valid` 且 signer thumbprint 必须匹配；
5. 只有 app EXE 验证通过后，才允许调用 `build_windows_installer.ps1` / ISCC；
6. ISCC 生成 installer 后，使用同一 signing identity 再次签名并验证 installer；
7. 只有 installer 签名验证通过后，才计算最终 SHA-256。

Production 缺少任一配置、工具、证书、private key、EKU、有效期、时间戳、
签名或验证条件时，流程必须 fail closed，并报告具体错误，例如
`CODE_SIGNING_CERT_NOT_FOUND` 或 `TIMESTAMP_CONFIGURATION_MISSING`。

Development 构建仍输出 `*-development-setup.exe`，不强制签名，也绝不能被视为
formal production release。

当前 V1 合同未要求单独签名 uninstaller；不扩大本轮范围。

即使签名成功，`ManualAcceptanceCompleted`、GUI/安装验收和 `OwnerApproval`
仍是后续人工发布门禁，脚本不会自动改为通过。

---

## 自动更新

**当前阶段尚未实现自动更新。**

---

## Production 发布门禁

只有同时满足以下条件，才可以向用户分发：

- [ ] 正式 HTTPS 授权服务器 URL 已配置并通过测试；
- [ ] 正式 Ed25519 公钥已嵌入；
- [ ] `WHUTCampusAutoLogin.exe` 已通过 Authenticode 签名；
- [ ] 安装器 EXE 已通过 Authenticode 签名；
- [ ] 在隔离 Windows 10/11 环境中完成完整安装/升级/卸载测试；
- [ ] 人工 GUI 验收（主窗口、托盘、中文、高 DPI）已完成；
- [ ] 无 UAC 提示已确认；
- [ ] 用户数据边界（APPDATA 保留）已验证；
- [ ] 项目所有者明确批准。

---

## 人工验收清单

安装器编译成功后，在隔离 Windows 环境中验证：

### 首次安装
- [ ] 无 UAC 管理员弹窗
- [ ] 默认安装目录为 `%LOCALAPPDATA%\Programs\WHUTCampusAutoLogin`
- [ ] 安装向导中文显示正确
- [ ] 开始菜单「武汉理工校园网助手」快捷方式存在
- [ ] 桌面快捷方式默认未创建
- [ ] 可选桌面快捷方式：勾选后正常工作
- [ ] 安装后「启动应用」任务启动应用
- [ ] 应用无控制台窗口
- [ ] 主窗口和托盘图标正常
- [ ] 中文文本正常显示
- [ ] 125%/150%/175% DPI 无异常
- [ ] 用户数据写入 `%APPDATA%\WHUTCampusAutoLogin\`
- [ ] 安装目录无用户日志或配置
- [ ] 不自动创建开机自启

### 覆盖安装（升级）
- [ ] 运行中应用出现关闭提示
- [ ] 不强制结束进程
- [ ] 相同版本覆盖：允许
- [ ] 高版本覆盖低版本：成功
- [ ] `%APPDATA%` 数据未丢失
- [ ] 授权文件未丢失
- [ ] 已有自启快捷方式未被破坏
- [ ] 安装目录无明显废弃文件

### 卸载
- [ ] 应用安装目录被移除
- [ ] 开始菜单快捷方式被移除
- [ ] 桌面快捷方式（如有）被移除
- [ ] `whut-campus-auto-login.lnk` 从 Startup 移除
- [ ] `%APPDATA%\WHUTCampusAutoLogin\` 保留
- [ ] Credential Manager 条目保留
- [ ] 无残留运行进程
- [ ] Windows 卸载列表条目消失

---

## 不得包含的内容

安装器输入（`dist\WHUTCampusAutoLogin\`）不得包含：

- 测试框架（pytest, _pytest, pluggy）
- 服务端代码（FastAPI, uvicorn, SQLAlchemy）
- 数据库文件（.db, .sqlite）
- 用户日志和配置
- 本地授权 token
- 校园网凭据
- 开发文档
- 构建日志
- `.git` 目录
- `.venv-build` 目录

构建脚本会在调用 ISCC 前自动验证上述内容。
