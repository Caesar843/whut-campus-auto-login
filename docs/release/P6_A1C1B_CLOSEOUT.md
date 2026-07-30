# P6-A1c-1B 运行中授权服务证明阶段收尾记录

## 1. 状态

- 阶段：`P6-A1c-1B`
- 结论：`COMPLETE`
- 收尾日期：2026-07-30
- 最终 `main` SHA：`3e4ed02536a0bde91e6ee24e2cd35864a2adac4d`
- 功能分支最终 SHA：`ba52b3110a47ede93bc3bd6eca42d825b4d4d77d`
- 合并提交：`1fcb4d4195a235da539dbd74638049b74b7047df`
- 原 `main` 侧提交：`227d22bd805621446417640d293229da85d263f5`

本阶段完成了运行中授权服务密钥与进程证明机制的实现、跨平台回归测试、原生 Ubuntu 特权验证、systemd 首次启动与重启验证，以及最终证据归档和测试环境清理。

## 2. 验证范围

本阶段证明：

1. systemd `MainPID` 运行的是预期部署树中的授权服务进程；
2. 部署源码、Git 提交、虚拟环境解释器链、固定 wrapper、startup gate、unit、公钥文件和相关父目录满足既定所有权、权限、ACL 和符号链接约束；
3. 运行进程加载的 Ed25519 私钥可派生出审计输出中的公钥指纹；
4. Unix Socket 对端身份、进程身份、源码树、签名负载和固定提交可以被独立核对；
5. 审计 wrapper 成功输出严格遵守十行合同，失败路径继续 fail closed。

本阶段不证明真实支付、DNS、TLS、公网流量、生产数据库、真实授权签发或生产发布已经完成。机制边界以 `docs/release/RUNNING_LICENSE_SERVER_ATTESTATION.md` 为准。

## 3. 最终验证矩阵

### 3.1 Windows

最终合并候选在 Windows 上完成完整测试：

- `1885 passed`
- `50 skipped`
- `0 failed`
- `1 warning`，为已知 Starlette/httpx deprecation warning
- `compileall`：通过
- `git diff --check`：通过

Windows 专用兼容修复仅使 `os.getxattr` mock 在缺少该原生属性的平台上可以安装；原 ACL 安全语义和 Linux 实际验证未被放宽。

### 3.2 原生 Ubuntu

验证环境：Ubuntu 24.04.4 LTS、systemd PID 1、ext4、Python 3.12。

最终合并候选 `3e4ed02536a0bde91e6ee24e2cd35864a2adac4d` 完成：

- POSIX shell 语法检查：通过；
- Startup Gate 测试：`0 failed`、`0 skipped`、退出码 `0`；
- Phase 1：`0 failed`、`0 skipped`、退出码 `0`；
- Privileged Phase 2：`16 passed`、`0 failed`、`0 skipped`、退出码 `0`；
- Phase 3 首次 systemd 启动：通过；
- `/healthz`：通过；
- `/internal/runtime-attestation` 前缀、尾部斜杠和随机子路径：均返回 `404`；
- RuntimeDirectory 与 Unix Socket 所有权、权限和非符号链接约束：通过；
- 首次 live audit：退出码 `0`、stdout `10` 行、stderr `0` 行；
- systemd 重启后 MainPID 更换：通过；
- 重启后 Runtime Socket inode 更换：通过；
- 重启后 live audit：退出码 `0`、stdout `10` 行、stderr `0` 行；
- `source_commit=3e4ed02536a0bde91e6ee24e2cd35864a2adac4d`；
- `NRestarts=0`。

最终状态：

```text
MERGE_V5_NATIVE_VALIDATION_COMPLETE
MERGE_V5_RESTART_SCRIPT_EXIT_CODE=0
```

## 4. 本阶段闭环的问题

本阶段开发和验证过程中发现并关闭：

1. startup gate 对标准 venv `.venv/lib64 -> lib` 别名的安全兼容问题；
2. Unix Socket 对端提前断开造成的预期 `EPIPE`、`ECONNRESET`、`ENOTCONN` 测试竞态；
3. live audit 错误按符号链接自身固定 `0777` mode 判定解释器路径不安全的问题；
4. live audit 对解释器符号链接链缺少逐跳所有权、父目录和最终目标验证的问题；
5. audit wrapper 将 Startup Gate 的成功 `result=PASS` 混入正式十行审计输出的问题；
6. Windows 中 `os.getxattr` 不存在导致 ACL mock 测试在进入产品逻辑前失败的问题；
7. 已分叉的 `main` 与功能分支通过保留双方历史的 merge commit 安全整合，没有 rebase、cherry-pick 或 force push。

## 5. 安全边界保持情况

以下边界未被放宽：

- Startup Gate 任一检查失败即拒绝启动；
- Gate 失败退出码、stdout 和 stderr 诊断继续保留；
- Auditor 仅在 Gate 成功后启动；
- 成功审计 stdout 严格为十行，stderr 必须为空；
- 最终解释器必须是 root-owned regular file、组和其他用户不可写、owner executable；
- 符号链接链逐跳检查 root ownership 和父目录控制；
- dangling link、循环、异常文件类型和不安全权限继续 fail closed；
- 审计不记录私钥、完整公钥、challenge、签名、环境变量、Token 或数据库内容；
- 校园网账号密码仍只保存在客户端本机，不上传授权服务器。

## 6. 最终证据归档

最终证据包：

```text
p6-a1c1b-final-evidence-v5.tar.gz
```

SHA-256：

```text
3d4380e60a1faf7af82482af84f0f57aa2fcbb568d4a5a68d9a96ede02e7d815
```

归档包括：

- Native Ubuntu Startup Gate 日志；
- Phase 1 日志；
- Privileged Phase 2 日志；
- 首次启动和重启后的 live-audit stdout/stderr；
- Git 与 merge history 证据；
- 清理前部署元数据；
- 清理后固定路径与端口状态；
- 已验证的 Bundle v5；
- 文件级 `SHA256SUMS`。

归档明确排除：环境文件、私钥、生成的密钥文件、测试数据库内容和明文敏感信息。大型归档仅在本地或受控备份中保存，不提交到 Git。

## 7. 收尾清理结果

Ubuntu 测试环境已确认：

```text
SERVICE_LOAD_STATE=not-found
PORT_8787_LISTENERS=0
WHUTLOGIN_USER=absent
WHUTLOGIN_GROUP=absent
UBUNTU_STAGE_CLOSEOUT_COMPLETE
```

同时已完成：

- 删除固定测试部署、临时密钥、测试数据库、unit、sudoers、wrapper 和 RuntimeDirectory；
- 删除 v2、v3、v4、merge candidate v5 临时仓库；
- 删除中间 Bundle、传输文件和临时日志；
- 保留基础仓库和最终证据压缩包；
- Windows 端重新核对归档 SHA-256；
- 清除 `AGENTS.md` 中由工具写入的临时 memory context；
- 本地切回并同步 `main`；
- 删除已合并的本地和远端功能分支；
- 最终工作区 clean。

## 8. 后续开发入口

后续任务必须：

1. 从 clean 的 `main` 和完整 SHA `3e4ed02536a0bde91e6ee24e2cd35864a2adac4d` 开始；
2. 新建独立功能分支；
3. 不继续复用 P6-A1c-1B 的临时排错清单、测试部署或密钥；
4. 生产启用前重新执行部署前冻结、三处公钥指纹比较、Startup Gate、live audit、HTTP 404 边界和回滚检查；
5. 将生产部署与本次原生 Ubuntu 验证明确区分，未经生产验收不得标记为已上线。
