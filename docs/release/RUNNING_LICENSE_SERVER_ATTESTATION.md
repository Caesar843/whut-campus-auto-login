# 运行中授权服务密钥与进程证明 SOP

## 适用边界

本机制只证明当前 systemd `MainPID` 正在运行经核对的源码，并且该进程
加载的 Ed25519 私钥可派生出输出的 `public_key_sha256`。它不读取或写入
业务数据库，不签发授权 Token，不改变支付、授权、后台或 Worker，也
不证明真实支付、DNS、TLS 或公网业务链路可用。不需要数据库迁移。

机制默认关闭，仅支持原生 Linux。Windows 可做 import-safe 和纯函数测试；
WSL 可做测试模式协议验证，但生产启用会 fail closed。生产 socket 固定为
`/run/whut-license-server/runtime-attestation.sock`，不得改成配置项。

## 部署前冻结

1. 只从最终审查并合并的部署 commit 安装
   `/opt/whut-campus-auto-login`，不得使用旧基线或缩写 SHA。
2. 确认仓库 `HEAD` 等于该完整 40 位小写 SHA，且 tracked/untracked
   工作区均 clean。
3. 部署目录、`.git`、所有 tracked 文件及父目录必须 root 所有，禁止
   组或其他用户写入，禁止不安全符号链接；`whutlogin` 不得写部署目录
   或源码。
4. 将该 SHA 写入 root 管理的
   `/etc/whut-campus-auto-login/license-server.env`：

```text
LICENSE_RUNTIME_ATTESTATION_ENABLED=true
LICENSE_RUNTIME_SOURCE_COMMIT=<最终完整部署 commit>
```

5. 固定公钥文件为
   `/etc/whut-campus-auto-login/license-public-key.b64`。它必须是 root
   所有、非符号链接、普通文件且组/其他用户不可写；不得把私钥放入该文件。
6. 将 unit 安装为
   `/etc/systemd/system/whut-license-server.service`。将
   `deploy/bin/whut-license-runtime-attestation-audit` 安装为
   `/usr/local/sbin/whut-license-runtime-attestation-audit`，root:root、
   mode 0755、普通用户不可写。安装 sudoers 示例前只替换固定审计账户，
   文件必须 root:root、mode 0440，并用 `visudo -cf` 验证。

不得从审计账户可写目录安装 unit、wrapper、Python、源码、公钥或环境文件。
不得把 socket、service、公钥或部署目录暴露为 wrapper 参数。

## systemd 与 socket

unit 固定 `User/Group=whutlogin`、`WEB_CONCURRENCY=1`、uvicorn
`--workers 1`、`UMask=0077`、`RuntimeDirectory=whut-license-server`、
`RuntimeDirectoryMode=0750`、`RuntimeDirectoryPreserve=no`。启动前，
root 权限的 `--startup-gate` 只读检查 commit、clean 状态、所有权、
权限、符号链接、固定文件和 `whutlogin` 不可写边界；任一失败即拒绝启动。

socket 父路径必须是 systemd 新建的真实目录。若 socket 路径启动前已经
存在，服务拒绝启动，不自动删除。正常退出仅在路径仍是本实例创建、所有者
正确且 device/inode 完全一致的 socket 时清理；不得清理替换后的路径。

## Nginx 与访问边界

HTTP 和 HTTPS server 均必须在通用 `location /` 前保留：

```nginx
location ^~ /internal/runtime-attestation {
    return 404;
}
```

这会覆盖精确路径、尾部斜杠和所有子路径。生产不提供该 HTTP endpoint；
只能由 root wrapper 经本机 Unix socket 调用，远程审计只能通过受控 SSH
执行该无参数 sudo 命令。部署后分别请求前缀本身、尾部斜杠和随机子路径，
全部必须返回 404。

## 生产审计

审计账户只能执行：

```bash
sudo /usr/local/sbin/whut-license-runtime-attestation-audit
```

wrapper 拒绝全部参数、清空调用方环境，并使用固定 Python、脚本、service、
socket、公钥文件和部署目录。CLI 生成一次性 32 字节 challenge；服务只签名
固定域分隔、固定字段、60 秒有效的 canonical JSON，不接受任意消息。服务端
通过 `SO_PEERCRED` 只接受 UID 0；CLI 反向核对 socket 对端 PID/UID 与
systemd `MainPID`/`whutlogin`，并独立核对 `/proc` cwd、start ticks、
Git HEAD/clean、APP_VERSION、公钥指纹和签名 payload。

成功输出严格为十行：

```text
runtime_attestation=pass
socket_peer_identity=pass
process_identity=pass
source_tree=pass
signature=pass
process_started_at=<UTC>
app_version=<version>
source_commit=<40 位小写 SHA>
public_key_sha256=<64 位小写 SHA-256>
result=PASS
```

日志和证据只保留上述非敏感字段及执行 UTC。不得记录 challenge、签名、
完整公钥、私钥、环境变量、授权 Token、管理员 Token 或数据库内容。失败
只保留稳定错误码和 `result=FAIL`。

## 验收、停止条件与密钥轮换

每次发布比较三处指纹：

1. 配置密钥预检的 `public_key_sha256`；
2. 本运行进程证明的 `public_key_sha256`；
3. Windows 制品离线证明的嵌入公钥指纹。

三者必须完全一致，且运行证明 `source_commit` 必须等于最终部署 HEAD。
任何非零退出、字段缺失、指纹/commit/PID/UID/cwd/start time 不一致、
过期证明、非 clean 工作区、公网前缀非 404、输出敏感信息或 traceback
都是停止条件；不得在同一审计会话中自动修复。

密钥轮换时先完成配置密钥预检，再重建 Windows 制品；重启服务后旧进程
证明必须失效，新证明的 start time、instance 和指纹必须变化。不要接受
重启前保存的证明文件；生产验收只接受本次随机 challenge 的在线响应。

## 回滚

回滚到已审查的旧版本时，将 `LICENSE_RUNTIME_SOURCE_COMMIT` 设置为实际
回滚 commit，重新执行 startup gate 和全部三处指纹比较。若旧版本不支持
本机制，先设 `LICENSE_RUNTIME_ATTESTATION_ENABLED=false`，使用旧 unit
并移除该审计 sudo 授权；不得保留一个伪成功的静态证明文件。回滚不修改
数据库，不恢复 `/admin/grant`，不使用 `LICENSE_ADMIN_TOKEN`，也不改变
支付、Worker 或授权签发语义。
