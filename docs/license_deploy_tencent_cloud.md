# 授权服务腾讯云部署说明

本文档只说明授权服务部署配置。授权服务已完成预生产部署；当前后台只支持查询、审计和追加订单售后备注，不支持补发授权、关单、冻结、修改订单状态或修改授权。

## 部署目标

- 云服务器：腾讯云轻量应用服务器
- 系统：Ubuntu
- 服务：FastAPI + systemd + Nginx
- 后端监听：`127.0.0.1:8787`
- 公网示例 IP：`124.223.7.147`
- 授权服务域名示例：`license.whutlogin.cn`

公网 IP 和域名只作为部署示例，不能硬编码进客户端业务逻辑。客户端生产地址通过 `LICENSE_SERVER_URL` 配置。

## 基础环境

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git nginx sqlite3
```

建议目录：

- 项目目录：`/opt/whut-campus-auto-login`
- 数据目录：`/var/lib/whut-campus-auto-login`
- 环境变量文件：`/etc/whut-campus-auto-login/license-server.env`

建议权限：

```bash
sudo chown -R whutlogin:whutlogin /opt/whut-campus-auto-login /var/lib/whut-campus-auto-login
sudo chmod 0750 /opt/whut-campus-auto-login /var/lib/whut-campus-auto-login
sudo chmod 0640 /var/lib/whut-campus-auto-login/license.sqlite3
sudo chmod 0600 /etc/whut-campus-auto-login/license-server.env
```

数据库父目录必须只允许服务运行用户写入。环境文件、私钥文件和其他秘密文件建议 `0600`，不要给 Nginx 用户或普通登录用户读取权限。

## 授权密钥

使用项目已有脚本生成 Ed25519 授权密钥：

```bash
python3 scripts/dev/generate_license_keys.py
```

私钥只放在服务器环境变量 `LICENSE_PRIVATE_KEY` 中，不能提交到仓库。公钥 `LICENSE_PUBLIC_KEY` 用于客户端验签配置。

## 环境变量

服务器环境变量文件示例：

```bash
LICENSE_SERVER_URL=http://127.0.0.1:8787
LICENSE_PRIVATE_KEY=replace_with_base64_or_configured_private_key
LICENSE_PUBLIC_KEY=replace_with_public_key
DATABASE_URL=sqlite:////var/lib/whut-campus-auto-login/license.sqlite3
LICENSE_SERVER_ENV=production
ADMIN_ENABLED=false
ADMIN_OPERATOR_NAME=
ADMIN_ACCESS_TOKEN_SHA256=
```

`DATABASE_URL` 第一版只使用 SQLite。生产数据库文件建议放在：

```text
/var/lib/whut-campus-auto-login/license.sqlite3
```

不要把 `.env`、私钥、token、本地数据库或支付密钥提交到仓库。

生产默认保持 `ADMIN_ENABLED=false`。只有 SSH 隧道或受控内网入口验证完成后，才允许启用后台；启用时 `ADMIN_OPERATOR_NAME` 必须非空，`ADMIN_ACCESS_TOKEN_SHA256` 必须是管理员 Bearer Token 的 SHA-256 十六进制摘要。不要把原始 Token 或摘要写入 Nginx 配置。

## 安装依赖

在 `/opt/whut-campus-auto-login` 下创建虚拟环境并安装服务端依赖：

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-server.txt
```

## 本地启动

```bash
uvicorn license_server.app:app --host 127.0.0.1 --port 8787
```

健康检查：

```bash
curl http://127.0.0.1:8787/healthz
```

期望返回：

```json
{"status":"ok"}
```

## systemd

复制示例文件：

```bash
sudo cp deploy/systemd/whut-license-server.service.example /etc/systemd/system/whut-license-server.service
sudo systemctl daemon-reload
sudo systemctl enable whut-license-server
sudo systemctl start whut-license-server
sudo systemctl status whut-license-server
```

示例 service 使用：

- `WorkingDirectory=/opt/whut-campus-auto-login`
- `EnvironmentFile=/etc/whut-campus-auto-login/license-server.env`
- `/opt/whut-campus-auto-login/.venv/bin/uvicorn`
- `127.0.0.1:8787`

查看日志：

```bash
sudo journalctl -u whut-license-server -n 100 --no-pager
sudo journalctl -u whut-license-server -f
```

上线前确认 journald 留存策略，例如 `/etc/systemd/journald.conf` 中的 `SystemMaxUse`、`MaxRetentionSec` 或所在系统的集中日志方案。不要在日志中记录管理员 Token、支付密钥、私钥或校园网凭据。

### 支付对账补偿 Worker

支付对账补偿 Worker 是 Web 服务之外的独立进程，用于支付回调缺失时的后台补偿。它不影响客户端手动刷新支付状态：Worker 默认关闭或未运行时，手动刷新仍可正常使用。该进程默认关闭，安装 unit 不代表启用或启动。

reconciliation Worker 与 Web 服务是两个独立 systemd unit。Worker unit 中的 `After=whut-license-server.service` 只提供共同启动时的顺序，不会把 Worker 生命周期绑定到 Web 服务；重启 Web 服务不会停止该 Worker，Web 服务重启后应单独确认该 Worker 状态。Worker 不会因为 Web 服务再次启动而自动启动，启用 Worker 必须是单独的管理员动作。

保持环境文件中的总开关为：

```bash
PAYMENT_RECONCILIATION_WORKER_ENABLED=false
```

安装独立 unit 后只刷新 systemd 配置并确认它仍为 disabled、inactive：

```bash
sudo cp deploy/systemd/whut-payment-reconciliation-worker.service.example /etc/systemd/system/whut-payment-reconciliation-worker.service
sudo systemctl daemon-reload
sudo systemctl is-enabled whut-payment-reconciliation-worker.service
sudo systemctl is-active whut-payment-reconciliation-worker.service
```

启用前必须逐项确认：Web 服务已完成数据库迁移；当前数据库精确匹配 Schema V5；环境文件使用绝对 SQLite 路径；`PAYMENT_PROVIDER=wechat_native` 且微信支付配置完整；生产网络和真实微信商户查单、关单权限已经验证；已经取得完整数据库备份。Worker 自身只做只读 Schema V5 启动门禁，不会执行迁移，也不会创建或修复数据库。

上述生产前置条件和真实微信商户验证未全部完成时，不得把总开关改为 true，不得启用或启动该 unit。本轮不启用该 Worker，不声称已验证生产网络、真实微信商户查单或关单，也不声称生产数据库已出现 claim。启动日志不得出现 Secret。该进程不得与 Notification Worker 混用入口或 unit。

停止并保持关闭的回滚方式：

```bash
sudo systemctl stop whut-payment-reconciliation-worker.service
sudo systemctl disable whut-payment-reconciliation-worker.service
```

随后把环境文件恢复为 `PAYMENT_RECONCILIATION_WORKER_ENABLED=false`。不要通过 Worker 入口运行数据库迁移；需要迁移时仍由既有 Web 服务部署流程在备份和维护窗口内完成。

## Nginx

复制示例文件：

```bash
sudo cp deploy/nginx/license.whutlogin.cn.conf.example /etc/nginx/sites-available/license.whutlogin.cn
sudo ln -s /etc/nginx/sites-available/license.whutlogin.cn /etc/nginx/sites-enabled/license.whutlogin.cn
sudo nginx -t
sudo systemctl reload nginx
```

公网 HTTP 测试：

```bash
curl http://124.223.7.147/healthz
curl http://license.whutlogin.cn/healthz
```

## HTTPS 后续配置

备案通过后再配置 HTTPS。可以使用腾讯云免费证书或 Let's Encrypt。最终生产授权服务地址应为：

```text
https://license.whutlogin.cn
```

Nginx 示例文件中保留了 443 配置说明，证书路径使用占位值，部署时替换为服务器上的真实证书路径。

公网必须保留：

```nginx
location ^~ /internal/admin {
    return 404;
}
```

该规则必须优先于通用 `location /`，避免公网直接访问后台。后台访问建议使用 SSH 隧道：

```bash
ssh -N -L 8787:127.0.0.1:8787 deploy_user@SERVER_HOST
```

随后在本机访问 `http://127.0.0.1:8787/internal/admin/`。管理员 Token 只在后台页面输入，不放进 URL、Nginx 配置或书签。

## SQLite V1 到 V2 升级

升级前停止服务并查看真实配置：

```bash
sudo systemctl stop whut-license-server
sudo grep -E '^(DATABASE_URL|LICENSE_DB_PATH)=' /etc/whut-campus-auto-login/license-server.env
```

必须根据实际环境文件人工确认 SQLite 文件的绝对路径。`DATABASE_URL` 如果是 SQLite URL，需要人工转换为对应文件路径；不得直接假设数据库位于 `/var/lib/whut-campus-auto-login/license.sqlite3`，也不得把 `DATABASE_URL` 原字符串直接赋给 `DB_PATH`。

输入并校验确认后的数据库文件路径：

```bash
read -r -p "Enter the confirmed absolute SQLite database path: " DB_PATH

case "$DB_PATH" in
  /*) ;;
  *)
    echo "DB_PATH must be an absolute filesystem path."
    exit 1
    ;;
esac

sudo test -f "$DB_PATH" || {
  echo "Database file does not exist: $DB_PATH"
  exit 1
}

sudo stat --format='%n %s bytes %U:%G %a' "$DB_PATH"
```

备份数据库：

```bash
BACKUP_DIR=/var/backups/whut-license-server
BACKUP="$BACKUP_DIR/license.sqlite3.v1-pre-p4-$(date -u +%Y%m%dT%H%M%SZ)"

sudo install -d -m 0700 "$BACKUP_DIR"
sudo cp -a -- "$DB_PATH" "$BACKUP"
sudo test -s "$BACKUP"
sudo sqlite3 "$BACKUP" 'PRAGMA integrity_check;'
```

部署新版本后启动服务，初始化逻辑会在启动时完成 V1 到 V2 迁移：

```bash
sudo systemctl start whut-license-server
sudo systemctl status whut-license-server
```

验证版本、表和索引：

```bash
sqlite3 "$DB_PATH" "SELECT key, value FROM schema_meta ORDER BY key;"
sqlite3 "$DB_PATH" "PRAGMA table_info(admin_audit_logs);"
sqlite3 "$DB_PATH" "PRAGMA index_list(admin_audit_logs);"
curl http://127.0.0.1:8787/healthz
```

回滚前必须再次确认当前 shell 中的 `DB_PATH` 和 `BACKUP` 指向正确文件。回滚时停止新服务，保留失败后的 V2 数据库现场，恢复 V1 备份并切回部署前程序版本：

```bash
sudo systemctl stop whut-license-server
FAILED_DB="${DB_PATH}.failed-v2-$(date -u +%Y%m%dT%H%M%SZ)"
sudo mv -- "$DB_PATH" "$FAILED_DB"
sudo cp -a -- "$BACKUP" "$DB_PATH"
sudo systemctl start whut-license-server
```

已升级到 V2 的数据库禁止再由旧程序打开；旧程序必须配合恢复出的 V1 备份使用。

## 客户端切换生产授权服务

开发默认地址：

```bash
LICENSE_SERVER_URL=http://127.0.0.1:8787
```

生产地址：

```bash
LICENSE_SERVER_URL=https://license.whutlogin.cn
```

如果未配置 `LICENSE_SERVER_URL`，客户端回退到 `http://127.0.0.1:8787`，便于本地开发脚本继续使用。

## 安全边界

授权服务不接收、不保存、也不上传：

- 校园网账号
- 校园网账号 hash
- 脱敏校园网账号
- 校园网密码
- 用户上网内容
- 本地运行日志

授权服务只处理设备授权状态、试用时间和后续支付订单状态。当前部署配置不接支付，不提交支付密钥。支付 V1 仅支持微信 Native；支付表、Mock 网关、支付客户端和真实微信商户联调仍以 `docs/design/PAYMENT_V1_IMPLEMENTATION.md` 为准。
