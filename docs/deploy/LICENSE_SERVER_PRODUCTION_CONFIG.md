# 授权服务生产配置准备

本文件只说明免费版 `license_server` 的生产配置边界。授权服务已完成预生产部署；本文不是完整云服务器部署手册，不展开 Nginx、HTTPS、systemd、数据库迁移和备份细节。

## 服务端职责

免费版服务端只保留三类职责：

1. 设备注册：接收设备指纹哈希，记录设备首见/末见时间；
2. 免费授权签发：为新设备签发永久免费授权（`license_type=free`、`expires_at=9999-12-31T00:00:00Z`），并用 Ed25519 私钥签发 `signed_license_token`；
3. 内部只读后台：查看设备与授权统计、审计日志，追加运维备注。

服务端不存在任何试用期、付费、激活码、订单或回调能力。

## 运行环境

通过 `LICENSE_SERVER_ENV` 区分运行环境：

- `development`：本地开发，可使用相对 SQLite 路径和本地临时配置。
- `test`：自动化测试，使用测试注入的临时数据库和临时密钥。
- `production`：生产模式，关键配置必须显式提供，缺失或无效时拒绝启动。

`SERVER_ENV` 仅作为旧配置兼容入口，新配置不要继续使用。

## 配置项

服务端配置：

- `LICENSE_SERVER_ENV`：运行环境，生产必须为 `production`。
- `DATABASE_URL`：SQLite URL，例如 `sqlite:////srv/APP_NAME/license.sqlite3`。生产必须是绝对路径。
- `LICENSE_DB_PATH`：兼容用数据库文件路径。生产必须是绝对路径。优先使用 `DATABASE_URL`。
- `LICENSE_PRIVATE_KEY`：Base64 编码的 32 字节 Ed25519 私钥。生产建议改用 `LICENSE_PRIVATE_KEY_FILE`。
- `LICENSE_PRIVATE_KEY_FILE`：保存上述私钥内容的文件路径。生产建议使用这个变量，路径必须是绝对路径。
- `LICENSE_RUNTIME_ATTESTATION_ENABLED`：是否启用运行时证明（runtime attestation）。默认关闭，仅支持 `production` 环境；开启时要求 Linux 运行环境与 Unix socket 部署。
- `LICENSE_RUNTIME_SOURCE_COMMIT`：运行时证明使用的完整部署 commit，40 位小写十六进制；仅在运行时证明启用时必填。
- `ADMIN_ENABLED`：是否启用 `/internal/admin` 最小后台。生产默认必须为 `false`。
- `ADMIN_OPERATOR_NAME`：后台追加运维备注时写入审计的操作人名称。启用后台写操作前必须配置为非空值。
- `ADMIN_ACCESS_TOKEN_SHA256`：管理员 Bearer Token 的 SHA-256 十六进制摘要。只保存摘要，不保存原始 Token。

客户端相关配置：

- `LICENSE_SERVER_URL`：客户端访问授权服务的地址。
- `LICENSE_PUBLIC_KEY`：客户端验签用 Ed25519 公钥。

生产必填项：

- `LICENSE_SERVER_ENV=production`
- `DATABASE_URL` 或 `LICENSE_DB_PATH`
- `LICENSE_PRIVATE_KEY` 或 `LICENSE_PRIVATE_KEY_FILE`

后台管理配置默认关闭：

```bash
ADMIN_ENABLED=false
ADMIN_OPERATOR_NAME=
ADMIN_ACCESS_TOKEN_SHA256=
```

只有在 SSH 隧道、受控内网入口或等效访问隔离已经验证完成后，才允许把 `ADMIN_ENABLED` 改为 `true`。启用时必须同时提供非空 `ADMIN_OPERATOR_NAME` 和 64 位十六进制 `ADMIN_ACCESS_TOKEN_SHA256`。不要把真实管理员 Token 或摘要写入文档、仓库、Nginx 配置或浏览器书签。

## Ed25519 私钥

生成开发或生产用密钥对：

```powershell
python scripts/dev/generate_license_keys.py
```

生产私钥只保存到服务器安全位置，例如：

```text
/etc/APP_NAME/license-private-key.b64
```

不要把私钥文件放进仓库，不要复制到客户端。客户端只需要 `LICENSE_PUBLIC_KEY`。

## 数据库路径

本轮仍使用 SQLite，不迁移 MySQL 或 PostgreSQL。生产数据库路径必须显式且可预测，例如：

```text
sqlite:////srv/APP_NAME/license.sqlite3
```

数据库文件和父目录不要放在临时目录，不要依赖当前工作目录。

## 数据库结构与历史库兼容

当前支持的 schema 版本为 6（`license_server/db.py` 的 `SUPPORTED_SCHEMA_VERSION`），核心表只有 `devices`、`licenses`、`admin_audit_logs`、`schema_meta`：

- `devices` 只保存 `product_id`、设备指纹哈希与首见/末见时间，不含任何校园网账号信息；
- `licenses` 保存免费授权记录；`order_id` 为历史遗留列，免费版恒为 NULL，不再读写；
- `admin_audit_logs` 保存后台审计记录；
- 历史遗留业务表（`payment_orders`、`payment_notifications`、`payment_reconciliations`、`license_grants` 等，登记于 `db.LEGACY_PAYMENT_TABLES`）在新库中不再创建；历史库中如仍存在，保持原样、不校验、不读写。

服务启动时对没有 `schema_meta` 的历史 SQLite 旧库执行兼容检查，全部通过后把版本标记写入 `schema_meta=6`：

- 核心表 `devices`、`licenses` 必须与免费版历史结构精确一致（列顺序、类型、`NOT NULL`、主键、外键、唯一约束和索引）；旧库中已移除的敏感列（如 `campus_account_hash`、`campus_account_masked`、`device_name`、`os`、`app_version`、`revoked_reason`）会随升级自动删除；
- 允许存在且保持原样的表仅限上述遗留业务表；其他未知表、视图或触发器一律拒绝；
- 所有相关业务表的行数必须为 0。

以下情况会在任何 DDL 写入前拒绝启动，并要求人工迁移：

- 任一业务表存在数据；
- 核心表结构、约束或索引与预期不一致；
- 存在未知表、视图或触发器；
- 已版本化数据库的 `schema_version` 高于当前支持的 6。

自动迁移不替代部署备份。每次部署前必须对数据库文件执行外部文件级备份，并确认备份可恢复；非空旧库不得依赖启动时初始化进行迁移。

## 运行时证明（runtime attestation）

`LICENSE_RUNTIME_ATTESTATION_ENABLED=true` 时，服务在启动 lifespan 中创建本地 Unix socket（`/run/whut-license-server/runtime-attestation.sock`，权限 `0600`），只应答该服务器本机特权进程的运行时证明请求，并对证明内容签名。该能力仅支持 production 环境，socket 必须位于 `RuntimeDirectory=whut-license-server` 对应的运行目录内；相关部署脚本见 `deploy/libexec/whut-license-startup-gate.py` 与 `deploy/bin/whut-license-runtime-attestation-audit`。公网 Nginx 必须继续拦截 `/internal/runtime-attestation`（`deploy/nginx/` 下的授权服务配置示例已内置该规则）。

## 启动失败

生产模式下，以下情况会在服务开始提供请求前失败：

- `LICENSE_SERVER_ENV` 非法。
- 缺少数据库路径配置。
- 生产数据库路径不是绝对路径。
- 缺少私钥配置。
- 私钥文件不存在、不可读或内容不是 Base64 Ed25519 raw 私钥。
- `LICENSE_RUNTIME_ATTESTATION_ENABLED=true` 但环境不是 production，或 `LICENSE_RUNTIME_SOURCE_COMMIT` 不是 40 位小写 commit。
- `ADMIN_ENABLED=true` 但 `ADMIN_ACCESS_TOKEN_SHA256` 不是 64 位十六进制摘要。

错误信息只包含配置项名称或文件路径，不包含私钥和 token 内容。

## 健康检查

轻量存活检查：

```http
GET /healthz
```

正常返回：

```json
{"status":"ok"}
```

完整健康检查：

```http
GET /health
```

该组接口不需要管理员 token，不返回数据库路径、私钥路径、管理员 token、环境变量、设备、授权或审计数据。

## 对外业务接口

- `POST /device/register`：设备注册并签发免费授权。请求体只需要 `product_id` 与 `device_fingerprint_hash`；历史客户端附带的 `device_name`、`os`、`app_version` 会被忽略，携带校园网账号相关字段返回 422。
- `POST /license/refresh`：刷新已注册设备的授权，返回同样的字段集合；未注册设备返回 404 `device_not_found`。
- `GET /healthz`、`GET /health`：健康检查。

两个业务端点都只接收设备指纹哈希与 `product_id`，不接收也不保存校园网账号密码。授权响应中的 `status` 为 `free_active`（授权可用）、`free_expired`（已过期）或 `revoked`（已吊销）。

## 内部只读后台

启用 `ADMIN_ENABLED=true` 后，`/internal/admin/` 提供只读后台（静态页面与 `/internal/admin/assets/admin.js`，页面本身不含业务数据，管理员令牌只保存在浏览器会话中）。数据接口（需 Bearer 管理员令牌）：

- `GET /internal/admin/api/summary`：设备总量、24 小时/7 天/30 天活跃设备数、授权类型与状态分布；
- `GET /internal/admin/api/devices`、`GET /internal/admin/api/devices/{device_fingerprint_hash}`：设备列表与详情；
- `GET /internal/admin/api/licenses`：授权列表；
- `GET /internal/admin/api/audit-logs`、`GET /internal/admin/api/audit-logs/{audit_id}`：审计日志查询；
- `POST /internal/admin/api/devices/{device_fingerprint_hash}/notes`、`POST /internal/admin/api/licenses/{license_id}/notes`：追加运维备注（唯一写操作，全部写入审计）。

后台没有签发授权、冻结授权或修改授权状态的端点。所有响应都附带安全响应头（`Cache-Control: no-store`、`X-Content-Type-Options: nosniff`、`Referrer-Policy: no-referrer`、CSP），备注内容会做敏感信息过滤，审计中的敏感备注以 `[REDACTED]` 展示。公网部署必须由 Nginx 拦截 `/internal/admin`，只允许 SSH 隧道或受控内网访问。

## 模板文件

`license_server/.env.example` 只是模板，只能提交变量名和占位符。实际 `.env`、私钥、SQLite 数据库和 token 文件不得进入 Git。

## 后续部署事项

- Nginx 反向代理；
- HTTPS 证书；
- systemd 或其他进程管理；
- 数据库备份；
- 运行时证明（attestation）上线前的部署与审计流程确认。
