# 授权服务生产配置准备

本文件只说明 `license_server` 的生产配置边界。授权服务已完成预生产部署；本文不是完整云服务器部署手册，不展开 Nginx、HTTPS、systemd、数据库迁移、支付接入和备份细节。

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
- `LICENSE_PRIVATE_KEY`：Base64 编码的 32 字节 Ed25519 私钥。
- `LICENSE_PRIVATE_KEY_FILE`：保存上述私钥内容的文件路径。生产建议使用这个变量，路径必须是绝对路径。
- `PAYMENT_CURRENCY`：币种，当前默认 `CNY`。
- `PAYMENT_CHANNELS`：既有订单骨架使用的支付渠道列表，当前只是订单骨架。
- `PAYMENT_ORDER_TTL_MINUTES`：未支付订单有效分钟数。
- `ADMIN_ENABLED`：是否启用 `/internal/admin` 最小后台。生产默认必须为 `false`。
- `ADMIN_OPERATOR_NAME`：后台追加售后备注时写入审计的操作人名称。启用后台写操作前必须配置为非空值。
- `ADMIN_ACCESS_TOKEN_SHA256`：管理员 Bearer Token 的 SHA-256 十六进制摘要。只保存摘要，不保存原始 Token。

支付 V1 的产品目录、`PAYMENT_PRICE_FEN=990` 启动校验、微信 Native-only 范围、支付表和回调幂等规则以 `docs/design/PAYMENT_V1_IMPLEMENTATION.md` 为准。当前预生产授权服务完成，不代表支付预生产闭环完成。

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

## 未版本化旧库自动升级

服务只会自动升级同时满足以下条件的未版本化 SQLite 旧库：

- 仅包含已知生产旧版的 `devices`、`licenses`、`payment_orders` 三张业务表；`sqlite_sequence` 可以存在；
- 三张表的列顺序、类型、`NOT NULL`、主键、外键、唯一约束和索引与已知生产旧 DDL 精确一致；
- 三张业务表的行数均为 0。

满足条件时，初始化会在既有 `BEGIN IMMEDIATE` 事务中建立当前 V1 baseline，再升级到 Schema V2。最终写入 `schema_meta=2`，`PRAGMA user_version` 继续保持 0。再次启动不会重复迁移。

以下情况会在任何 DDL 写入前拒绝启动，并要求人工迁移：

- 任一业务表存在数据；
- 存在额外或缺失的业务表、列、约束或索引；
- 列类型、顺序、`NOT NULL`、主键、外键、唯一约束或索引列顺序不一致；
- 其他未知的未版本化 Schema。

自动迁移不替代部署备份。每次部署前必须对数据库文件执行外部文件级备份，并确认备份可恢复；非空旧库不得依赖启动时初始化进行迁移。

## 启动失败

生产模式下，以下情况会在服务开始提供请求前失败：

- `LICENSE_SERVER_ENV` 非法。
- 缺少数据库路径配置。
- 生产数据库路径不是绝对路径。
- 缺少私钥配置。
- 私钥文件不存在、不可读或内容不是 Base64 Ed25519 raw 私钥。

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

该接口不需要管理员 token，不返回数据库路径、私钥路径、管理员 token、环境变量、设备、授权或订单数据。

## 模板文件

`license_server/.env.example` 只是模板，只能提交变量名和占位符。实际 `.env`、私钥、SQLite 数据库和 token 文件不得进入 Git。

## 后续部署与支付事项

授权服务预生产部署已完成。后续仍需要补齐或确认：

- Nginx 反向代理；
- HTTPS 证书；
- systemd 或其他进程管理；
- 数据库备份；
- 支付平台真实接入；
- 支付回调验签和幂等处理；
- 支付相关数据库表、Mock 网关和支付客户端。
