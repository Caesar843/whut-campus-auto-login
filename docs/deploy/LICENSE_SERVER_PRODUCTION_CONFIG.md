# 授权服务生产配置准备

本文件只说明 `license_server` 的生产配置边界。它不是云服务器部署手册，本轮尚未完成 Nginx、HTTPS、systemd、数据库迁移、支付接入和备份。

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
- `LICENSE_ADMIN_TOKEN`：管理员接口 token。生产必须显式配置，至少 32 个字符，不能使用占位符。
- `PAYMENT_YEARLY_AMOUNT`：年费金额，当前默认 `9.9`。
- `PAYMENT_CURRENCY`：币种，当前默认 `CNY`。
- `PAYMENT_CHANNELS`：允许的支付渠道列表，当前只是订单骨架。
- `PAYMENT_ORDER_TTL_MINUTES`：未支付订单有效分钟数。

客户端相关配置：

- `LICENSE_SERVER_URL`：客户端访问授权服务的地址。
- `LICENSE_PUBLIC_KEY`：客户端验签用 Ed25519 公钥。

生产必填项：

- `LICENSE_SERVER_ENV=production`
- `DATABASE_URL` 或 `LICENSE_DB_PATH`
- `LICENSE_PRIVATE_KEY` 或 `LICENSE_PRIVATE_KEY_FILE`
- `LICENSE_ADMIN_TOKEN`

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

## 管理员 Token

生产 token 用随机值生成，例如：

```powershell
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

不要使用 `change-me`、`admin-token`、`replace_with...` 或其他占位符。配置校验失败时只会提示配置项名称，不会输出 token 内容。

## 数据库路径

本轮仍使用 SQLite，不迁移 MySQL 或 PostgreSQL。生产数据库路径必须显式且可预测，例如：

```text
sqlite:////srv/APP_NAME/license.sqlite3
```

数据库文件和父目录不要放在临时目录，不要依赖当前工作目录。现有数据库 schema 不在本轮修改。

## 启动失败

生产模式下，以下情况会在服务开始提供请求前失败：

- `LICENSE_SERVER_ENV` 非法。
- 缺少数据库路径配置。
- 生产数据库路径不是绝对路径。
- 缺少私钥配置。
- 私钥文件不存在、不可读或内容不是 Base64 Ed25519 raw 私钥。
- 缺少管理员 token。
- 管理员 token 过短或使用明显占位符。

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

## 尚未完成

本轮没有完成真实云服务器部署。后续仍需要：

- Nginx 反向代理；
- HTTPS 证书；
- systemd 或其他进程管理；
- 数据库备份；
- 支付平台真实接入；
- 支付回调验签和幂等处理。
