# 授权服务腾讯云部署说明

本文档只说明授权服务部署配置。授权服务已完成预生产部署；本文不包含支付接入或后台管理闭环。

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
LICENSE_ADMIN_TOKEN=replace_with_strong_admin_token
DATABASE_URL=sqlite:////var/lib/whut-campus-auto-login/license.sqlite3
LICENSE_SERVER_ENV=production
```

`DATABASE_URL` 第一版只使用 SQLite。生产数据库文件建议放在：

```text
/var/lib/whut-campus-auto-login/license.sqlite3
```

不要把 `.env`、私钥、token、本地数据库或支付密钥提交到仓库。

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
