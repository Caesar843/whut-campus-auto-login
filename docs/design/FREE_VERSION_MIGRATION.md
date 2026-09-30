# 支付模块移除与永久免费版迁移说明

本文档记录把「武汉理工校园网自动登录小工具」从「14 天试用 + 9.9 元/年 + 微信 Native 支付」
改造为「永久免费」的完整变更，以及免费版的契约、数据迁移策略与验证方式。

## 1. 改造后的产品契约

| 项目 | 改造前 | 改造后 |
| --- | --- | --- |
| 使用门槛 | 14 天试用，到期后停止自动登录 | 永久免费，无试用期、无内购、无激活码 |
| 付费入口 | 主界面「激活正式版」按钮 + 支付窗口（二维码轮询） | 无。主界面不存在任何支付、购买、续费入口 |
| 服务端职责 | 试用记录、支付订单、支付回调、对账、worker、后台订单视图 | 设备注册、免费授权签发、后台使用统计与审计、运行时证明 |
| 授权类型 | `trial` / `paid` | `free`（`expires_at = 9999-12-31T00:00:00Z`） |
| 客户端放行判定 | 读取本地凭证 + 试用期/付费状态 → 可能拦截 | `check_license_before_login()` 无参数、永远放行，零 I/O |
| 网络请求 | 启动一次 + 登录成功后一次 + 支付轮询 | 启动一次 + 登录成功后一次（仅使用情况上报） |

免费版仍然保留服务端与后台，原因：需要统计有多少设备在使用本工具。上报内容只有
**设备指纹哈希**与**时间戳**，不包含校园网账号、密码或任何上网内容。

## 2. 客户端契约（`license_client`）

- `LicenseStatus.FREE = "free"`，文案 `FREE_LICENSE_MESSAGE = "授权状态：免费版，永久免费使用，无试用期与内购限制。"`
- `free_decision(*, reason="free_mode", usage_sync_required=False, message_for_ui=None)`
  → `status=FREE, allowed=True, license_type="free"`。
- `check_license_before_login()`：不接受任何参数，直接返回
  `free_decision(usage_sync_required=True)`，不读本地凭证、不发网络请求，因此开机时即使
  未完成校园网认证也不影响自动登录。
- `initialize_license(*, device_fingerprint_hash=None, api_client=None)`：应用启动时调用一次，
  向服务端上报设备使用情况并刷新本地 signed_token。
- `try_initialize_license_after_bootstrap_login(*, bootstrap_decision, device_fingerprint_hash=None, api_client=None)`：
  仅在 `bootstrap_required` 或 `usage_sync_required` 为真时再上报一次（即校园网登录成功后）。
- `report_device_usage(...)`：尽力而为，任何异常只写日志，不改变放行结果。
- 被删除的客户端表面：`payment_api.py`、`payment_state.py`、支付相关的 `LicenseStatus`
  状态迁移与轮询逻辑；`constants.py` 里的 `PAYMENT_*`、价格与币种常量。

桌面端 `desktop_app/main_window.py` 不再有关联支付窗口的字段、按钮与处理函数；
`LICENSE_PLACEHOLDER` 与主界面说明文案改为免费版口径：

> 免费说明：本工具完全免费，无试用期、无内购、无需激活码。……只会向服务器上报本机设备指纹
> 与最近使用时间，不会上报校园网账号和密码。

## 3. 服务端契约（`license_server`）

- `POST /device/register`、`POST /license/refresh`：路径与请求体保持不变，但不再产生试用期或
  付费授权。新设备注册即签发永久免费授权：`license_type="free"`、`source="free"`、
  `expires_at="9999-12-31T00:00:00Z"`。
- `license_service.py`：`create_free_license(connection, *, device_id, starts_at)`、
  `latest_license`、`active_license`；删除 `latest_paid_license`、`paid_active_license_exists`。
- `device_proof.py`：payload 允许的 `license_type` 集合为 `{"free", "trial", "paid"}`
  （后两者用于承认历史凭证），其余校验规则不变。
- 后台 `/internal/admin/`：设备列表与活跃度统计（24 小时 / 7 天 / 30 天）、授权列表、
  审计日志、设备与授权备注、404/401/400/500 错误语义与安全响应头全部保留；
  **订单、支付通知、授权发放（grant）端点已删除**，访问这些旧路径返回 404。
- `config.py`：只剩 environment、database_path、private_key_b64、admin_*（`ADMIN_ENABLED`、
  `ADMIN_OPERATOR_NAME`、`ADMIN_ACCESS_TOKEN_SHA256`）、运行时证明（`LICENSE_RUNTIME_ATTESTATION_ENABLED`、
  `LICENSE_RUNTIME_SOURCE_COMMIT`）。历史 env 里残留的 `PAYMENT_*` / `WECHAT_PAY_*` 变量被忽略，
  不再导致启动失败。

## 4. 数据库迁移策略

- `SUPPORTED_SCHEMA_VERSION = 6`，核心表只有 `devices`、`licenses`、`admin_audit_logs`、`schema_meta`。
- 新建数据库只创建这四张表，**不再创建任何支付表**。
- 历史库（含支付时代的表与数据）升级到 6：
  - 支付遗留表（`payment_orders`、`payment_notifications`、`payment_reconciliations`、
    `license_grants`）原样保留：不清空、不迁移、不校验、不读写，仅由
    `db.LEGACY_PAYMENT_TABLES` 登记。
  - 无 `schema_meta` 的历史空库：核心表结构必须与预期一致且没有任何业务数据，否则报
    `manual migration required` 并回滚（不写入任何变更）。
  - 已带 `schema_meta` 的旧版本库（1–5）：直接升级到 6，支付遗留表与已有设备/授权数据保留。
  - 版本高于 6：报错并保持原样。
- `licenses.order_id` 作为历史列保留（新数据恒为 NULL），避免重写历史表带来的风险。

## 5. 后台接口实测契约（测试以此为准）

`tests/license_server/test_admin_readonly.py`、`test_admin_ui.py`、`test_admin_audit.py`、
`test_admin_notes.py` 的断言与 `license_server/admin_routes.py` 的真实响应对齐：

- 页面标题为「管理后台」，脚本令牌存储键为 `whut-admin-secret`。
- summary 字段：`devices_total`、`devices_active_24h`、`devices_active_7d`、
  `devices_active_30d`、`licenses_by_type`、`licenses_by_status`、`licenses_active_unexpired`。
- devices 列表项字段：`device_id_hash`、`product_id`、`first_seen_at`、`last_seen_at`、
  `license_id`、`license_type`、`license_status`、`license_expires_at`，按 `last_seen_at`
  倒序，过滤参数为 `device_id_hash` / `product_id` / `seen_from` / `seen_to`。
- 设备详情字段：`device_id_hash`、`product_id`、`first_seen_at`、`last_seen_at`、`licenses`。
- 授权项字段：`license_id`、`license_type`、`status`、`starts_at`、`expires_at`、`source`、
  `created_at`、`revoked_at`（不返回 `device_id_hash` 与 `order_id`）。
- 审计项字段：`id`、`actor`、`source_ip`、`request_id`、`action`、`target_type`、
  `target_id`、`result`、`before_state`、`after_state`、`reason`、`failure_code`、`created_at`。
- 写操作只有两个 notes POST（设备与授权），提交后有 in-flight 防重并在 finally 中恢复按钮。
- 设备详情视图只渲染白名单字段，不含校园网账号、密码、`order_id`、`signed_token`。

客户端 `license_client/license_state.py` 的历史凭证评估分支（`evaluate_local_license`，
免费版运行时不可达）文案也已改为免费版中性措辞，不再出现「续费」「激活正式版」字样。

## 6. 被删除的文件与模块

- 服务端：`payment.py`、`payment_gateway.py`、`payment_routes.py`、`payment_service.py`、
  `wechat_payment.py`、`payment_notification_repository.py`、`payment_notification_routes.py`、
  `payment_notification_worker.py`、`payment_notification_worker_main.py`、
  `payment_reconciliation_repository.py`、`payment_reconciliation_service.py`、
  `payment_reconciliation_worker.py`、`payment_reconciliation_worker_main.py`。
- 客户端与桌面端：`license_client/payment_api.py`、`license_client/payment_state.py`、
  `desktop_app/payment_window.py`。
- 部署：`deploy/systemd/whut-license-payment-worker.service.example`、
  `deploy/systemd/whut-payment-reconciliation-worker.service.example`。
- 文档：`docs/design/PAYMENT_V1_IMPLEMENTATION.md`、`docs/deploy/PAYMENT_NOTIFICATION_WORKER.md`、
  `docs/design/PAYMENT_AND_LICENSE.md`（内容并入本文件与 `LICENSE_AND_FREE_VERSION.md`）。
- 测试：`tests/license_server/test_payment*.py`、`tests/license_server/test_wechat_payment*.py`、
  `tests/client/test_payment_flow.py`、`tests/client/test_payment_window.py`、
  `tests/license_client/test_payment_api_client.py`、`tests/license_client/test_payment_state.py`。

## 7. 如何验证

```bash
python -m pytest tests/license_client tests/client -q          # 客户端：免费放行与界面
python -m pytest tests/license_server -q                        # 服务端：注册、后台、迁移
python -m pytest -q                                             # 全量
```

服务端手验（本机 SQLite + 测试私钥）：

```bash
curl -s -X POST http://127.0.0.1:8787/device/register \
  -H "Content-Type: application/json" \
  -d '{"product_id":"whut-campus-auto-login","device_fingerprint_hash":"device-a"}'
# 期望：{"license_type":"free","license_status":"active","status":"free_active",
#        "expires_at":"9999-12-31T00:00:00Z", ...}

curl -s -X POST http://127.0.0.1:8787/device/register \
  -H "Content-Type: application/json" \
  -d '{"product_id":"whut-campus-auto-login","device_fingerprint_hash":"device-a"}' | grep license_id
# 期望：第二次注册返回同一 license_id，不重复签发

curl -s http://127.0.0.1:8787/internal/admin/api/summary -H "Authorization: Bearer $ADMIN_TOKEN"
# 期望：devices_total / devices_active_24h / devices_active_7d / devices_active_30d /
#        licenses_by_type / licenses_by_status / licenses_active_unexpired

curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8787/internal/admin/api/orders \
  -H "Authorization: Bearer $ADMIN_TOKEN"
# 期望：404（支付时代端点已不存在）
```

## 8. 回滚

改造以「删除文件 + 改写模块」的方式完成，回滚依赖版本控制：恢复被删除的文件与对应
文档/测试，并把 `license_server/db.py` 回退到支付时代的 schema 版本。历史库中的支付表
未被修改，因此回滚后旧数据仍然可用。

## 9. 仍然缺少的真实信息

- 真实校园网抓包信息（登录接口、参数、返回）——当前实现依项目既有约定，未伪造新接口。
- 生产 HTTPS 授权域名与 Ed25519 公钥（客户端打包时注入）。
- 生产后台管理令牌（`ADMIN_ACCESS_TOKEN_SHA256`），只保存在服务器环境变量中。