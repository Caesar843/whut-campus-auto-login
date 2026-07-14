# 微信支付通知 Worker 部署

本文只说明独立微信支付通知 Worker 的生产运行方式。Worker 与 Web 服务加载同一份服务端环境文件和 SQLite 数据库，不监听端口，也不替代现有 Web 服务。

## 前置条件

- 发布代码必须包含 P5-A2-1 至 P5-A2-4，并完成离线测试。
- 数据库必须已由当前代码验证为 Schema V4，且部署前已有完整数据库备份。
- `whut-license-server.service` Web 服务健康，微信 Native 支付配置完整有效。
- `/etc/whut-campus-auto-login/license-server.env` 由 `root:whutlogin` 持有并使用 `0640` 或更严格权限。
- 环境文件中的私钥、APIv3 密钥和 Token 不得写入命令行历史、unit 或日志。
- 数据库文件及父目录必须允许 `whutlogin` 读写，包括 SQLite WAL/SHM 辅助文件；密钥文件必须允许该用户只读。

默认只运行一个 Worker。A2-1/A2-3 的数据库 claim 和幂等事务允许误启动多个实例而不重复发放授权，但多实例会增加 SQLite 锁竞争，扩容前必须单独评估。

## 环境配置

先保持 Worker 关闭：

```text
PAYMENT_NOTIFICATION_WORKER_ENABLED=false
PAYMENT_NOTIFICATION_WORKER_POLL_SECONDS=1
PAYMENT_NOTIFICATION_MAX_ATTEMPTS=8
```

`PAYMENT_NOTIFICATION_WORKER_POLL_SECONDS` 必须为大于 0 且不超过 300 的有限秒数。`PAYMENT_NOTIFICATION_MAX_ATTEMPTS` 必须为 1 至 100 的整数。启用 Worker 时，`PAYMENT_PROVIDER` 必须为 `wechat_native`，并且现有微信配置、数据库路径和签名密钥配置必须全部有效。

## 安装与启用

1. 部署并验证新代码，但先不要启动 Worker。
2. 停止写入数据库的相关服务后创建并验证完整数据库备份，再按发布流程恢复 Web 服务。
3. 安装 unit：

```bash
sudo install -o root -g root -m 0644 \
  deploy/systemd/whut-license-payment-worker.service.example \
  /etc/systemd/system/whut-license-payment-worker.service
sudo systemctl daemon-reload
```

4. 保持 `PAYMENT_NOTIFICATION_WORKER_ENABLED=false`，直接运行模块一次以验证共享配置可以加载；此时进程会正常退出且不会 claim 通知：

```bash
cd /opt/whut-campus-auto-login
sudo -u whutlogin /opt/whut-campus-auto-login/.venv/bin/python \
  -m license_server.payment_notification_worker_main
```

5. 确认 Web 服务仍健康，将 `PAYMENT_NOTIFICATION_WORKER_ENABLED` 改为 `true`，在 unit 尚未启动时执行一次受完整门禁保护的无任务诊断：

```bash
cd /opt/whut-campus-auto-login
sudo -u whutlogin /opt/whut-campus-auto-login/.venv/bin/python \
  -m license_server.payment_notification_worker_main --once
```

6. 启用单实例 Worker：

```bash
sudo systemctl enable --now whut-license-payment-worker.service
sudo systemctl status whut-license-payment-worker.service --no-pager
sudo journalctl -u whut-license-payment-worker.service -n 50 --no-pager
```

7. 再次确认 Web 服务健康、Mock 路由未暴露，并通过现有只读后台或获批的 SQLite URI `mode=ro` 聚合检查通知队列状态。

## 停止与优雅退出

```bash
sudo systemctl stop whut-license-payment-worker.service
```

systemd 发送 SIGTERM。信号 handler 只设置停止标志；空队列等待会立即唤醒，正在执行的短事务允许完成，完成后不再领取新通知。`TimeoutStopSec=30` 是最终上限。正常 SIGTERM/SIGINT 和 `--once` 返回 0；配置错误返回 2，并由 `RestartPreventExitStatus=2` 阻止无效配置重启循环；初始化、Schema 或未知运行错误返回 1，并由 `Restart=on-failure` 处理。

## 监控与排障

```bash
systemctl status whut-license-payment-worker.service --no-pager
journalctl -u whut-license-payment-worker.service --since "30 minutes ago" --no-pager
```

关注固定生命周期事件、反复非零退出和 systemd 重启循环。队列诊断只统计 `RECEIVED`、`RETRY`、`PROCESSING`、`PROCESSED`、`DUPLICATE`、`ORPHAN`、`ABNORMAL` 数量及最早时间，不输出订单号、通知号、交易号、商户号、设备哈希、密钥或 Token。

- 大量 `RETRY`：检查 SQLite 锁竞争、磁盘空间和服务用户写权限。
- 大量 `ABNORMAL`：使用既有只读后台核对失败分类，保留证据并进入人工处理流程。
- 长期 `PROCESSING`：确认 Worker 是否重启循环；过期租约由正式 Repository 回收，不手工改状态。
- Web 回调正常但授权迟迟未发放：确认 Worker 为 active、Schema V4 门禁通过、队列中存在待处理项。

不要手工删除通知、重新发放 grant、绕过唯一约束或关闭外键。不得在日志或排障输出中打印原始支付记录及任何 Secret。

## 回滚

1. 先执行 `systemctl stop whut-license-payment-worker.service`，并将 `PAYMENT_NOTIFICATION_WORKER_ENABLED=false`。
2. 确认进程已退出且 Web 服务状态明确。
3. 恢复上一版 unit、环境文件和代码；执行 `systemctl daemon-reload`。
4. 只有在数据库写入服务全部停止、备份已校验且代码/Schema 兼容性已确认时，才按既有数据库恢复流程恢复备份。
5. 恢复 Web 服务并验证健康。旧代码不得打开其不支持的升级后数据库。
6. Worker 保持 disabled，直到问题定位完成并重新通过 `--once` 门禁。

回滚期间保留 journal、备份校验结果和固定错误代码，不保留或传播支付标识和密钥内容。
