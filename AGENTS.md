\# AGENTS.md



\## 1. 项目总目标



本项目是“武汉理工校园网自动登录小工具”。



第一版只面向武汉理工大学校园网环境，目标是：



用户第一次打开工具后，输入校园网账号和密码并保存配置；之后电脑开机时，工具在后台自动启动，并在电脑已连接武汉理工校园网环境的前提下，自动完成校园网认证登录。



本项目不是破解校园网，也不是绕过学校认证规则，而是减少用户重复打开网页、输入账号密码、点击登录的操作。



开发前必须先阅读：



\- docs/design/PROJECT\_BRIEF.md



所有实现必须服从该背景文件中的项目边界。



\---



\## 2. 第一版必须坚持的产品边界



第一版只做：



1\. 输入校园网账号和密码；

2\. 校园网账号密码安全保存在本机；

3\. 开机自动运行；

4\. 自动尝试登录武汉理工校园网；

5\. 修改账号密码；

6\. 清除本机配置；

7\. 测试登录；

8\. 永久免费使用，无试用期、无内购、无需激活码；

9\. 启动时与校园网登录成功后各上报一次设备使用情况（仅设备指纹哈希与时间戳）；

10\. 基础设备授权凭证（服务端签发，license\_type=free）；

11\. 右下角托盘后台运行；

12\. 基础状态展示。



第一版明确不做：



1\. 不做多学校适配；

2\. 不做复杂网络诊断；

3\. 不做广告；

4\. 不做云端校园网账号系统；

5\. 不上传用户校园网账号密码；

6\. 不做验证码绕过；

7\. 不做设备限制突破；

8\. 不做复杂日志系统；

9\. 不做强反破解；

10\. 不做账号注册、手机号登录、用户中心；

11\. 不做浏览器插件版；

12\. 不做移动端；

13\. 不做多设备同步；

14\. 不做校园网异常自动修复；

15\. 不做复杂会员体系；

16\. 不做支付、内购、订阅、激活码、订单与退款系统。



\---



\## 3. 账号密码安全规则



校园网账号密码只能保存在用户本机。



严禁：



1\. 将校园网账号密码上传到服务器；

2\. 将校园网账号密码写入云端数据库；

3\. 将校园网密码明文写入本地普通 txt/json 文件；

4\. 在日志中打印校园网密码；

5\. 在错误信息中显示校园网密码；

6\. 在授权、设备指纹、使用情况上报接口中夹带校园网账号密码；

7\. 将校园网账号密码与设备授权状态绑定上传。



推荐：



1\. Windows 端优先使用 Windows Credential Manager 或 Windows DPAPI 保存密码；

2\. 本地配置文件只保存非敏感配置；

3\. 清除配置时必须同时清除本机保存的账号密码；

4\. 日志中如需显示账号，只能脱敏显示。



\---



\## 4. 校园网登录模块约束



campus\_login 是核心模块，负责武汉理工校园网认证登录。



要求：



1\. campus\_login 不能依赖 UI；

2\. campus\_login 不能依赖授权模块（登录路径不做任何授权服务器网络请求）；

3\. campus\_login 不能依赖授权服务器内部实现；

4\. campus\_login 应提供清晰的状态返回；

5\. campus\_login 必须能被命令行脚本单独调用测试。



至少需要区分以下状态：



1\. 登录成功；

2\. 已经登录；

3\. 账号或密码错误；

4\. 未检测到校园网环境；

5\. 校园网认证服务不可用；

6\. 网络请求超时；

7\. 未知错误。



第一阶段优先实现最小登录验证脚本，不要先做复杂 UI。



\---



\## 5. 授权系统约束



第一版采用：



设备指纹 + 服务端签名授权凭证 + 使用情况上报



授权系统目标只有两件事：



1\. 识别设备，签发永久免费的授权凭证；

2\. 统计有多少设备在使用本工具。



免费版没有试用期、没有收费、没有功能门槛。



授权系统不是强反破解系统，不要求防专业逆向、Hook、补丁破解、虚拟机克隆、深度伪造硬件信息。



授权服务只允许保存：



1\. device\_id\_hash；

2\. license\_type（免费版固定为 free）；

3\. license\_status；

4\. license\_expire\_at；

5\. first\_seen\_at；

6\. last\_seen\_at；

7\. created\_at；

8\. 后台备注与审计记录（操作者名称、动作、目标设备/授权、时间）。



授权服务禁止保存：



1\. 校园网账号；

2\. 校园网密码；

3\. 用户手机号；

4\. 用户注册账号；

5\. 用户上网内容；

6\. 复杂个人资料；

7\. 任何支付、订单、金额、交易号信息。



历史遗留说明：`licenses.order\_id` 列与历史支付表属于旧结构，保留但不写入、不读取、不展示。



\---



\## 6. 本地授权凭证规则



本地 signed\_token 必须由服务端签名。



推荐设计：



1\. 服务端持有私钥；

2\. 客户端只内置公钥；

3\. signed\_token 中包含 device\_id\_hash、license\_type、license\_status、expires\_at；

4\. 客户端验证签名；

5\. 客户端验证 token 中的 device\_id\_hash 是否匹配当前设备；

6\. 用户修改本地授权文件后签名必须失效；

7\. 用户复制别人授权文件后设备指纹必须不匹配。



严禁：



1\. 把签名私钥放进客户端；

2\. 在客户端生成或伪造服务端授权；

3\. 在客户端实现试用期倒计时、付费门槛或激活码校验；

4\. 依赖本地时间或本地配置决定是否允许使用（免费版一律放行，凭证只用于设备识别与统计）。



\---



\## 7. 开机自动登录授权流程约束



用户开机时可能还没完成校园网认证，因此可能无法访问云端授权服务。



所以不能设计成：



必须先访问云端授权服务，授权通过后才允许自动登录校园网。



正确流程：



1\. 电脑开机；

2\. 工具后台启动；

3\. 本地直接放行（免费版不读取任何付费或试用状态）；

4\. 立即执行校园网自动登录；

5\. 应用启动时上报一次设备使用情况；校园网登录成功后再上报一次；

6\. 上报失败只记日志，不影响任何功能。



授权服务只负责统计与凭证刷新，不参与"是否允许使用"的判断。



\---



\## 8. 免费版约束（原支付章节已废止）



第一版采用：



永久免费 + 无内购 + 无激活码 + 无订单系统



严禁：



1\. 重新引入支付、订单、内购、订阅、开通会员、退款等任何商业化能力；

2\. 人工发码或要求用户输入激活码；

3\. 在客户端或服务端保留支付端点、支付回调、支付密钥、支付对账与支付 worker 配置；

4\. 以任何形式限制"未付费用户"的功能（免费版不存在"正式版"概念）。



免费版正常流程：



1\. 客户端启动，生成设备指纹；

2\. 客户端上报一次设备使用情况（仅设备指纹哈希与时间戳）；

3\. 服务端为新设备签发永久免费授权（license\_type=free，expires\_at=9999-12-31T00:00:00Z）；

4\. 客户端无需任何操作即可使用全部功能；

5\. 校园网登录成功后客户端再上报一次使用情况；

6\. 服务端后台可以查看设备数量、活跃设备数与授权状态。



历史支付实现（payment 模块、支付回调、对账 worker、支付窗口、支付状态机）已整体删除，不得恢复。



\---



\## 9. 历史支付章节（已废弃）



支付回调、订单状态查询、对账补偿、支付 worker 的相关规则随支付模块一并删除。



服务端不得再暴露任何支付、回调、订单、授权发放（grant）端点。



历史数据库里的支付遗留表保持原样：不清空、不迁移、不校验、不读写，仅由 `license\_server/db.py` 的 `LEGACY\_PAYMENT\_TABLES` 登记，升级代码也不得依据它们做任何判断。



数据库 schema 版本固定为 6，核心表只有 devices、licenses、admin\_audit\_logs、schema\_meta。



\---



\## 10. 模块边界



项目建议模块：



desktop\_app/

&#x20;   桌面界面、托盘、自启、配置管理、授权与使用状态展示



campus\_login/

&#x20;   武汉理工校园网认证登录逻辑



license\_client/

&#x20;   设备指纹、免费版放行判定、本地授权凭证、使用情况上报



license\_server/

&#x20;   设备注册记录、免费授权签发、内部只读后台统计、运行时证明



shared/

&#x20;   客户端和服务端可共享的常量、状态码、数据结构



docs/

&#x20;   项目设计、接口、部署、测试、说明



tests/

&#x20;   自动化测试



scripts/

&#x20;   开发、构建、数据库辅助脚本



deploy/

&#x20;   Nginx、systemd、Docker 等部署文件



\---



\## 11. 技术路线约束



第一版优先技术路线：



客户端：

&#x20;   Python + PySide6



服务端：

&#x20;   FastAPI + MySQL/SQLite + Nginx + HTTPS



本地密码保存：

&#x20;   Windows Credential Manager 或 Windows DPAPI



打包：

&#x20;   PyInstaller



说明：



1\. 第一版优先稳定落地，不追求极致 UI；

2\. 不要一开始引入过重架构；

3\. 不引入任何支付/内购第三方 SDK；

4\. 不要为了炫技引入复杂微服务。



\---



\## 12. 请求频率约束



客户端不能频繁请求授权服务器。



推荐规则：



1\. 软件启动时上报一次；

2\. 校园网登录成功后最多再上报一次；

3\. 授权服务器不可用时不要重试、不要弹窗；

4\. 网络异常时本地直接放行（免费版不依赖服务器可用性）；

5\. 上报请求超时不超过 5 秒。



严禁：



1\. 每隔几秒长期请求授权服务器；

2\. 后台无限重试；

3\. 因授权服务器不可用而阻止用户登录校园网。



\---



\## 13. 日志规则



允许记录：



1\. 程序启动；

2\. 登录状态；

3\. 授权状态；

4\. 使用情况上报结果；

5\. 错误类型；

6\. 请求耗时；

7\. 模块运行状态。



禁止记录：



1\. 校园网密码；

2\. 完整校园网账号；

3\. 服务器签名私钥；

4\. 后台管理令牌；

5\. 原始敏感 token；

6\. 用户隐私信息。



账号如需出现在日志中，必须脱敏，例如：



2024\*\*\*\*1234



\---



\## 14. 后台管理约束



第一版后台只做必要功能：



1\. 查看设备列表与首见、末见时间；

2\. 查看活跃设备数（24 小时 / 7 天 / 30 天）；

3\. 查看设备授权状态与到期时间；

4\. 查看授权列表；

5\. 查看审计日志；

6\. 给设备或授权添加运维备注；

7\. 冻结异常设备授权。



后台必须有访问控制（令牌摘要比对 + 仅内部地址访问）。



严禁：



1\. 后台查看校园网账号密码；

2\. 后台保存用户校园网密码；

3\. 后台做复杂用户画像；

4\. 后台做广告投放；

5\. 后台查看或恢复任何支付、订单信息。



\---



\## 15. UI 文案约束



主界面必须说明：



本工具会在电脑已连接武汉理工校园网环境后，自动完成校园网认证登录。

它不会自动选择 Wi-Fi、绕过验证码或突破校园网设备限制。

校园网账号密码仅保存在本机，不会上传服务器。



免费说明必须明确：



本工具完全免费，无试用期、无内购、无需激活码。

只会向服务器上报本机设备指纹与最近使用时间，不会上报校园网账号和密码。



\---



\## 16. 开发顺序约束



必须按以下顺序推进：



第一阶段：

&#x20;   campus\_login 最小命令行登录脚本



第二阶段：

&#x20;   desktop\_app 最小桌面端，支持输入账号密码、保存配置、测试登录



第三阶段：

&#x20;   Windows 开机自启、托盘、状态展示



第四阶段：

&#x20;   license\_client + license\_server，免费版放行 + 设备使用情况上报 + 后台统计



第五阶段：

&#x20;   打包、安装、真实用户测试



不要跳过第一阶段直接写完整 UI；

不要在登录核心不稳定时引入新功能；

不要重新引入支付或任何商业化模块。



\---



\## 17. 验收标准



第一版完成后至少满足：



1\. 用户可以输入校园网账号密码；

2\. 用户可以保存、修改、清除配置；

3\. 工具可以设置开机自启；

4\. 电脑已连接校园网环境时，工具可以自动完成认证登录；

5\. 用户可以点击“测试登录”验证账号密码；

6\. 软件永久免费，界面上没有任何支付、购买、续费、激活码入口；

7\. 免费状态绑定设备指纹；

8\. 修改系统时间不影响任何功能；

9\. 删除配置、重装软件后仍然免费可用；

10\. 客户端启动时与校园网登录成功后各上报一次设备使用情况；

11\. 上报内容只含设备指纹哈希与时间戳，不含校园网账号密码；

12\. 服务端可以为新设备签发 license\_type=free 的永久授权；

13\. 授权服务器不可用时，客户端仍可正常登录校园网；

14\. 授权凭证必须绑定设备指纹；

15\. 授权凭证必须由服务端签名；

16\. 校园网账号密码不上传服务器；

17\. 授权服务器不能部署在开发者个人电脑上；

18\. 后台可以查看设备数量、活跃设备数与授权状态，且只读查询不解锁任何支付数据。



\---



\## 18. Codex 工作要求



每次修改代码后，必须汇报：



1\. 修改了哪些文件；

2\. 新增了哪些文件；

3\. 删除了哪些文件；

4\. 如何运行；

5\. 如何测试；

6\. 当前还缺什么真实信息；

7\. 是否涉及账号密码、签名密钥、后台管理令牌等敏感信息。



如果缺少真实校园网抓包信息，不要伪造接口。



不要新增或恢复任何支付、内购、激活码相关实现；发现遗留支付代码或配置时，必须删除并记录在汇报中。



如果某功能只能写 mock，必须明确标记为 mock。



\---



\## 19. 当前阶段提醒



当前项目已完成"移除支付模块、转为永久免费"的改造。



优先任务是：



1\. 保持免费版放行逻辑与设备使用上报稳定；

2\. 维护后台设备与授权统计能力；

3\. 巩固校园网登录核心与桌面端体验；

4\. 打包、安装与真实用户测试；

5\. 不引入支付、内购、激活码等商业化模块。



不要在校园网登录核心未验证前投入大量时间做 UI。



<claude-mem-context>
# Memory Context

# [whut-campus-auto-login] recent context, 2026-09-28 8:33pm GMT+8

Legend: 🎯session 🔴bugfix 🟣feature 🔄refactor ✅change 🔵discovery ⚖️decision 🚨security_alert 🔐security_note
Format: ID TIME TYPE TITLE
Fetch details: get_observations([IDs]) | Search: mem-search skill

Stats: 50 obs (9,016t read) | 0t work

### Jul 28, 2026
S10 Final Phase 1 Runtime Attestation Test Suite Execution (Jul 28, 1:13 PM)
S9 WSL Testing Phase Closure with CodeRabbit Integration (Jul 28, 1:13 PM)
244 2:28p 🔵 Code Analysis Confirms Git Safe.directory Configuration
246 2:29p 🔴 Git Safe.directory Configuration Insufficient
247 2:30p 🔴 Git Clone Global Configuration Required
249 2:31p 🔴 Git Safe.directory Environment Variables Test
250 2:32p 🔴 Git Global Configuration Works for First Clone
252 " 🟣 P6-A1c-1B Test Git Clone Fix Implementation
253 2:34p 🟣 P6-A1c-1B Test Suite Git Configuration Fix Applied
256 2:36p 🟣 P6-A1c-1B Fix Synchronization to Ext4 Repository
257 " 🟣 P6-A1c-1B Phase 2 Regression Test Execution
258 2:37p 🟣 P6-A1c-1B Phase 2 Test Monitoring
259 " 🔴 P6-A1c-1B Phase 2 Tests Still Failing
261 2:39p 🔵 ACL Check and Unix Socket Permission Analysis
264 2:42p 🔵 Deployment Gate Logic and Test Implementation Analysis
266 2:44p 🔵 Deployment Gate Logic and Test Implementation Analysis
268 2:45p 🔵 POSIX ACL Attribute Discovery
269 " 🔵 ACL Attribute Access Error Analysis
271 2:47p 🔵 POSIX ACL Error Patterns Identified
272 2:48p 🟣 P6-A1c-1B Socket Connection Error Handling Fix
274 2:49p 🟣 P6-A1c-1B Connection Reset Error Handling Applied
277 2:52p 🟣 P6-A1c-1B Test File Synchronization to Ext4 Repository
279 2:54p 🔵 Unix Peer Credentials Test Success
281 2:56p 🔵 P6-A1c-1B Deployment Environment Status
282 2:57p 🔴 P6-A1c-1B Phase 2 Test Execution Command Syntax Error
284 " 🔴 P6-A1c-1B Phase 2 Test Suite Results
285 2:58p 🟣 P6-A1c-1B Python Module Import Fix
287 2:59p 🟣 Python Module Import Fix Applied
289 3:01p 🟣 ACL Permission Test Success
290 3:02p 🔴 P6-A1c-1B Final Phase 2 Test Results
292 3:04p 🔵 P6-A1c-1B Test Environment Audit Results
295 3:07p 🟣 P6-A1c-1B Test Environment Cleanup Completed
297 3:08p 🟣 P6-A1c-1B Task Completion Summary
299 3:11p 🔵 Linux Runtime Attestation Test Suite
S11 Phase 1 Test Suite Completion and CodeRabbit Review Trigger (Jul 28, 3:12 PM)
S12 CodeRabbit Review of Runtime Attestation Test Suite (Jul 28, 3:14 PM)
303 3:17p ✅ P6-A1c-1B WSL Test Completion Task
304 " 🔴 CodeRabbit Review Timeout Handling
S13 Retrying CodeRabbit Review for Tests Directory (Jul 28, 3:18 PM)
307 3:22p 🔵 WSL Testing Task Identified
308 " 🔴 Git Safe Directory Configuration Fixed
309 🔴 Git Safe Directory Configuration Applied
311 3:23p 🔴 Git Safe Directory Configuration Applied
313 3:26p 🔵 Environment Cleanup and Validation Completed
315 3:28p ✅ Client Requirements Installation Initiated
316 3:29p 🔵 Background Installation Process Not Found
318 3:31p 🔵 Client Requirements Installation Timed Out
320 3:33p 🔵 Background Pip Installation Still Running
322 3:35p 🔵 Pip Installation Status Monitored
324 3:37p 🔵 Pip Installation Progress Tracked
326 3:39p ✅ Background Pip Installation Terminated
328 3:40p 🚨 Temporary Cleanup Attempt Blocked
330 3:42p ✅ Targeted Cleanup Completed
332 3:44p 🟣 Phase 1 Regression Tests Completed
335 3:47p 🔵 Git Repository Status Confirmed
</claude-mem-context>